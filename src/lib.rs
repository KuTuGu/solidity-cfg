use anyhow::{anyhow, Error, Result};
use ethers::abi::{decode, AbiEncode, AbiParser, ParamType, Token};
use ethers::prelude::k256::ecdsa::SigningKey;
use ethers::prelude::*;
use ethers::solc::sourcemap::{Jump, SourceElement};
use ethers::solc::{
    artifacts::contract::CompactContractBytecode, sourcemap::SourceMap, Artifact,
    ProjectCompileOutput,
};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::utils::hex::FromHex;
use petgraph::graph::DiGraph;
use petgraph::graph::NodeIndex;
use petgraph::Graph;
use revm::interpreter::{opcode, spec_opcode_gas};
use revm::primitives::SpecId;
use std::collections::HashMap;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{collections::BTreeMap, fs};

#[derive(Debug, Clone)]
pub struct Node {
    pub enter: bool,
    pub name: Option<String>,
    pub address: Option<Address>,
    pub depth: u64,
    pub op: Opcode,
    pub value: Option<U256>,
    pub input: Option<BTreeMap<String, Token>>,
    pub output: Option<BTreeMap<String, Token>>,
    pub gas: Gas,
}

#[derive(Debug, Clone)]
pub struct Gas {
    pub gas_used: u64,
    pub gas_left: u64,
}

#[derive(Debug, Clone)]
pub struct CallStack {
    address: Address,
    data: Option<String>,
}

pub type Client = Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>;

pub struct CFG {
    tx: TypedTransaction,
    client: Client,
    identifier: LocalContractIdentifier,
    bytecode: HashMap<Address, Bytes>,
    call_stack: Vec<CallStack>,
}

impl CFG {
    pub async fn new(
        tx: TypedTransaction,
        client: Client,
        identifier: LocalContractIdentifier,
    ) -> Result<Self> {
        let contract = tx.to_addr().unwrap().clone();
        let call_stack = vec![CallStack {
            address: contract,
            data: tx.data().map(|d| d.to_string()),
        }];
        let mut bytecode = HashMap::<Address, Bytes>::new();
        bytecode.insert(contract, client.get_code(contract, None).await?);

        Ok(Self {
            tx,
            client,
            identifier,
            bytecode,
            call_stack,
        })
    }

    pub async fn analyze(&mut self) -> Result<Graph<Node, ()>> {
        let options: GethDebugTracingCallOptions = GethDebugTracingCallOptions {
            tracing_options: GethDebugTracingOptions {
                disable_storage: Some(true),
                enable_memory: Some(true),
                ..Default::default()
            },
        };
        let trace = Some(
            self.client
                .debug_trace_call(self.tx.clone(), None, options)
                .await?,
        );
        let node_list = match trace {
            Some(GethTrace::Known(GethTraceFrame::Default(frame))) => {
                let mut result = vec![];
                for log in &frame.struct_logs {
                    if let Some(node) = async {
                        match log.op.parse::<Opcode>().ok()? {
                            Opcode::JUMP | Opcode::JUMPI => self.parse_fn(log),
                            Opcode::CALL
                            | Opcode::STATICCALL
                            | Opcode::DELEGATECALL
                            | Opcode::RETURN
                            | Opcode::STOP => self.parse_call(log).await,
                            _ => None,
                        }
                    }
                    .await
                    {
                        result.push(node);
                    }
                }
                result
            }
            _ => vec![],
        };

        self.parse_graph(node_list)
    }

    fn parse_fn(&self, log: &StructLog) -> Option<Node> {
        // if no source, the contract is not verified, just return
        let contract = &self.call_stack.last()?.address;
        let (source_map, pc_ic_map) = self
            .identifier
            .source_map
            .get(self.bytecode.get(contract)?)?;
        let pc = log.pc as usize;
        let ic = *pc_ic_map.get(&pc)?;
        let element = source_map.get(ic)?;

        match element {
            SourceElement {
                jump,
                index: Some(index),
                ..
            } if jump == &Jump::In || jump == &Jump::Out => {
                let enter = jump == &Jump::In;
                let source_code = self.identifier.source_code.get(index)?;
                let dest = log.stack.as_ref()?.last()?.as_usize();

                // Enter a function, parse the input abi of the target function
                // Exit a function, parse the output abi of the current function
                let el = if enter {
                    source_map.get(*pc_ic_map.get(&dest)?)?
                } else {
                    element
                };

                let f = source_code.get(el.offset..el.offset + el.length)?;
                let (name, input, output) = self.parse_fn_data(f, log, enter).map_or_else(
                    || ("unknown".to_string(), None, None),
                    |(name, data)| {
                        let data = data.filter(|d| !d.is_empty());

                        if jump == &Jump::In {
                            (name, data, None)
                        } else {
                            (name, None, data)
                        }
                    },
                );

                Some(Node {
                    enter,
                    name: Some(name),
                    address: Some(contract.clone()),
                    depth: log.depth,
                    op: log.op.parse::<Opcode>().ok()?,
                    value: None,
                    input,
                    output,
                    gas: Gas {
                        gas_left: log.gas,
                        gas_used: 0,
                    },
                })
            }
            _ => None,
        }
    }

    fn parse_fn_data(
        &self,
        f: &str,
        log: &StructLog,
        input: bool,
    ) -> Option<(String, Option<BTreeMap<String, Token>>)> {
        let (f, _body) = f.split_once("{")?.to_owned();
        let mut f = f.to_string();
        // need to deal with irregular abi case where modifier exists and no returns
        if !f.contains(" returns ") {
            f += " returns ()";
        }
        let param_str = if input {
            let (_s, param_str) = f.split_once('(')?;
            let (param_str, _s) = param_str.split_once(')')?;
            param_str
        } else {
            let (_s, param_str) = f.rsplit_once('(')?;
            let (param_str, _s) = param_str.rsplit_once(')')?;
            param_str
        };

        let mut stack = log.stack.as_ref()?.iter().rev();
        let _dest = stack.next()?;
        let mut parse_err = false;
        let data = param_str
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(|param| {
                let data = {
                    let data = stack.next()?;
                    if param.contains("memory") || param.contains("calldata") {
                        let str = if param.contains("memory") {
                            log.memory.as_ref()?.join("")
                        } else {
                            self.call_stack.last()?.data.clone()?
                        };

                        let pointer = ((data.as_usize() + 32) as u64).encode_hex()[2..].to_owned();
                        Vec::from_hex(pointer + &str).ok()
                    } else {
                        Some(data.encode())
                    }
                };

                data.map_or_else(
                    || {
                        parse_err = true;
                        None
                    },
                    |data| Some(data),
                )
            })
            .flatten()
            .collect::<Vec<u8>>();

        let f = AbiParser::default().parse_function(&f).ok()?;
        let name = f.name;
        if parse_err {
            return Some((name, None));
        }
        let param = if input { f.inputs } else { f.outputs };
        let mut name_offset = 0;
        let (names, types): (Vec<String>, Vec<ParamType>) = param
            .into_iter()
            .rev()
            .map(|param| {
                (
                    // default variable name for output
                    if param.name.is_empty() {
                        name_offset += 1;
                        name_offset.to_string()
                    } else {
                        param.name
                    },
                    param.kind,
                )
            })
            .unzip();
        let tokens = decode(types.as_ref(), &data).ok()?;
        let data = names
            .into_iter()
            .zip(tokens.into_iter())
            .map(|token| token)
            .collect::<BTreeMap<_, _>>();

        Some((name, Some(data)))
    }

    async fn parse_call(&mut self, log: &StructLog) -> Option<Node> {
        let opcode = log.op.parse::<Opcode>().ok()?;
        let mut stack = log.stack.as_ref()?.into_iter().rev();
        let (enter, address, value) = match opcode {
            Opcode::CALL | Opcode::DELEGATECALL | Opcode::STATICCALL => {
                let _gas = stack.next()?.as_u64();
                let address = stack.next()?;
                let address = (address.leading_zeros() >= 96)
                    .then(|| Address::from_slice(&address.encode()[12..]))?;
                let value = if opcode == Opcode::CALL {
                    Some(stack.next()?.clone())
                } else {
                    None
                };

                // store contract bytecode
                self.bytecode
                    .entry(address)
                    .or_insert(self.client.get_code(address, None).await.ok()?);

                (true, Some(address), value)
            }
            _ => {
                self.call_stack.pop();
                (false, None, None)
            }
        };

        let (input, output) = match opcode {
            Opcode::STOP => (None, None),
            _ => {
                let offset = stack.next()?.as_usize() * 2;
                let length = stack.next()?.as_usize() * 2;
                let data = log
                    .memory
                    .as_ref()?
                    .join("")
                    .get(offset..offset + length)
                    .map(|data| data.to_string());

                let token = data.clone().map(|data| {
                    vec![("calldata".into(), Token::String(data))]
                        .into_iter()
                        .collect::<BTreeMap<String, Token>>()
                });

                if opcode == Opcode::RETURN {
                    (None, token)
                } else {
                    self.call_stack.push(CallStack {
                        address: address.unwrap(),
                        data,
                    });
                    (token, None)
                }
            }
        };

        Some(Node {
            enter,
            name: None,
            address,
            value,
            input,
            output,
            depth: log.depth,
            op: opcode,
            gas: Gas {
                gas_left: log.gas - log.gas_cost,
                gas_used: log.gas_cost,
            },
        })
    }

    // merge node by postfix expression
    fn parse_graph(&self, mut list: Vec<Node>) -> Result<Graph<Node, ()>> {
        let mut graph = DiGraph::new();
        let mut stack: Vec<(Node, NodeIndex)> = vec![];
        // The last end opcode has no corresponding start node
        list.pop();
        list.into_iter().try_for_each(|node| {
            if node.enter {
                let index = graph.add_node(node.clone());
                stack
                    .last()
                    .map(|(.., parent_index)| graph.add_edge(parent_index.clone(), index, ()));
                stack.push((node, index));
            } else {
                let exit = node;
                let (mut enter, enter_index) = stack.pop().ok_or(anyhow!("nodes do not match"))?;

                // merge enter && exit node
                enter.output = exit.output;
                if enter.gas.gas_used == 0 {
                    enter.gas.gas_used = enter
                        .gas
                        .gas_left
                        .checked_sub(exit.gas.gas_left)
                        .ok_or(anyhow!("gas calculation error"))?;
                }

                let node = graph
                    .node_weight_mut(enter_index)
                    .ok_or(anyhow!("could not found the enter node"))?;
                *node = enter;
            }

            Ok::<(), Error>(())
        })?;

        if stack.is_empty() {
            Ok(graph)
        } else {
            Err(anyhow!("missing end node"))
        }
    }
}

#[derive(Debug, Default)]
pub struct LocalContractIdentifier {
    root: PathBuf,
    // The unit is file
    // source_index -> source_code
    source_code: BTreeMap<u32, String>,
    // The unit is contract (
    //   may be larger than files, such as import other files;
    //   may also be smaller than a file, such as a file with multiple contracts
    // )
    // bytecode -> (source_map, pc_ic_map)
    source_map: HashMap<Bytes, (SourceMap, PCICMap)>,
}

impl LocalContractIdentifier {
    pub fn new<T: AsRef<Path>>(path: T) -> Self {
        Self {
            root: PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path),
            ..Default::default()
        }
    }
    pub fn compile(&self) -> Result<ProjectCompileOutput> {
        let paths = ProjectPathsConfig::builder().sources(&self.root).build()?;
        let project = Project::builder()
            .paths(paths)
            .set_cached(false)
            .set_no_artifacts(false)
            .build()?
            .compile()?;

        if project.has_compiler_errors() {
            Err(anyhow!("{:#?}", project.output().errors))
        } else {
            Ok(project)
        }
    }

    pub fn verify(&mut self, project: ProjectCompileOutput) {
        let (artifacts, sources) = project.into_artifacts_with_sources();

        self.source_code = sources
            .into_sources()
            .map(|(path, source)| {
                let file = self.root.join(&path);
                (source.id, fs::read_to_string(&file).unwrap())
            })
            .collect::<BTreeMap<_, _>>();

        self.source_map = artifacts
            .into_iter()
            .filter_map(|(_id, artifact)| {
                let artifact = CompactContractBytecode::from(artifact);
                let source_map = artifact.get_source_map_deployed()?.ok()?;
                let bytecode = artifact.get_deployed_bytecode_bytes()?.into_owned();
                let pc_ic_map = build_pc_ic_map(SpecId::LATEST, &bytecode);

                Some((bytecode, (source_map, pc_ic_map)))
            })
            .collect::<HashMap<_, _>>();
    }
}

/// A map of program counters to instruction counters.
type PCICMap = BTreeMap<usize, usize>;
/// Builds a mapping from instruction counters to program counters.
fn build_pc_ic_map(spec: SpecId, code: &[u8]) -> PCICMap {
    let opcode_infos = spec_opcode_gas(spec);
    let mut pc_ic_map: PCICMap = PCICMap::new();

    let mut i = 0;
    let mut cumulative_push_size = 0;
    while i < code.len() {
        let op = code[i];
        pc_ic_map.insert(i, i - cumulative_push_size);
        if opcode_infos[op as usize].is_push() {
            // Skip the push bytes.
            //
            // For more context on the math, see: https://github.com/bluealloy/revm/blob/007b8807b5ad7705d3cacce4d92b89d880a83301/crates/revm/src/interpreter/contract.rs#L114-L115
            i += (op - opcode::PUSH1 + 1) as usize;
            cumulative_push_size += (op - opcode::PUSH1 + 1) as usize;
        }
        i += 1;
    }

    pc_ic_map
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::utils::Anvil;
    use petgraph::dot::Dot;
    use std::{fs::File, io::Write};

    abigen!(TestContract, r#"[function entry(uint _a, uint _b)]"#);

    #[tokio::test]
    async fn test_it_works() {
        let mut identifier = LocalContractIdentifier::new("contracts");
        let project = identifier.compile().unwrap();

        // deploy contract && anvil persistence
        let output = project
            .find_first("A")
            .expect("could not find contract")
            .clone();
        let (abi, bytecode, _) = output.into_parts();
        let anvil = Anvil::new().port(8545_u16).timeout(20000_000_u64).spawn();
        let wallet: LocalWallet = anvil.keys()[0].clone().into();
        let wallet = wallet.with_chain_id(anvil.chain_id());
        let provider = Provider::<Http>::connect(&anvil.endpoint()).await;
        let client = SignerMiddleware::new(provider, wallet.clone());
        let client = Arc::new(client);
        let factory = ContractFactory::new(abi.unwrap(), bytecode.unwrap(), client.clone());
        let contract = factory.deploy(()).unwrap().send().await.unwrap();
        let addr = contract.address();

        identifier.verify(project);
        let contract = TestContract::new(addr, client.clone());
        let tx = contract.entry(U256::from(1), U256::from(2)).tx;

        let mut cfg = CFG::new(tx, client, identifier).await.unwrap();
        let graph = cfg.analyze().await.unwrap();
        let dot = format!("{:#?}", Dot::new(&graph));
        let mut file = File::create("graph.dot").unwrap();
        file.write_all(dot.as_bytes()).unwrap();
    }
}
