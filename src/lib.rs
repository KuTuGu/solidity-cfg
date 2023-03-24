use anyhow::{anyhow, Result};
use ethers::abi::{decode, AbiEncode, AbiParser, Function, ParamType, Token};
use ethers::prelude::*;
use ethers::solc::sourcemap::{Jump, SourceElement};
use ethers::solc::{
    artifacts::contract::CompactContractBytecode, sourcemap::SourceMap, Artifact,
    ProjectCompileOutput,
};
use ethers::utils::Anvil;
use revm::interpreter::{opcode, spec_opcode_gas};
use revm::primitives::SpecId;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;
use std::{collections::BTreeMap, fs};

abigen!(TestContract, r#"[function entry(uint _a, uint _b)]"#);

struct AST {
    source_code: Bytes,
    source_map: SourceMap,
    pc_ic_map: PCICMap,
}

#[derive(Debug)]
pub enum Node {
    Func(FuncNode),
    Call(CallNode),
}

#[derive(Debug)]
pub struct FuncNode {
    pub name: String,
    pub depth: u64,
    pub op: Opcode,
    pub contract: Address,
    pub input: Option<BTreeMap<String, Token>>,
    pub output: Option<BTreeMap<String, Token>>,
    pub gas: u64,
}

#[derive(Debug)]
pub struct CallNode {
    pub address: Address,
    pub depth: u64,
    pub op: Opcode,
    pub value: Option<U256>,
    pub input: Option<String>,
    pub output: Option<String>,
    pub gas: u64,
}

#[derive(Debug)]
pub struct CFG {
    pub path: String,
    pub contract: String,
}

impl CFG {
    pub fn new<T: Into<String> + Debug>(path: T, contract: T) -> Self {
        Self {
            path: path.into(),
            contract: contract.into(),
        }
    }

    pub async fn analyze(&self) -> Result<Vec<Node>> {
        let project = self.compile()?;
        let trace = self.get_contract_trace(&project).await?;
        let ast = self.ast(project);

        Ok(match trace {
            GethTrace::Known(GethTraceFrame::Default(frame)) => frame
                .struct_logs
                .iter()
                .filter_map(|log| match log.op.parse::<Opcode>().ok()? {
                    Opcode::JUMP | Opcode::JUMPI => self.parse_func_node(log, &ast),
                    Opcode::CALL | Opcode::STATICCALL | Opcode::DELEGATECALL | Opcode::RETURN => {
                        self.parse_call_node(log)
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
            _ => vec![],
        })
    }

    fn compile(&self) -> Result<ProjectCompileOutput> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(&self.path);
        let paths = ProjectPathsConfig::builder().sources(&root).build()?;
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

    async fn get_contract_trace(&self, project: &ProjectCompileOutput) -> Result<GethTrace> {
        let output = project
            .find_first(&self.contract)
            .expect("could not find contract")
            .clone();
        match output.id {
            Some(id) if id != u32::MAX => {
                let (abi, bytecode, _) = output.into_parts();
                let anvil = Anvil::new().port(8545_u16).timeout(20000_000_u64).spawn();
                let wallet: LocalWallet = anvil.keys()[0].clone().into();
                let wallet = wallet.with_chain_id(anvil.chain_id());
                let provider = Provider::<Http>::connect(&anvil.endpoint()).await;
                let client = SignerMiddleware::new(provider, wallet.clone());
                let client = Arc::new(client);
                let factory = ContractFactory::new(
                    abi.ok_or(anyhow!("no abi"))?,
                    bytecode.ok_or(anyhow!("no bytecode"))?,
                    client.clone(),
                );
                let contract = factory.deploy(())?.send().await?;
                let addr = contract.address();
                let contract = TestContract::new(addr, client.clone());

                let tx = contract.entry(U256::from(1), U256::from(2)).tx;
                let options: GethDebugTracingCallOptions = GethDebugTracingCallOptions {
                    tracing_options: GethDebugTracingOptions {
                        disable_storage: Some(true),
                        enable_memory: Some(false),
                        ..Default::default()
                    },
                };

                Ok(client.debug_trace_call(tx, None, options).await?)
            }
            _ => Err(anyhow!("invalid source_index")),
        }
    }

    fn ast(&self, project: ProjectCompileOutput) -> BTreeMap<u32, AST> {
        let (artifacts, mut sources) = project.into_artifacts_with_sources();
        let (result, ..): (BTreeMap<u32, AST>, ()) = artifacts
            .into_iter()
            .map(|(id, artifact)| (id, CompactContractBytecode::from(artifact)))
            .filter_map(|(id, artifact)| {
                let source_index = sources.remove_by_path(id.source.as_os_str().to_str()?)?.id;
                let source_code = fs::read_to_string(&id.source)
                    .ok()?
                    .as_bytes()
                    .to_vec()
                    .into();

                let source_map = artifact.get_source_map_deployed()?.ok()?;
                let bytecode = artifact.get_deployed_bytecode_bytes()?;
                let pc_ic_map = build_pc_ic_map(SpecId::LATEST, &bytecode);

                Some((
                    (
                        source_index,
                        AST {
                            source_code,
                            source_map,
                            pc_ic_map,
                        },
                    ),
                    (),
                ))
            })
            .unzip();

        result
    }

    fn parse_func(&self, ast: &BTreeMap<u32, AST>, el: &SourceElement) -> Option<Function> {
        let code = &ast.get(&el.index?)?.source_code;
        let f = String::from_utf8(code[el.offset..el.offset + el.length].to_vec()).ok()?;
        let f = f.split("{").next()?;
        let abi = AbiParser::default().parse(&[&f]).ok()?;
        let (.., f) = abi.functions.into_iter().next()?;

        f.into_iter().next()
    }

    fn parse_func_node(&self, log: &StructLog, ast: &BTreeMap<u32, AST>) -> Option<Node> {
        ast.iter().find_map(
            |(
                _source_index,
                AST {
                    source_map,
                    pc_ic_map,
                    ..
                },
            )| {
                let pc = log.pc as usize;
                let ic = *pc_ic_map.get(&pc)?;
                let element = source_map.get(ic)?;
                match element {
                    SourceElement {
                        jump,
                        index: Some(index),
                        ..
                    } if (jump == &Jump::In || jump == &Jump::Out) && index != &u32::MAX => {
                        let mut stack = log.stack.clone()?.into_iter().rev();
                        let dest = stack.next()?.as_usize();
                        let dest_element = source_map.get(*pc_ic_map.get(&dest)?)?;
                        let (name, param) = match jump {
                            &Jump::In => {
                                // Enter a function, parse the input abi of the target function
                                let f = self.parse_func(&ast, dest_element)?;
                                (f.name, f.inputs)
                            }
                            &Jump::Out => {
                                // Exit a function, parse the output abi of the current function
                                let f = self.parse_func(&ast, element)?;
                                (f.name, f.outputs)
                            }
                            _ => unreachable!(),
                        };

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
                        let tokens = decode(
                            types.as_ref(),
                            stack
                                .into_iter()
                                .flat_map(|i| i.encode())
                                .collect::<Vec<u8>>()
                                .as_ref(),
                        )
                        .ok()?;

                        let (data, ..): (BTreeMap<String, Token>, ()) = names
                            .into_iter()
                            .zip(tokens.into_iter())
                            .map(|token| (token, ()))
                            .unzip();
                        let (input, output) = match data.is_empty() {
                            true => (None, None),
                            false if jump == &Jump::In => (Some(data), None),
                            false if jump == &Jump::Out => (None, Some(data)),
                            _ => unreachable!(),
                        };

                        Some(Node::Func(FuncNode {
                            name,
                            depth: log.depth,
                            op: log.op.parse::<Opcode>().ok()?,
                            contract: Address::zero(),
                            input,
                            output,
                            gas: log.gas,
                        }))
                    }
                    _ => None,
                }
            },
        )
    }

    fn parse_call_node(&self, log: &StructLog) -> Option<Node> {
        let opcode = log.op.parse::<Opcode>().ok()?;
        let mut stack = log.stack.clone()?.into_iter().rev();
        let (gas, address, value) = if opcode != Opcode::RETURN {
            let gas = stack.next()?.as_u64();
            let address = stack.next()?;
            let address: Address = (address.leading_zeros() >= 96)
                .then(|| Address::from_slice(&address.encode()[12..]))?;
            let value = if opcode == Opcode::CALL {
                Some(stack.next()?)
            } else {
                None
            };

            (gas, address, value)
        } else {
            (0, Address::zero(), None)
        };
        let offset = stack.next()?.as_usize();
        let length = stack.next()?.as_usize();
        let data = log.memory.clone().and_then(|data| {
            data.join("")
                .get(offset..offset + length)
                .and_then(|data| Some(data.to_string()))
        });
        let (input, output) = if opcode != Opcode::RETURN {
            (data, None)
        } else {
            (None, data)
        };

        Some(Node::Call(CallNode {
            address,
            value,
            input,
            output,
            depth: log.depth,
            op: opcode,
            gas,
        }))
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

    #[tokio::test]
    async fn test_it_works() {
        let cfg = CFG::new("contracts", "A");
        let result = cfg.analyze().await.unwrap();
        dbg!(result);
    }
}
