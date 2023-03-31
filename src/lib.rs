mod identifier;
pub use identifier::*;

use anyhow::{anyhow, Error, Result};
use ethers::abi::{decode, AbiEncode, AbiParser, ParamType, Token};
use ethers::prelude::k256::ecdsa::SigningKey;
use ethers::prelude::*;
use ethers::solc::sourcemap::{Jump, SourceElement};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::utils::hex::FromHex;
use petgraph::graph::DiGraph;
use petgraph::graph::NodeIndex;
use petgraph::Graph;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

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

pub type SignerClient = Arc<SignerMiddleware<Provider<Http>, Wallet<SigningKey>>>;

pub struct CFG<T: Into<TypedTransaction> + Clone, I: ContractIdentifier> {
    tx: T,
    block: Option<BlockId>,
    client: SignerClient,
    identifier: I,
    call_stack: Vec<CallStack>,
}

impl<T: Into<TypedTransaction> + Clone, I: ContractIdentifier> CFG<T, I> {
    pub fn new(tx: T, block: Option<BlockId>, client: SignerClient, identifier: I) -> Self {
        Self {
            tx,
            block,
            client,
            identifier,
            call_stack: vec![],
        }
    }

    pub async fn analyze(&mut self) -> Result<Graph<Node, ()>> {
        let options: GethDebugTracingCallOptions = GethDebugTracingCallOptions {
            tracing_options: GethDebugTracingOptions {
                disable_storage: Some(false),
                enable_memory: Some(true),
                ..Default::default()
            },
        };
        let tx = self.tx.clone().into();
        let trace = Some(
            self.client
                .debug_trace_call(tx.clone(), self.block, options)
                .await?,
        );
        let node_list = match trace {
            Some(GethTrace::Known(GethTraceFrame::Default(frame))) => {
                // add first call node
                let gas = frame.gas.as_u64();
                let addr =
                    U256::from_big_endian(tx.to_addr().copied().unwrap_or_default().as_ref());
                let struct_log = [
                    vec![StructLog {
                        depth: 0,
                        error: None,
                        gas,
                        gas_cost: gas,
                        memory: Some(vec![]),
                        op: String::from("CALL"),
                        pc: 0,
                        refund_counter: None,
                        stack: Some(vec![
                            U256::zero(),                            // length
                            U256::zero(),                            // offset
                            tx.value().copied().unwrap_or_default(), // value
                            addr,                                    // address
                            frame.gas,                               // gas
                        ]),
                        storage: None,
                    }],
                    frame.struct_logs,
                ]
                .concat();

                let call_list = struct_log
                    .iter()
                    .filter_map(|log| {
                        let stack = log.stack.as_ref()?;
                        match log.op.parse::<Opcode>().ok()? {
                            Opcode::CALL | Opcode::STATICCALL | Opcode::DELEGATECALL => {
                                Some(self.parse_call_addr(stack.get(stack.len() - 2)?)?)
                            }
                            _ => None,
                        }
                    })
                    .collect::<Vec<_>>();

                self.identifier.build(call_list).await?;

                let mut result = vec![];
                for log in &struct_log {
                    if let Some(node) = async {
                        match log.op.parse::<Opcode>().ok()? {
                            // log only have jump, no jumpi
                            Opcode::JUMP => self.parse_fn(log),
                            Opcode::CALL
                            | Opcode::STATICCALL
                            | Opcode::DELEGATECALL
                            | Opcode::RETURN
                            | Opcode::STOP
                            | Opcode::REVERT => self.parse_call(log),
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
        let contract = self.call_stack.last()?.address;
        let contract_key = self.identifier.get_contract_key(contract)?;
        let source_map = self.identifier.get_source_map(&contract_key)?;
        let pc_ic_map = self.identifier.get_pc_ic_map(&contract_key)?;
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
                let (name, input, output) = {
                    let source_code = self.identifier.get_source_code(&contract_key, index)?;
                    let dest = log.stack.as_ref()?.last()?.as_usize();

                    // Enter a function, parse the input abi of the target function
                    // Exit a function, parse the output abi of the current function
                    let el = if enter {
                        source_map.get(*pc_ic_map.get(&dest)?)?
                    } else {
                        element
                    };

                    let f = source_code.get(el.offset..el.offset + el.length)?;
                    self.parse_fn_data(f, log, enter).map(|(name, data)| {
                        let data = data.filter(|d| !d.is_empty());

                        if jump == &Jump::In {
                            (name, data, None)
                        } else {
                            (name, None, data)
                        }
                    })
                }
                .unwrap_or(("unknown".to_string(), None, None));

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

        let mut stack = log.stack.clone()?;
        let _dest = stack.pop()?;
        let memory = &log.memory.as_ref()?.join("");
        let calldata = self.call_stack.last()?.data.as_ref()?;
        let _storage = log.storage.as_ref()?;
        let param_str = param_str.split(',').rev().collect::<Vec<_>>();

        let f = AbiParser::default().parse_function(&f).ok()?;
        let param = if input { f.inputs } else { f.outputs };
        let mut param_name_offset = 0;
        let data: Result<BTreeMap<String, Token>> =
            param
                .into_iter()
                .rev()
                .enumerate()
                .try_fold(BTreeMap::new(), |mut acc, (i, param)| {
                    // default param name for output
                    let name = if param.name.is_empty() {
                        param_name_offset += 1;
                        param_name_offset.to_string()
                    } else {
                        param.name
                    };
                    let param_str = param_str
                        .get(i)
                        .ok_or(anyhow!("no corresponding param_str"))?;
                    let data = stack.pop().ok_or(anyhow!("no corresponding data"))?;

                    let data = if param_str.contains("memory") {
                        let data = match param.kind.clone() {
                            // offset is 0
                            ParamType::FixedArray(_, _) | ParamType::FixedBytes(_) => {
                                memory[data.as_usize() * 2..].to_string()
                            }
                            _ => {
                                let pointer = (data + 32).encode_hex()[2..].to_owned();
                                pointer + memory
                            }
                        };
                        decode(&[param.kind], &Vec::from_hex(data)?)?
                    } else if param_str.contains("calldata") {
                        let data = match param.kind.clone() {
                            // offset is 0
                            ParamType::FixedArray(_, _) | ParamType::FixedBytes(_) => {
                                calldata[data.as_usize() * 2..].to_string()
                            }
                            typ => {
                                let data = match typ {
                                    // These types have an unused length
                                    ParamType::Array(_) | ParamType::Bytes | ParamType::String => {
                                        stack.pop().ok_or(anyhow!("no corresponding data"))?
                                    }
                                    _ => data,
                                };
                                let pointer = data.encode_hex()[2..].to_owned();
                                pointer + calldata
                            }
                        };
                        decode(&[param.kind], &Vec::from_hex(data)?)?
                    } else if param_str.contains("storage") {
                        // we need to implement all types of parsing, not supported yet
                        Err(anyhow!("no support parse storage data"))?
                    } else {
                        decode(&[param.kind], &data.encode())?
                    }
                    .pop()
                    .ok_or(anyhow!("decode param data err"))?;

                    acc.insert(name, data);
                    Ok(acc)
                });

        Some((f.name, data.ok()))
    }

    fn parse_call(&mut self, log: &StructLog) -> Option<Node> {
        let opcode = log.op.parse::<Opcode>().ok()?;
        let mut stack = log.stack.clone()?;
        let (enter, address, value) = match opcode {
            Opcode::CALL | Opcode::DELEGATECALL | Opcode::STATICCALL => {
                let _gas = stack.pop()?.as_u64();
                let address = self.parse_call_addr(&stack.pop()?)?;
                let value = if opcode == Opcode::CALL {
                    Some(stack.pop()?.clone())
                } else {
                    None
                };

                (true, Some(address), value)
            }
            _ => {
                self.call_stack.pop()?;
                (false, None, None)
            }
        };
        let name = address.and_then(|addr| self.identifier.get_label(addr));

        let (input, output) = match opcode {
            Opcode::STOP => (None, None),
            _ => {
                let offset = stack.pop()?.as_usize() * 2;
                let length = stack.pop()?.as_usize() * 2;
                let data = log
                    .memory
                    .as_ref()?
                    .join("")
                    .get(offset..offset + length)
                    .map(|data| data.to_string());

                let token = self.parse_call_data(data.clone());
                if opcode == Opcode::RETURN || opcode == Opcode::REVERT {
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
            name,
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

    fn parse_call_addr(&self, data: &U256) -> Option<Address> {
        (data.leading_zeros() >= 96).then(|| Address::from_slice(&data.encode()[12..]))
    }

    fn parse_call_data(&self, data: Option<String>) -> Option<BTreeMap<String, Token>> {
        data.filter(|data| !data.is_empty()).map(|data| {
            vec![("data".into(), Token::String(data))]
                .into_iter()
                .collect::<BTreeMap<_, _>>()
        })
    }

    // merge node by postfix expression
    fn parse_graph(&self, list: Vec<Node>) -> Result<Graph<Node, ()>> {
        let mut graph = DiGraph::new();
        let mut stack: Vec<(Node, NodeIndex)> = vec![];
        list.into_iter().try_for_each(|node| {
            if node.enter {
                let index = graph.add_node(node.clone());
                stack
                    .last()
                    .map(|(.., parent_index)| graph.add_edge(parent_index.clone(), index, ()));
                stack.push((node, index));
            } else {
                let exit = node;
                let (mut enter, enter_index) = stack.pop().ok_or(anyhow!("missing start node"))?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::utils::Anvil;
    use petgraph::dot::Dot;
    use std::{fs::File, io::Write};

    abigen!(TestContract, r#"[function entry(uint _a, uint _b)]"#);

    #[tokio::test]
    async fn test_it_works() {
        let anvil = Anvil::new().port(8545_u16).timeout(20000_000_u64).spawn();
        let wallet: LocalWallet = anvil.keys()[0].clone().into();
        let wallet = wallet.with_chain_id(anvil.chain_id());
        let provider = Provider::<Http>::connect(&anvil.endpoint()).await;
        let client = SignerMiddleware::new(provider, wallet.clone());
        let client = Arc::new(client);

        let identifier = LocalContractIdentifier::new("contracts", client.clone()).unwrap();
        let output = identifier
            .project
            .as_ref()
            .unwrap()
            .find_first("A")
            .expect("could not find contract")
            .clone();
        let (abi, bytecode, _) = output.into_parts();
        let factory = ContractFactory::new(abi.unwrap(), bytecode.unwrap(), client.clone());
        let contract = factory.deploy(()).unwrap().send().await.unwrap();
        let addr = contract.address();

        let contract = TestContract::new(addr, client.clone());
        let tx = contract.entry(U256::from(1), U256::from(2)).tx;

        let mut cfg = CFG::new(tx, None, client, identifier);
        let graph = cfg.analyze().await.unwrap();
        let dot = format!("{:#?}", Dot::new(&graph));
        let mut file = File::create("graph.dot").unwrap();
        file.write_all(dot.as_bytes()).unwrap();
    }
}
