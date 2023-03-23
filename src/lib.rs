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

#[derive(Debug)]
pub struct CFG {
    pub path: String,
    pub contract: String,
}

#[derive(Debug)]
pub struct Node {
    pub name: String,
    pub depth: u64,
    pub op: Opcode,
    pub contract: Address,
    pub caller: Address,
    pub input: Option<BTreeMap<String, Token>>,
    pub output: Option<BTreeMap<String, Token>>,
    pub gas: Gas,
}

#[derive(Debug)]
pub struct Gas {
    pub gas_cost: u64,
    pub total_gas: u64,
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
                    Opcode::JUMP | Opcode::JUMPI => {
                        ast.iter()
                            .find_map(|(_source_index, (.., source_map, pc_ic_map))| {
                                let pc = log.pc as usize;
                                let ic = *pc_ic_map.get(&pc)?;
                                let element = source_map.get(ic)?;
                                match element {
                                    SourceElement {
                                        jump,
                                        index: Some(index),
                                        ..
                                    } if (jump == &Jump::In || jump == &Jump::Out)
                                        && index != &u32::MAX
                                        && ast.get(&index) != None =>
                                    {
                                        let stack = log.stack.clone()?;
                                        let dest = stack.get(stack.len() - 1)?.as_usize();
                                        let dest_element =
                                            source_map.get(*pc_ic_map.get(&dest)?)?;
                                        let dest_func = self.parse_func(&ast, dest_element);
                                        let current_func = self.parse_func(&ast, element);

                                        match jump {
                                            &Jump::In => {
                                                Some(self.parse_node(dest_func?, jump, log)?)
                                            }
                                            &Jump::Out => {
                                                Some(self.parse_node(current_func?, jump, log)?)
                                            }
                                            _ => unreachable!(),
                                        }
                                    }
                                    _ => None,
                                }
                            })
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

    fn ast(&self, project: ProjectCompileOutput) -> BTreeMap<u32, (Bytes, SourceMap, PCICMap)> {
        let (artifacts, mut sources) = project.into_artifacts_with_sources();
        let (result, ..): (BTreeMap<u32, (Bytes, SourceMap, PCICMap)>, ()) = artifacts
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
                let pc_ic_maps = build_pc_ic_map(SpecId::LATEST, &bytecode);

                Some(((source_index, (source_code, source_map, pc_ic_maps)), ()))
            })
            .unzip();

        result
    }

    fn parse_func(
        &self,
        ast: &BTreeMap<u32, (Bytes, SourceMap, PCICMap)>,
        el: &SourceElement,
    ) -> Option<Function> {
        let dest_code = &ast.get(&el.index?)?.0;
        let f = String::from_utf8(dest_code[el.offset..el.offset + el.length].to_vec()).ok()?;
        let f = f.split("{").next()?;
        let abi = AbiParser::default().parse(&[&f]).ok()?;
        let (.., f) = abi.functions.into_iter().next()?;

        f.into_iter().next()
    }

    fn parse_node(&self, f: Function, typ: &Jump, log: &StructLog) -> Option<Node> {
        let Function {
            name,
            inputs,
            outputs,
            ..
        } = f;
        let param = match typ {
            Jump::In => inputs,
            Jump::Out => outputs,
            _ => unreachable!(),
        };
        let mut name_offset = 0;
        let (names, types): (Vec<String>, Vec<ParamType>) = param
            .into_iter()
            .rev()
            .map(|param| {
                (
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

        let mut stack = log.stack.clone()?.into_iter().rev();
        let _dest = stack.next();
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
            false if typ == &Jump::In => (Some(data), None),
            false if typ == &Jump::Out => (None, Some(data)),
            _ => unreachable!(),
        };

        Some(Node {
            name,
            depth: log.depth,
            op: log.op.parse::<Opcode>().ok()?,
            contract: Address::zero(),
            caller: Address::zero(),
            input,
            output,
            gas: Gas {
                gas_cost: log.gas_cost,
                total_gas: log.gas,
            },
        })
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
