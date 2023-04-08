use crate::SignerClient;
use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use ethers::abi::HumanReadableParser;
use ethers::abi::ParamType;
use ethers::abi::StateMutability;
use ethers::etherscan::contract::Metadata;
use ethers::prelude::*;
use ethers::solc::artifacts::ast::NodeType;
use ethers::solc::artifacts::LowFidelitySourceLocation as PartialSourceLocation;
use ethers::solc::artifacts::Node;
use ethers::solc::artifacts::{Ast, StorageLocation};
use ethers::solc::remappings::Remapping;
use ethers::solc::sourcemap::SourceElement;
use ethers::solc::{sourcemap::SourceMap, Artifact, ProjectCompileOutput};
use futures::stream::StreamExt;
use revm::{opcode, spec_opcode_gas, SpecId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[async_trait]
pub trait ContractIdentifier {
    async fn build(&mut self, list: Vec<Address>) -> Result<()>;
    fn get_label(&self, contract: Address) -> Option<String>;
    fn get_artifact(&self, contract: Address) -> Option<&ContractArtifact>;
}

#[derive(Debug)]
pub struct OnlineContractIdentifier {
    client: Arc<Client>,
    contract_meta: HashMap<Address, Metadata>,
    contract_artifact: HashMap<Address, ContractArtifact>,
}

impl OnlineContractIdentifier {
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(client),
            contract_meta: HashMap::new(),
            contract_artifact: HashMap::new(),
        }
    }
}

#[async_trait]
impl ContractIdentifier for OnlineContractIdentifier {
    async fn build(&mut self, mut list: Vec<Address>) -> Result<()> {
        list.sort();
        list.dedup();

        let list = futures::stream::iter(list.into_iter().map(|addr| {
            let client = self.client.clone();
            async move {
                if let Ok(meta) = client.contract_source_code(addr).await {
                    meta.items
                        .into_iter()
                        .next()
                        .filter(|meta| !meta.is_vyper())
                        .map(|meta| (addr, meta))
                } else {
                    // contract not verified / network problem
                    None
                }
            }
        }))
        .boxed()
        .buffer_unordered(1)
        .collect::<Vec<Option<(Address, Metadata)>>>()
        .await;

        futures::future::join_all(list.into_iter().filter_map(|resp| {
            let (addr, meta) = resp?;
            Some(async move {
                let artifact = compile_from_source(&meta);
                (addr, meta, artifact)
            })
        }))
        .await
        .into_iter()
        .for_each(|(addr, meta, artifact)| {
            self.contract_meta.insert(addr, meta);
            artifact
                .map(|artifact| self.contract_artifact.insert(addr, artifact))
                .unwrap_or_default();
        });

        Ok(())
    }

    fn get_label(&self, key: Address) -> Option<String> {
        Some(self.contract_meta.get(&key)?.contract_name.clone())
    }

    fn get_artifact(&self, contract: Address) -> Option<&ContractArtifact> {
        self.contract_artifact.get(&contract)
    }
}

/// Creates and compiles a project from an Etherscan source.
fn compile_from_source(metadata: &Metadata) -> Result<ContractArtifact> {
    let root = tempfile::tempdir()?;
    let root_path = root.path();
    let project = etherscan_project(metadata, root_path)?;

    let project = project.compile()?;
    root.close()?;

    if project.has_compiler_errors() {
        return Err(anyhow!("{:#?}", project.output().errors));
    }

    let addr = Address::zero();
    contract_artifact_from_project(&project, |contract, _art| {
        if contract == &metadata.contract_name {
            Some(addr)
        } else {
            None
        }
    })
    .remove(&addr)
    .ok_or(anyhow!("not find contract artifact"))
}

fn contract_artifact_from_project<F: Fn(&str, &ConfigurableContractArtifact) -> Option<Address>>(
    project: &ProjectCompileOutput,
    find_address: F,
) -> HashMap<Address, ContractArtifact> {
    let mut pos_fn_map = HashMap::new();
    let artifacts = project
        .artifacts()
        .filter_map(|(contract, artifact)| {
            let mut art = ContractArtifact::try_from(artifact).ok()?;
            let fn_map = std::mem::take(&mut art.pos_fn_map);
            pos_fn_map.extend(Arc::try_unwrap(fn_map).ok()?);

            let addr = find_address(&contract, artifact)?;
            Some((addr, art))
        })
        .collect::<HashMap<_, _>>();

    let pos_fn_map = Arc::new(pos_fn_map);
    artifacts
        .into_iter()
        .map(|(addr, mut art)| {
            art.pos_fn_map = pos_fn_map.clone();
            (addr, art)
        })
        .collect::<HashMap<_, _>>()
}

/// Creates a [Project] from an Etherscan source.
fn etherscan_project(metadata: &Metadata, target_path: impl AsRef<Path>) -> Result<Project> {
    let target_path = dunce::canonicalize(target_path.as_ref())?;
    let sources_path = target_path.join(&metadata.contract_name);
    metadata.source_tree().write_to(&target_path)?;

    let mut settings = metadata.source_code.settings()?.unwrap_or_default();

    // make remappings absolute with our root
    for remapping in settings.remappings.iter_mut() {
        let new_path = sources_path.join(remapping.path.trim_start_matches('/'));
        remapping.path = new_path.display().to_string();
    }

    // add missing remappings
    if !settings
        .remappings
        .iter()
        .any(|remapping| remapping.name.starts_with("@openzeppelin/"))
    {
        let oz = Remapping {
            name: "@openzeppelin/".into(),
            path: sources_path.join("@openzeppelin").display().to_string(),
        };
        settings.remappings.push(oz);
    }

    // root/
    //   ContractName/
    //     [source code]
    let paths = ProjectPathsConfig::builder()
        .sources(sources_path)
        .remappings(settings.remappings.clone())
        .build_with_root(target_path);

    let v = metadata.compiler_version()?;
    let v = format!("{}.{}.{}", v.major, v.minor, v.patch);
    let solc = Solc::find_or_install_svm_version(v)?;

    Ok(Project::builder()
        .solc_config(SolcConfig::builder().settings(settings).build())
        .paths(paths)
        .solc(solc)
        .ephemeral()
        .set_no_artifacts(false)
        .build()?)
}

#[derive(Debug)]
pub struct LocalContractIdentifier {
    client: SignerClient,
    project: ProjectCompileOutput,
    contract_artifact: HashMap<Address, ContractArtifact>,
}

impl LocalContractIdentifier {
    pub fn new<T: AsRef<Path>>(path: T, client: SignerClient) -> Result<Self> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        let paths = ProjectPathsConfig::builder().sources(&root).build()?;
        let project = Project::builder()
            .paths(paths)
            .ephemeral()
            .set_no_artifacts(false)
            .build()?
            .compile()?;

        if project.has_compiler_errors() {
            return Err(anyhow!("{:#?}", project.output().errors));
        }

        Ok(Self {
            client,
            project,
            contract_artifact: HashMap::new(),
        })
    }

    pub fn find_contract<T: AsRef<str>>(
        &self,
        contract: T,
    ) -> Option<&ConfigurableContractArtifact> {
        self.project.find_first(contract)
    }
}

#[async_trait]
impl ContractIdentifier for LocalContractIdentifier {
    async fn build(&mut self, mut list: Vec<Address>) -> Result<()> {
        list.sort();
        list.dedup();

        let bytecodes = futures::future::join_all(list.into_iter().map(|addr| {
            let client = self.client.clone();
            async move { (client.get_code(addr, None).await, addr) }
        }))
        .await
        .into_iter()
        .filter_map(|(code, addr)| Some((code.ok()?, addr)))
        .collect::<HashMap<Bytes, Address>>();

        self.contract_artifact =
            contract_artifact_from_project(&self.project, |_contract, artifact| {
                let bytecode = artifact.get_deployed_bytecode_bytes()?.into_owned();
                bytecodes.get(&bytecode).copied()
            });

        Ok(())
    }

    fn get_label(&self, _contract: Address) -> Option<String> {
        None
    }

    fn get_artifact(&self, contract: Address) -> Option<&ContractArtifact> {
        self.contract_artifact.get(&contract)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceLocation {
    start: usize,
    length: usize,
    index: usize,
}

impl TryFrom<&SourceElement> for SourceLocation {
    type Error = Error;

    fn try_from(el: &SourceElement) -> Result<Self> {
        Ok(Self {
            start: el.offset,
            length: el.length,
            index: el
                .index
                .map(|i| i as usize)
                .ok_or(anyhow!("no source index"))?,
        })
    }
}

impl TryFrom<&PartialSourceLocation> for SourceLocation {
    type Error = Error;

    fn try_from(loc: &PartialSourceLocation) -> Result<Self> {
        Ok(Self {
            start: loc.start,
            length: loc.length.ok_or(anyhow!("no length"))?,
            index: loc.index.ok_or(anyhow!("no source index"))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct StorageLocationFunction {
    pub name: String,
    pub inputs: Vec<StorageLocationParam>,
    pub outputs: Vec<StorageLocationParam>,
    pub state_mutability: StateMutability,
}

#[derive(Debug, Clone)]
pub struct StorageLocationParam {
    pub name: String,
    pub kind: ParamType,
    pub internal_type: Option<String>,
    pub storage_location: StorageLocation,
}

#[derive(Debug, Default)]
pub struct ContractArtifact {
    pub source_map: SourceMap,
    pub pc_ic_map: PCICMap,
    pub pos_fn_map: Arc<HashMap<SourceLocation, StorageLocationFunction>>,
}

impl TryFrom<&ConfigurableContractArtifact> for ContractArtifact {
    type Error = Error;
    fn try_from(artifact: &ConfigurableContractArtifact) -> Result<Self> {
        let source_map = artifact
            .get_source_map_deployed()
            .ok_or(anyhow!("no source_map"))??;
        let bytecode = artifact
            .get_deployed_bytecode_bytes()
            .ok_or(anyhow!("no bytecode"))?;
        let pc_ic_map = build_pc_ic_map(SpecId::LATEST, &bytecode);
        let pos_fn_map = Arc::new(
            artifact
                .ast
                .as_ref()
                .map(|ast| build_fn_map(ast))
                .ok_or(anyhow!("no ast"))?,
        );

        Ok(Self {
            source_map,
            pc_ic_map,
            pos_fn_map,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ASTFunction {
    name: String,
    parameters: ParameterList,
    return_parameters: ParameterList,
    state_mutability: StateMutability,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParameterList {
    parameters: Vec<Parameter>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Parameter {
    name: String,
    storage_location: StorageLocation,
    type_descriptions: ParameterTypeDescription,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ParameterTypeDescription {
    type_identifier: String,
    type_string: String,
}

impl TryInto<StorageLocationFunction> for ASTFunction {
    type Error = Error;
    fn try_into(self) -> Result<StorageLocationFunction> {
        let inputs = parse_param_list(self.parameters.parameters)?;
        let outputs = parse_param_list(self.return_parameters.parameters)?;

        fn parse_param_list(param_list: Vec<Parameter>) -> Result<Vec<StorageLocationParam>> {
            param_list.into_iter().try_fold(vec![], |mut acc, param| {
                acc.push(StorageLocationParam {
                    name: param.name,
                    kind: HumanReadableParser::parse_type(&param.type_descriptions.type_string)?,
                    internal_type: None,
                    storage_location: param.storage_location,
                });
                Ok(acc)
            })
        }

        Ok(StorageLocationFunction {
            name: self.name,
            inputs,
            outputs,
            state_mutability: self.state_mutability,
        })
    }
}

fn build_fn_map(ast: &Ast) -> HashMap<SourceLocation, StorageLocationFunction> {
    fn parse_fn(node: &Node) -> Option<(SourceLocation, StorageLocationFunction)> {
        let f: ASTFunction =
            serde_json::from_str(&serde_json::to_string(&node.other).ok()?).ok()?;

        Some((
            SourceLocation::try_from(&node.src).ok()?,
            f.try_into().ok()?,
        ))
    }

    ast.nodes
        .iter()
        .filter_map(|node| match node.node_type {
            NodeType::FunctionDefinition => Some(vec![parse_fn(node)?]),
            NodeType::ContractDefinition => Some(
                node.nodes
                    .iter()
                    .filter_map(|node| {
                        if node.node_type == NodeType::FunctionDefinition {
                            Some(parse_fn(node)?)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect::<HashMap<SourceLocation, StorageLocationFunction>>()
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
