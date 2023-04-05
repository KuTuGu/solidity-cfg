use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ethers::etherscan::contract::Metadata;
use ethers::prelude::*;
use ethers::solc::remappings::Remapping;
use ethers::solc::{
    artifacts::contract::CompactContractBytecode, sourcemap::SourceMap, Artifact,
    ProjectCompileOutput,
};
use futures::stream::StreamExt;
use revm::{opcode, spec_opcode_gas, SpecId};
use std::collections::HashMap;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{collections::BTreeMap, fs};

use crate::SignerClient;

#[async_trait]
pub trait ContractIdentifier {
    type Key: ?Sized;

    async fn build(&mut self, list: Vec<Address>) -> Result<()>;

    fn get_label(&self, _key: Address) -> Option<String> {
        None
    }

    fn get_contract_key(&self, key: Address) -> Option<&Self::Key>;

    // The unit is file
    // source_index -> source_code
    fn get_source_code(&self, key: &Self::Key, i: &u32) -> Option<&String>;

    // The unit is contract (
    //   may be larger than files, such as import other files;
    //   may also be smaller than a file, such as a file with multiple contracts
    // )
    // key -> (source_map, pc_ic_map)
    fn get_source_map(&self, key: &Self::Key) -> Option<&SourceMap>;
    fn get_pc_ic_map(&self, key: &Self::Key) -> Option<&PCICMap>;
}

#[derive(Debug)]
pub struct OnlineContractIdentifier {
    client: Arc<Client>,
    contract_meta: BTreeMap<Address, Metadata>,
    contract_source: BTreeMap<String, ContractSourceSome>,
}

#[derive(Debug)]
struct ContractSourceSome {
    source_code: BTreeMap<u32, String>,
    source_map: SourceMap,
    pc_ic_map: PCICMap,
}

impl OnlineContractIdentifier {
    pub fn new(client: Client) -> Self {
        Self {
            client: Arc::new(client),
            contract_meta: BTreeMap::new(),
            contract_source: BTreeMap::new(),
        }
    }
}

#[async_trait]
impl ContractIdentifier for OnlineContractIdentifier {
    // can not accurately match local and online bytecode, only by contract name
    type Key = Metadata;

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

        let mut result = futures::future::join_all(list.into_iter().filter_map(|resp| {
            let (addr, meta) = resp?;
            Some(async move {
                let source = compile_from_source(&meta).await;
                (addr, meta, source)
            })
        }))
        .await
        .into_iter();

        while let Some((addr, meta, Ok(source))) = result.next() {
            let name = meta.contract_name.clone();
            self.contract_meta.insert(addr, meta);
            self.contract_source.insert(name, source);
        }

        Ok(())
    }

    fn get_label(&self, key: Address) -> Option<String> {
        Some(self.contract_meta.get(&key)?.contract_name.clone())
    }

    fn get_contract_key(&self, key: Address) -> Option<&Self::Key> {
        self.contract_meta.get(&key)
    }

    fn get_source_code(&self, key: &Self::Key, i: &u32) -> Option<&String> {
        self.contract_source
            .get(&key.contract_name)?
            .source_code
            .get(i)
    }

    fn get_source_map(&self, key: &Self::Key) -> Option<&SourceMap> {
        Some(&self.contract_source.get(&key.contract_name)?.source_map)
    }

    fn get_pc_ic_map(&self, key: &Self::Key) -> Option<&PCICMap> {
        Some(&self.contract_source.get(&key.contract_name)?.pc_ic_map)
    }
}

/// Creates and compiles a project from an Etherscan source.
async fn compile_from_source(metadata: &Metadata) -> Result<ContractSourceSome> {
    let root = tempfile::tempdir()?;
    let root_path = root.path();
    let project = etherscan_project(metadata, root_path)?;

    let project = project.compile()?;

    if project.has_compiler_errors() {
        return Err(anyhow!("{:#?}", project.output().errors));
    }

    let (artifacts, sources) = project.into_artifacts_with_sources();
    let source_code = sources
        .into_sources()
        .filter_map(|(path, source)| {
            Some((source.id, fs::read_to_string(root_path.join(path)).ok()?))
        })
        .collect::<BTreeMap<_, _>>();
    let (source_map, pc_ic_map) = artifacts
        .into_iter()
        .find_map(|(id, artifact)| {
            if id.name == metadata.contract_name {
                let artifact = CompactContractBytecode::from(artifact);
                let source_map = artifact.get_source_map_deployed()?.ok()?;
                let bytecode = artifact.get_deployed_bytecode_bytes()?;
                let pc_ic_map = build_pc_ic_map(SpecId::LATEST, &bytecode);

                Some((source_map, pc_ic_map))
            } else {
                None
            }
        })
        .ok_or(anyhow!("no source some"))?;

    root.close()?;

    Ok(ContractSourceSome {
        source_code,
        source_map,
        pc_ic_map,
    })
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
    root: PathBuf,
    client: SignerClient,
    pub project: Option<ProjectCompileOutput>,
    bytecode: BTreeMap<Address, Bytes>,
    source_code: BTreeMap<u32, String>,
    source_map: HashMap<Bytes, (SourceMap, PCICMap)>,
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
            Err(anyhow!("{:#?}", project.output().errors))
        } else {
            Ok(Self {
                root,
                client,
                project: Some(project),
                bytecode: BTreeMap::new(),
                source_code: BTreeMap::new(),
                source_map: HashMap::new(),
            })
        }
    }
}

#[async_trait]
impl ContractIdentifier for LocalContractIdentifier {
    // bytecode
    type Key = Bytes;

    async fn build(&mut self, mut list: Vec<Address>) -> Result<()> {
        let (artifacts, sources) = self
            .project
            .clone()
            .ok_or(anyhow!("no project"))?
            .into_artifacts_with_sources();

        list.sort();
        list.dedup();
        self.bytecode = futures::future::join_all(list.into_iter().map(|addr| {
            let client = self.client.clone();
            async move { (addr, client.get_code(addr, None).await) }
        }))
        .await
        .into_iter()
        .filter_map(|(addr, code)| Some((addr, code.ok()?)))
        .collect::<BTreeMap<Address, Bytes>>();

        self.source_code = sources
            .into_sources()
            .map(|(path, source)| (source.id, fs::read_to_string(self.root.join(path)).unwrap()))
            .collect::<BTreeMap<_, _>>();
        self.source_map = artifacts
            .into_iter()
            .filter_map(|(_id, artifact)| {
                let artifact = CompactContractBytecode::from(artifact);
                let source_map = artifact.get_source_map_deployed()?.ok()?;
                let bytecode = artifact.get_deployed_bytecode_bytes()?;
                let pc_ic_map = build_pc_ic_map(SpecId::LATEST, &bytecode);

                Some((bytecode.into_owned(), (source_map, pc_ic_map)))
            })
            .collect::<HashMap<_, _>>();

        Ok(())
    }

    fn get_contract_key(&self, key: Address) -> Option<&Self::Key> {
        self.bytecode.get(&key)
    }

    fn get_source_code(&self, _key: &Self::Key, i: &u32) -> Option<&String> {
        self.source_code.get(i)
    }

    fn get_source_map(&self, key: &Self::Key) -> Option<&SourceMap> {
        Some(&self.source_map.get(key)?.0)
    }

    fn get_pc_ic_map(&self, key: &Self::Key) -> Option<&PCICMap> {
        Some(&self.source_map.get(key)?.1)
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
