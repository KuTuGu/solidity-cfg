use ethers::prelude::{Address, Bytes};
use ethers::solc::artifacts::CompactDeployedBytecode;
use ethers::solc::sourcemap::{Jump, SourceElement};
use ethers::solc::{
    artifacts::{contract::CompactContractBytecode, Ast, CompactBytecode},
    sourcemap::SourceMap,
    Artifact, Project,
};
use ethers::solc::{ArtifactId, ProjectPathsConfig};
use revm::interpreter::{opcode, spec_opcode_gas};
use revm::primitives::SpecId;
use std::collections::BTreeMap;
use std::{collections::HashMap, fs};

pub fn analyze() {
    // Same as [`Self::project()`] but sets configures the project to not emit artifacts and ignore
    // cache, caching causes no output until https://github.com/gakonst/ethers-rs/issues/727
    let path = ProjectPathsConfig::builder().build().unwrap();
    let path = ProjectPathsConfig::builder()
        .sources(path.root.join("contracts"))
        .build()
        .unwrap();
    let project = Project::builder()
        .paths(path.clone())
        .set_cached(false)
        .set_no_artifacts(false)
        .build()
        .unwrap()
        .compile()
        .unwrap();
    assert!(
        !project.has_compiler_errors(),
        "{:#?}",
        project.output().errors
    );
    let (artifacts, mut sources) = project.into_artifacts_with_sources();

    let (sources, (ic_pc_maps, (asts, (source_maps, bytecodes)))): (
        HashMap<ArtifactId, Bytes>,
        (
            HashMap<ArtifactId, (ICPCMap, ICPCMap)>,
            (
                HashMap<ArtifactId, Ast>,
                (
                    HashMap<ArtifactId, (SourceMap, SourceMap)>,
                    HashMap<ArtifactId, (Bytes, Bytes)>,
                ),
            ),
        ),
    ) = artifacts
        .into_iter()
        .map(|(id, artifact)| (id, CompactContractBytecode::from(artifact)))
        .filter_map(|(id, artifact)| {
            if (&path).has_library_ancestor(&id.source) {
                return None;
            }
            let asts = (
                id.clone(),
                sources
                    .remove_by_path(id.source.as_os_str().to_str()?)?
                    .ast?,
            );
            let sources = (
                id.clone(),
                fs::read_to_string(&id.source)
                    .ok()?
                    .as_bytes()
                    .to_vec()
                    .into(),
            );
            let source_maps = (
                id.clone(),
                (
                    artifact.get_source_map()?.ok()?,
                    artifact
                        .get_deployed_bytecode()
                        .as_ref()?
                        .bytecode
                        .as_ref()?
                        .source_map()?
                        .ok()?,
                ),
            );
            let bytecodes = (
                id.clone(),
                (
                    artifact
                        .get_bytecode()
                        .and_then(|bytecode| dummy_link_bytecode(bytecode.into_owned()))?,
                    artifact
                        .get_deployed_bytecode()
                        .and_then(|bytecode| dummy_link_deployed_bytecode(bytecode.into_owned()))?,
                ),
            );
            // Build IC -> PC mappings
            //
            // The source maps are indexed by *instruction counters*, which are the indexes of
            // instructions in the bytecode *minus any push bytes*.
            //
            // Since our coverage inspector collects hit data using program counters, the anchors also
            // need to be based on program counters.
            // TODO: Index by contract ID
            let ic_pc_maps = (
                id.clone(),
                (
                    build_ic_pc_map(SpecId::LATEST, bytecodes.1 .0.as_ref()),
                    build_ic_pc_map(SpecId::LATEST, bytecodes.1 .1.as_ref()),
                ),
            );

            Some((sources, (ic_pc_maps, (asts, (source_maps, bytecodes)))))
        })
        .unzip();

    for (id, (.., source_map)) in source_maps.iter() {
        match (
            sources.get(id),
            asts.get(id),
            ic_pc_maps.get(id),
            bytecodes.get(id),
        ) {
            (Some(source), Some(ast), Some(ic_pc_map), Some(bytecode)) => match ast.src.index {
                Some(source_index) if source_index != usize::MAX => {
                    for source_element in source_map {
                        match source_element {
                            SourceElement {
                                jump,
                                index: Some(index),
                                ..
                            } if jump == &Jump::In
                                && index != &u32::MAX
                                && index.clone() as usize == source_index =>
                            {
                                dbg!(String::from_utf8(
                                    source[source_element.offset
                                        ..source_element.offset + source_element.length]
                                        .to_vec()
                                )
                                .unwrap(),);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }
}

/// A map of instruction counters to program counters.
type ICPCMap = BTreeMap<usize, usize>;

/// Builds a mapping from instruction counters to program counters.
fn build_ic_pc_map(spec: SpecId, code: &[u8]) -> ICPCMap {
    let opcode_infos = spec_opcode_gas(spec);
    let mut ic_pc_map: ICPCMap = ICPCMap::new();

    let mut i = 0;
    let mut cumulative_push_size = 0;
    while i < code.len() {
        let op = code[i];
        ic_pc_map.insert(i - cumulative_push_size, i);
        if opcode_infos[op as usize].is_push() {
            // Skip the push bytes.
            //
            // For more context on the math, see: https://github.com/bluealloy/revm/blob/007b8807b5ad7705d3cacce4d92b89d880a83301/crates/revm/src/interpreter/contract.rs#L114-L115
            i += (op - opcode::PUSH1 + 1) as usize;
            cumulative_push_size += (op - opcode::PUSH1 + 1) as usize;
        }
        i += 1;
    }

    ic_pc_map
}

/// Helper function that will link references in unlinked bytecode to the 0 address.
///
/// This is needed in order to analyze the bytecode for contracts that use libraries.
fn dummy_link_bytecode(mut obj: CompactBytecode) -> Option<Bytes> {
    let link_references = obj.link_references.clone();
    for (file, libraries) in link_references {
        for library in libraries.keys() {
            obj.link(&file, library, Address::zero());
        }
    }

    obj.object.resolve();
    obj.object.into_bytes()
}

/// Helper function that will link references in unlinked bytecode to the 0 address.
///
/// This is needed in order to analyze the bytecode for contracts that use libraries.
fn dummy_link_deployed_bytecode(obj: CompactDeployedBytecode) -> Option<Bytes> {
    obj.bytecode.and_then(dummy_link_bytecode)
}
