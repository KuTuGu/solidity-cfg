use ethers::prelude::*;
use ethers::solc::sourcemap::{Jump, SourceElement};
use ethers::utils::Anvil;
use revm::interpreter::{opcode, spec_opcode_gas};
use revm::primitives::SpecId;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

abigen!(TestContract, "out/test.sol/A.json");

pub async fn analyze() {
    // compile contract
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contracts");
    let paths = ProjectPathsConfig::builder()
        .sources(&root)
        .build()
        .unwrap();
    let project = Project::builder()
        .paths(paths)
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
    let contract = project
        .find_first("A")
        .expect("could not find contract")
        .clone();

    // source && sourcemap
    let source_index = contract.id.unwrap();
    assert!(source_index != u32::MAX);
    let source: Bytes = fs::read_to_string(root.join("test.sol"))
        .unwrap()
        .as_bytes()
        .to_vec()
        .into();
    let source_map = contract.get_source_map_deployed().unwrap().unwrap();
    let source_code = contract.get_deployed_bytecode_bytes().unwrap();
    let pc_ic_map = build_pc_ic_map(SpecId::LATEST, &source_code);

    // deploy contract
    let anvil = Anvil::new().port(8545_u16).timeout(20000_000_u64).spawn();
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let wallet = wallet.with_chain_id(anvil.chain_id());
    let provider = Provider::<Http>::connect(&anvil.endpoint()).await;
    let client = SignerMiddleware::new(provider, wallet.clone());
    let contract = TestContract::deploy(Arc::new(client.clone()), ())
        .unwrap()
        .send()
        .await
        .unwrap();

    // tx
    let tx = contract.entry(U256::from(1), U256::from(2)).tx;
    let options: GethDebugTracingCallOptions = GethDebugTracingCallOptions {
        tracing_options: GethDebugTracingOptions {
            disable_storage: Some(true),
            enable_memory: Some(false),
            ..Default::default()
        },
    };
    let trace = client.debug_trace_call(tx, None, options).await.unwrap();

    // analyze trace
    match trace {
        GethTrace::Known(GethTraceFrame::Default(frame)) => {
            frame.struct_logs.iter().for_each(|log| {
                let opcode = log.op.parse::<Opcode>().unwrap();
                if opcode == Opcode::JUMP || opcode == Opcode::JUMPI {
                    let pc = log.pc as usize;
                    let ic = pc_ic_map.get(&pc).unwrap().clone();
                    match source_map[ic] {
                        SourceElement {
                            jump,
                            index: Some(index),
                            offset,
                            length,
                            ..
                        } if jump == Jump::In && index != u32::MAX && index == source_index => {
                            let stack = log.stack.as_ref().unwrap();
                            let jump_dest = stack[stack.len() - 1].as_usize();
                            let jump_source_element =
                                &source_map[pc_ic_map.get(&jump_dest).unwrap().clone()];
                            dbg!(
                                pc,
                                ic,
                                source_map[ic].clone(),
                                jump_source_element,
                                log,
                                String::from_utf8(source[offset..offset + length].to_vec()),
                            );
                        }
                        _ => {}
                    }
                }
            })
        }
        _ => {}
    }
}

/// A map of program counters to instruction counters.
type PCICMap = HashMap<usize, usize>;

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
