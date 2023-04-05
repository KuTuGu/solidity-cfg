mod graph;
mod identifier;
mod parse;

pub use graph::*;
pub use identifier::*;
pub use parse::*;

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::prelude::*;
    use ethers::{
        providers::Provider,
        signers::{LocalWallet, Signer},
        utils::Anvil,
    };
    use std::sync::Arc;

    abigen!(TestContract, r#"[function entry(uint _a, uint _b)]"#);

    #[tokio::test(flavor = "multi_thread")]
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
        let node_list = cfg.analyze().await.unwrap();
        let graph = parse_graph(node_list).unwrap();
        draw_graph(&graph, "graph.dot");
    }
}
