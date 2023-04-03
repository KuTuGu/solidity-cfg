use ethers::{prelude::*, providers::Provider, utils::Anvil};
use solidity_cfg::*;
use std::sync::Arc;

const CHAIN_ID: u64 = 1;
const TX_HASH: &str = "0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d";
const BLOCK_NUMBER: u64 = 16817996;
const PROVIDER: &str = "https://rpc.ankr.com/eth";

abigen!(TestContract, r#"[function entry(uint _a, uint _b)]"#);

#[tokio::test(flavor = "multi_thread")]
async fn eluer() {
    let block = BLOCK_NUMBER - 2;
    let anvil = Anvil::new()
        .fork(PROVIDER)
        .fork_block_number(block)
        .port(8545_u16)
        .timeout(20000_000_u64)
        .chain_id(CHAIN_ID)
        .spawn();
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let wallet = wallet.with_chain_id(anvil.chain_id());
    let provider = Provider::<Http>::connect(&anvil.endpoint()).await;
    let client = SignerMiddleware::new(provider, wallet.clone());
    let client = Arc::new(client);
    let tx_hash = TX_HASH.parse::<TxHash>().unwrap();
    let tx = client.get_transaction(tx_hash).await.unwrap().unwrap();

    let etherscan = Client::builder()
        .chain(Chain::try_from(CHAIN_ID).unwrap())
        .unwrap()
        // you may need to provide an api key, otherwise won't fetch the contract source.
        // .with_api_key("YOUR_ETHERSCAN_API_KEY")
        .build()
        .unwrap();
    let identifier = OnlineContractIdentifier::new(etherscan);
    let mut cfg = CFG::new(
        &tx,
        Some(BlockId::Number(BlockNumber::Number(block.into()))),
        client,
        identifier,
    );
    let node_list = cfg.analyze().await.unwrap();
    let graph = parse_graph(node_list).unwrap();
    draw_graph(&graph, "eluer.dot");
}
