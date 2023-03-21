mod utils;
use utils::*;

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::prelude::*;

    #[tokio::test]
    async fn test_it_works() {
        vm::analyze().await;
    }
}
