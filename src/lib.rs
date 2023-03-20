mod utils;
use utils::*;

pub fn cfg() {
    ast::analyze();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        cfg();
    }
}
