use anyhow::{anyhow, Result};
use ethers::abi::Token;
use ethers::prelude::*;
use petgraph::dot::Dot;
use petgraph::graph::DiGraph;
use petgraph::graph::NodeIndex;
use petgraph::Graph;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::{fs::File, io::Write, path::Path};

#[derive(Debug, Clone)]
pub struct Node {
    pub enter: bool,
    pub name: Option<String>,
    pub address: Address,
    pub depth: u64,
    pub op: Opcode,
    pub value: Option<U256>,
    pub input: Option<BTreeMap<String, Token>>,
    pub output: Option<BTreeMap<String, Token>>,
    pub gas: Gas,
}

impl Node {
    fn is_jump(&self) -> bool {
        self.op == Opcode::JUMP
    }
    fn is_call(&self) -> bool {
        !self.is_jump()
    }
}

#[derive(Debug, Clone)]
pub struct Gas {
    pub gas_used: u64,
    pub gas_left: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JumpID {
    name: String,
    address: Address,
    depth: u64,
}

impl From<&Node> for JumpID {
    fn from(node: &Node) -> Self {
        Self {
            name: node.name.clone().unwrap(),
            address: node.address,
            depth: node.depth,
        }
    }
}

pub fn parse_graph(list: Vec<Node>) -> Result<Graph<Node, ()>> {
    let mut stack: Vec<(Node, NodeIndex)> = vec![];
    let mut enter_jump_map = HashMap::new();

    list.into_iter()
        .try_fold(DiGraph::new(), |mut graph, node| {
            if node.enter {
                if node.is_jump() {
                    *enter_jump_map.entry(JumpID::from(&node)).or_insert(0_u32) += 1;
                }
                let index = graph.add_node(node.clone());
                stack
                    .last()
                    .map(|(.., parent_index)| graph.add_edge(parent_index.clone(), index, ()));
                stack.push((node, index));
            } else {
                let exit = node;
                if let Some((mut enter, enter_index)) = if exit.is_jump() {
                    let exit_jump_node = JumpID::from(&exit);
                    match enter_jump_map.get(&exit_jump_node) {
                        Some(&cnt) if cnt > 0 => loop {
                            let node = stack.pop().ok_or(anyhow!("missing enter jump"))?;
                            if node.0.is_jump() {
                                enter_jump_map
                                    .entry(JumpID::from(&node.0))
                                    .and_modify(|c| *c = c.saturating_sub(1));
                                if exit_jump_node == JumpID::from(&node.0) {
                                    break Some(node);
                                }
                            } else {
                                // fail if out of call boundary
                                Err(anyhow!("missing enter jump"))?
                            }
                        },
                        _ => None,
                    }
                } else {
                    loop {
                        let node = stack.pop().ok_or(anyhow!("missing enter call"))?;
                        if node.0.is_call() {
                            if node.0.address == exit.address && node.0.enter {
                                break Some(node);
                            } else {
                                // fail if mismatch call node
                                Err(anyhow!("missing enter call"))?
                            }
                        } else {
                            enter_jump_map
                                .entry(JumpID::from(&node.0))
                                .and_modify(|c| *c = c.saturating_sub(1));
                        }
                    }
                } {
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
            }

            Ok(graph)
        })
}

pub fn draw_graph<T: AsRef<Path>>(graph: &Graph<Node, ()>, path: T) {
    let dot = format!("{:#?}", Dot::new(graph));
    let mut file = File::create(path).unwrap();
    file.write_all(dot.as_bytes()).unwrap();
}
