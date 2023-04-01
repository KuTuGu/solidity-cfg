use super::parse::Node;
use anyhow::{anyhow, Result};
use ethers::prelude::*;
use petgraph::dot::Dot;
use petgraph::graph::DiGraph;
use petgraph::graph::NodeIndex;
use petgraph::Graph;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::{fs::File, io::Write, path::Path};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JumpNode {
    name: String,
    address: Address,
    depth: u64,
}

impl From<&Node> for JumpNode {
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
                if node.op == Opcode::JUMP {
                    *enter_jump_map.entry(JumpNode::from(&node)).or_insert(0_u32) += 1;
                }
                let index = graph.add_node(node.clone());
                stack
                    .last()
                    .map(|(.., parent_index)| graph.add_edge(parent_index.clone(), index, ()));
                stack.push((node, index));
            } else {
                let exit = node;
                if let Some((mut enter, enter_index)) = match exit.op {
                    Opcode::JUMP => {
                        let exit_jump_node = JumpNode::from(&exit);
                        match enter_jump_map.get(&exit_jump_node) {
                            Some(e) if e > &0 => loop {
                                let node = stack.pop().ok_or(anyhow!("missing enter jump"))?;
                                match node.0.op {
                                    Opcode::JUMP => {
                                        enter_jump_map
                                            .entry(JumpNode::from(&node.0))
                                            .and_modify(|c| *c = c.saturating_sub(1));
                                        if exit_jump_node == JumpNode::from(&node.0) {
                                            break Some(node);
                                        }
                                    }
                                    _ => Err(anyhow!("missing enter jump"))?,
                                }
                            },
                            _ => None,
                        }
                    }
                    _ => loop {
                        let node = stack.pop().ok_or(anyhow!("missing enter call"))?;
                        match node.0.op {
                            Opcode::CALL | Opcode::DELEGATECALL | Opcode::STATICCALL
                                if node.0.address == exit.address && node.0.enter =>
                            {
                                break Some(node);
                            }
                            _ => {
                                enter_jump_map
                                    .entry(JumpNode::from(&node.0))
                                    .and_modify(|c| *c = c.saturating_sub(1));
                            }
                        }
                    },
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
