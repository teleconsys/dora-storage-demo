use std::collections::HashMap;

use anyhow::{Error, Result};
use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    share::dkg::rabin::{
        new_dist_key_generator, ComplaintCommits, Deal, DistKeyGenerator, Response, SecretCommits,
    },
    util::key::{new_key_pair, Pair},
    Group,
};
use thiserror::Error;

type Suite = kyber_rs::group::edwards25519::SuiteEd25519;

#[derive(Default)]
struct Node {
    index: usize,
    key: Pair<Point>,
    dkg: Option<DistKeyGenerator<Suite>>,
    deals: Option<HashMap<usize, Deal<Point>>>,
    responses: Vec<Response>,
    suite: SuiteEd25519,
}

#[derive(Error, Debug)]
enum NodeError {
    #[error("Dkg not initialized")]
    DkgNotInitialized,
    #[error("No deals generated")]
    NoDeals,
    #[error("No deal for index {0}")]
    NoDealForIndex(usize),
    #[error("No response for index {0}")]
    NoResponseForIndex(usize),
}

#[test]
fn test_new_node() -> Result<()> {
    let node_result = Node::new(0)?;
    Ok(())
}

impl Node {
    fn new(index: usize) -> Result<Self> {
        Ok(Self {
            index,
            key: new_key_pair(Suite::new_blake_sha256ed25519())?,
            ..Default::default()
        })
    }

    fn init_dkg(&mut self, public_keys: &[Point]) -> Result<()> {
        self.dkg = Some(new_dist_key_generator(
            &self.suite,
            &self.key.private,
            public_keys,
            3,
        )?);
        self.deals = Some(
            self.dkg
                .as_mut()
                .ok_or(NodeError::DkgNotInitialized)?
                .deals()?,
        );
        Ok(())
    }

    fn process_deal(&mut self, deal: &Deal<Point>) -> Result<()> {
        let response = self
            .dkg
            .as_mut()
            .ok_or(NodeError::DkgNotInitialized)?
            .process_deal(deal)?;
        self.responses.push(response);
        Ok(())
    }

    fn get_deal(&self, index: usize) -> Result<Deal<Point>> {
        Ok(self
            .deals
            .as_ref()
            .ok_or(NodeError::NoDeals)?
            .get(&index)
            .ok_or::<NodeError>(NodeError::NoDealForIndex(index))?
            .clone())
    }

    fn get_response(&self, index: usize) -> Result<&Response> {
        self.responses
            .iter()
            .filter(|r| r.index as usize == self.index)
            .next()
            .ok_or(NodeError::NoResponseForIndex(index).into())
    }

    fn process_response(&mut self, response: &Response) {}
}

#[test]
fn test_main() -> Result<()> {
    main()
}

fn main() -> Result<()> {
    let suite = Suite::new_blake_sha256ed25519();
    let mut nodes = (0..5)
        .map(|i| Node::new(i))
        .collect::<Result<Vec<Node>>>()?;

    let public_keys: Vec<Point> = nodes.iter().map(|n| n.key.public.to_owned()).collect();

    for node in &mut nodes {
        node.init_dkg(&public_keys)?;
    }

    for i in 0..nodes.len() {
        nodes.sort_by(|a, b| match a.index {
            idx if idx == i => std::cmp::Ordering::Less,
            idx => b.index.cmp(&idx),
        });
        let (node, nodes) = nodes.split_first_mut().ok_or(Error::msg("could not ???"))?;
        for n in nodes {
            node.process_deal(&n.get_deal(node.index)?)?;
        }
    }

    // for node in &mut nodes {
    //     let responses: Vec<Response> = nodes
    //         .iter()
    //         .filter(|n| n.index != node.index)
    //         .map(|n| {
    //             node.dkg
    //                 .unwrap()
    //                 .process_deal(n.deals.unwrap().get(&node.index).unwrap())
    //                 .unwrap()
    //         })
    //         .collect();
    // }

    Ok(())
}
