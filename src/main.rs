use std::collections::HashMap;

use anyhow::{Error, Ok, Result};
use kyber_rs::{
    group::edwards25519::{Point as EdPoint, SuiteEd25519},
    share::dkg::rabin::{new_dist_key_generator, Deal, DistKeyGenerator, Justification, Response},
    util::key::Pair,
    Group, Point, Random, Scalar,
};
use thiserror::Error;

type Suite = kyber_rs::group::edwards25519::SuiteEd25519;

#[derive(Default)]
struct Node {
    index: usize,
    key: Pair<EdPoint>,
    dkg: Option<DistKeyGenerator<Suite>>,
    deals: Option<HashMap<usize, Deal<EdPoint>>>,
    // responses: HashMap<usize, Response>,
    responses: Vec<Response>,
    suite: SuiteEd25519,
    justifications: HashMap<usize, Option<Justification<Suite>>>,
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
    #[error("DKG not certified")]
    DkgNotCertified,
}

impl Node {
    fn new(index: usize) -> Result<Self> {
        Ok(Self {
            index,
            key: new_key_pair(&Suite::new_blake_sha256ed25519()),
            ..Default::default()
        })
    }

    fn init_dkg(&mut self, public_keys: &[EdPoint]) -> Result<()> {
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

    fn get_deal(&self, index: usize) -> Result<&Deal<EdPoint>> {
        self.deals
            .as_ref()
            .ok_or(NodeError::NoDeals)?
            .get(&index)
            .ok_or(NodeError::NoDealForIndex(index).into())
    }

    fn process_deal(&mut self, deal: &Deal<EdPoint>) -> Result<()> {
        let response = self
            .dkg
            .as_mut()
            .ok_or(NodeError::DkgNotInitialized)?
            .process_deal(deal)?;
        self.responses.push(response);
        Ok(())
    }

    fn get_responses(&self) -> Result<&Vec<Response>> {
        Ok(&self.responses)
    }

    fn process_response(&mut self, response: &Response) -> Result<()> {
        let justification = self
            .dkg
            .as_mut()
            .ok_or(NodeError::DkgNotInitialized)?
            .process_response(response)?;
        if let Some(_) = justification {
            println!(
                "Justification generated for response with index {}",
                response.index,
            );
        }
        self.justifications
            .insert(response.index as usize, justification);
        Ok(())
    }

    fn get_justifications(&self, index: usize) -> Result<Vec<&Option<Justification<Suite>>>> {
        Ok(self
            .dkg
            .as_ref()
            .ok_or(NodeError::DkgNotInitialized)?
            .participants
            .iter()
            .enumerate()
            .filter(|(i, _)| i != &index)
            .map(|(i, _)| match self.justifications.get(&i) {
                Some(j) => j,
                None => &None,
            })
            .collect())
    }

    fn process_justification(&mut self, justification: &Justification<Suite>) -> Result<()> {
        self.dkg
            .as_mut()
            .ok_or(NodeError::DkgNotInitialized)?
            .process_justification(justification)?;
        Ok(())
    }

    fn is_ready(&self) -> Result<()> {
        let dkg = self.dkg.as_ref().ok_or(NodeError::DkgNotInitialized)?;
        println!(
            "Qualified {} nodes for node {}",
            dkg.qual().len(),
            self.index
        );
        if !dkg.certified() {
            return Err(NodeError::DkgNotCertified.into());
        }
        Ok(())
    }
}

#[test]
fn test_main() -> Result<()> {
    main()
}

fn main() -> Result<()> {
    let _suite = Suite::new_blake_sha256ed25519();
    let mut nodes = (0..5)
        .map(|i| Node::new(i))
        .collect::<Result<Vec<Node>>>()?;

    let public_keys: Vec<EdPoint> = nodes.iter().map(|n| n.key.public.to_owned()).collect();

    for node in &mut nodes {
        node.init_dkg(&public_keys)?;
    }

    println!("Processing Deals");
    for_each_node_pair(&mut nodes, |node, other_node| {
        let deal = &other_node.get_deal(node.index)?;
        println!("\tdeal from {} for {}", deal.index, node.index);
        node.process_deal(deal)
    })?;

    println!("\nProcessing Responses");
    for_each_node_pair(&mut nodes, |node, other_node| {
        for response in other_node.get_responses()? {
            println!(
                "Processing response with index {} from node {} for node {}",
                response.index, other_node.index, node.index
            );
            node.process_response(response)?;
        }
        Ok(())
    })?;

    println!("\nProcessing Justifications");
    for_each_node_pair(&mut nodes, |node, other_node| {
        for justification in other_node.get_justifications(node.index)? {
            match justification {
                Some(justification) => {
                    println!(
                        "Processing justification {} for node {}",
                        justification.index, node.index
                    );
                    node.process_justification(justification)?;
                }
                None => (),
            }
        }
        Ok(())
    })?;

    println!("\nChecking if nodes are ready");
    for node in nodes {
        node.is_ready()?;
        println!("Node {} is ready", node.index);
    }

    Ok(())
}

fn new_key_pair(suite: &Suite) -> Pair<EdPoint> {
    let private = suite.scalar().pick(&mut suite.random_stream());
    let public = suite.point().mul(&private, None);
    Pair { private, public }
}

fn for_each_node_pair<F>(nodes: &mut [Node], f: F) -> Result<()>
where
    F: Fn(&mut Node, &mut Node) -> Result<()>,
{
    for i in 0..nodes.len() {
        let (node, nodes) = extract_node(nodes, i)?;
        for n in nodes {
            f(node, n)?;
        }
    }
    nodes.sort_by_key(|n| n.index);
    Ok(())
}

fn extract_node(nodes: &mut [Node], i: usize) -> Result<(&mut Node, &mut [Node])> {
    nodes.sort_by(|a, b| match a.index {
        idx if idx == i => std::cmp::Ordering::Less,
        idx => idx.cmp(&b.index),
    });
    nodes
        .split_first_mut()
        .ok_or(Error::msg("Could not extract node"))
}
