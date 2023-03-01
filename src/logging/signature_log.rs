use std::str::FromStr;

use anyhow::bail;
use colored::Colorize;
use identity_iota::core::ToJson;
use kyber_rs::{group::edwards25519::Point, sign::eddsa::EdDSA, util::key::Pair};
use serde::{Deserialize, Serialize};

use crate::{did::resolve_document, dlt::iota::Publisher};

#[derive(Clone)]
pub struct NodeSignatureLogger {
    own_did: String,
    committee_tag: String,
    keypair: Pair<Point>,
    node_url: String,
}

pub fn new_node_signature_logger(
    own_did: String,
    committee_did: String,
    keypair: Pair<Point>,
    node_url: String,
) -> NodeSignatureLogger {
    NodeSignatureLogger {
        own_did,
        committee_tag: committee_did.split(':').last().unwrap().to_string(),
        keypair,
        node_url,
    }
}

impl NodeSignatureLogger {
    pub fn publish(&self, log: &mut NodeSignatureLog) -> anyhow::Result<()> {
        let publisher = Publisher::new(&self.node_url)?;
        self.sign_log(log)?;

        let msg_id = tokio::runtime::Runtime::new()?
            .block_on(publisher.publish(&log.to_jcs()?, Some(self.committee_tag.clone())))?;
        log::info!(target: &signature_log_target(&log.session_id),
            "node's signature log published (msg_id: {})", msg_id);
        Ok(())
    }

    fn sign_log(&self, log: &mut NodeSignatureLog) -> anyhow::Result<()> {
        let eddsa = EdDSA::from(self.keypair.clone());
        log.add_sender(&self.own_did);
        log.add_signature(&eddsa.sign(&log.to_bytes()?)?);
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeSignatureLog {
    pub(crate) session_id: String,
    pub(crate) sender_did: String,
    pub(crate) absent_nodes: Vec<String>,
    pub(crate) bad_signers: Vec<String>,
    pub(crate) signature_hex: Option<String>,
}

pub fn new_signature_log(
    session_id: String,
    processed_partial_owners: Vec<Point>,
    bad_signers: Vec<Point>,
    did_urls: Vec<String>,
    node_url: String,
) -> anyhow::Result<(NodeSignatureLog, Vec<String>)> {
    // find out who didn't send a partial signature
    let mut processed_partial_owners_dids = vec![];
    for owner in processed_partial_owners {
        processed_partial_owners_dids.push(public_to_did(&did_urls, owner, &node_url)?);
    }

    let mut absent_nodes = did_urls.clone();
    for node in processed_partial_owners_dids.clone() {
        absent_nodes.retain(|x| *x != node);
    }

    // find out who was a bad signer
    let mut bad_signers_nodes = vec![];
    for owner in bad_signers {
        bad_signers_nodes.push(public_to_did(&did_urls, owner, &node_url)?);
    }

    let mut working_nodes = vec![];
    for did in processed_partial_owners_dids {
        if !bad_signers_nodes.contains(&did) {
            working_nodes.push(did);
        }
    }

    log::info!(target: &signature_log_target(&session_id),
        "signature success, nodes that didn't participate: {:?}, nodes that didn't provide a correct signature: {:?}", absent_nodes, bad_signers_nodes);
    Ok((
        NodeSignatureLog {
            session_id,
            sender_did: "".to_string(),
            absent_nodes,
            bad_signers: bad_signers_nodes,
            signature_hex: None,
        },
        working_nodes,
    ))
}

impl FromStr for NodeSignatureLog {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::de::from_str(s)
    }
}

impl NodeSignatureLog {
    fn add_sender(&mut self, sender: &str) {
        self.sender_did = sender.to_string();
    }

    fn add_signature(&mut self, signature: &[u8]) {
        self.signature_hex = Some(hex::encode(signature));
    }

    pub(crate) fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        self.to_jcs()
            .map_err(|_| anyhow::Error::msg("can not serialize log"))
    }
}

pub fn signature_log_target(session_id: &str) -> String {
    format!(
        "sign:{}",
        session_id.chars().take(10).collect::<String>().yellow()
    )
}

pub fn public_to_did(dids: &[String], public_key: Point, node_url: &str) -> anyhow::Result<String> {
    for did in dids.iter() {
        if resolve_document(did.to_string(), node_url)?.public_key()? == public_key {
            return Ok(did.to_string());
        }
    }
    bail!("could not find the offending DID")
}
