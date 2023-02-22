extern crate log;
extern crate pretty_env_logger;

mod api;
mod demo;
mod did;
mod dlt;
mod logging;
mod net;
mod states;
mod store;

use std::str::FromStr;

use anyhow::{bail, Result};

use api::requests::messages::CommitteeLog;

use clap::Parser;
use demo::run::{run_node, NodeArgs};

use did::resolve_document;
use dlt::iota::Publisher;
use identity_iota::core::ToJson;
use kyber_rs::sign::eddsa;
use logging::NodeSignatureLog;

use states::dkg;

use crate::{
    api::requests::{
        messages::{Execution, InputUri, OutputUri, StorageLocalUri, StorageUri},
        GenericRequest,
    },
    net::network::Network,
};

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand)]
enum Action {
    Node(NodeArgs),
    Request(RequestArgs),
    Send(SendArgs),
    NewCommittee(NewCommitteeArgs),
    Verify(VerifyArgs),
    VerifyLog(VerifyLogArgs),
}

#[derive(Parser)]
struct VerifyLogArgs {
    #[arg(required = true, long = "log", help = "response from a dora committee")]
    log: NodeSignatureLog,
}

#[derive(Parser)]
struct SendArgs {
    #[arg(required = true, long = "message", help = "message to send")]
    message: String,

    #[arg(
        long = "index",
        help = "index of the message",
        default_value = "dora_input_message"
    )]
    index: String,

    #[arg(long = "network", default_value = "iota-main")]
    network: String,
}

#[derive(Parser)]
struct VerifyArgs {
    #[arg(required = true, long = "committee-log", help = "dora committee log")]
    committee_log: CommitteeLog,
}

#[derive(Parser)]
struct RequestArgs {
    #[arg(default_value = "", long, help = "input uri")]
    input_uri: String,

    #[arg(long, help = "storage id", default_value = None)]
    storage_id: Option<String>,

    #[arg(long = "committee-index", long, help = "index")]
    committee_index: String,

    #[arg(long = "network", default_value = "iota-main")]
    network: String,
}

#[derive(Parser)]
struct NewCommitteeArgs {
    #[arg(
        long = "governor_index",
        default_value = "dora-governor-test",
        long,
        help = "index"
    )]
    governor_index: String,

    #[arg(long, help = "node DIDs")]
    nodes: Option<String>,

    #[arg(long = "network", default_value = "iota-main")]
    network: String,
}

fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();

    match args.action {
        Action::Node(args) => run_node(args)?,
        Action::Request(args) => send_request(args)?,
        Action::NewCommittee(args) => new_committee(args)?,
        Action::Verify(args) => verify(args)?,
        Action::VerifyLog(args) => verify_log(args)?,
        Action::Send(args) => send_message(args)?,
    }

    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let mut response = args.committee_log;
    let committee_did_url = response.committee_did.clone();

    println!("Retrieving committee's public key from DID document");
    let public_key = resolve_document(committee_did_url, None)?.public_key()?;
    println!("Public key retrieved");
    println!("Performing signature validation");

    if let Some(signature_hex) = response.signature_hex.clone() {
        response.signature_hex = None;
        eddsa::verify(
            &public_key,
            &response.to_jcs()?,
            &hex::decode(signature_hex)?,
        )
        .map_err(|_| anyhow::Error::msg("Signature is not valid"))?;
        println!("Signature is valid")
    } else {
        bail!("Missing signature")
    }

    Ok(())
}

fn verify_log(args: VerifyLogArgs) -> Result<()> {
    let mut log = args.log;
    let did_url = log.sender_did.clone();

    println!("Retrieving node's public key from DID document");
    let public_key = resolve_document(did_url, None)?.public_key()?;
    println!("Public key retrieved");
    println!("Performing signature validation");

    if let Some(signature_hex) = log.signature_hex.clone() {
        log.signature_hex = None;
        eddsa::verify(&public_key, &log.to_bytes()?, &hex::decode(signature_hex)?)
            .map_err(|_| anyhow::Error::msg("Signature is not valid"))?;
        println!("Signature is valid")
    } else {
        bail!("Missing signature")
    }

    Ok(())
}

fn send_request(args: RequestArgs) -> Result<()> {
    let net =
        Network::from_str(&args.network).map_err(|_| anyhow::Error::msg("invalid network"))?;
    let mut storage_id = StorageUri::None;
    if let Some(id) = args.storage_id {
        storage_id = StorageUri::Storage(StorageLocalUri(id));
    }
    let request = GenericRequest {
        input_uri: InputUri::from_str(&args.input_uri).unwrap(),
        output_uri: OutputUri::None,
        execution: Execution::None,
        signature: false,
        storage_uri: storage_id,
    };
    let request = serde_json::to_vec(&request)?;

    let publisher = Publisher::new(
        net.try_into()
            .map_err(|_| anyhow::Error::msg("invalid network"))?,
        None,
    )?;
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(publisher.publish(&request, Some(args.committee_index)))?;
    println!("{result}");
    Ok(())
}

fn new_committee(args: NewCommitteeArgs) -> Result<()> {
    let net =
        Network::from_str(&args.network).map_err(|_| anyhow::Error::msg("invalid network"))?;
    let mut nodes = match args.nodes {
        Some(n) => n,
        None => return Err(anyhow::Error::msg("Missing node dids")),
    };

    if let Network::IotaNetwork(n) = net.clone() {
        match n {
            identity_iota::iota_core::Network::Mainnet => {
                nodes = nodes
                    .split(',')
                    .map(|d| format!("\"did:iota:{d}\""))
                    .collect::<Vec<String>>()
                    .join(",");
            }
            identity_iota::iota_core::Network::Devnet => {
                nodes = nodes
                    .split(',')
                    .map(|d| format!("\"did:iota:dev:{d}\""))
                    .collect::<Vec<String>>()
                    .join(",");
            }
            _ => panic!("invalid network"),
        }
    }

    let request = format!("{{\"nodes\": [{nodes}]}}").as_bytes().to_owned();

    let publisher = Publisher::new(
        net.try_into()
            .map_err(|_| anyhow::Error::msg("invalid network"))?,
        None,
    )?;
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(publisher.publish(&request, Some(args.governor_index)))?;
    println!("{result}");
    Ok(())
}

fn send_message(args: SendArgs) -> Result<()> {
    let net =
        Network::from_str(&args.network).map_err(|_| anyhow::Error::msg("invalid network"))?;
    let message = args.message.as_bytes().to_owned();

    let publisher = Publisher::new(
        net.try_into()
            .map_err(|_| anyhow::Error::msg("invalid network"))?,
        None,
    )?;
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(publisher.publish(&message, Some(args.index)))?;
    println!("{result}");
    Ok(())
}
