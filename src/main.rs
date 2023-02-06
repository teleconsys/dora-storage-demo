extern crate log;
extern crate pretty_env_logger;

mod api;
mod demo;
mod did;
mod dlt;
mod net;
mod states;
mod store;

use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{atomic::AtomicBool, Arc, Mutex},
    thread,
};

use actix_web::{App, HttpServer};
use anyhow::{bail, Result};

use api::routes::{request::CommitteeLog, AppData};

use clap::Parser;
use demo::{
    node::NodeSignatureLog,
    run::{run_node, NodeArgs},
    run_iota::{self, IotaNodeArgs},
};

use did::resolve_document;
use dlt::iota::{client::iota_client, resolve_did, Publisher};
use identity_iota::{
    core::ToJson,
    iota_core::{IotaDID, Network},
};
use kyber_rs::sign::eddsa;
use net::host::Host;
use s3::request;
use states::dkg;

use crate::api::routes::{
    request::{
        Execution, InputUri, IotaIndexUri, IotaMessageUri, OutputUri, StorageLocalUri, StorageUri,
    },
    GenericRequest, NodeMessage,
};

#[derive(Parser)]
struct ApiArgs {
    #[arg(required = true, value_name = "HOST:PORT", help = "nodes in committee")]
    #[command()]
    nodes: Vec<Host>,

    #[arg(required = true, long, help = "inbound host")]
    host: Host,
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand)]
enum Action {
    Node(NodeArgs),
    Api(ApiArgs),
    IotaNode(IotaNodeArgs),
    ApiSend(ApiSendArgs),
    Verify(VerifyArgs),
    VerifyLog(VerifyLogArgs),
}

#[derive(Parser)]
struct VerifyLogArgs {
    #[arg(required = true, long = "log", help = "response from a dora committee")]
    log: NodeSignatureLog,
}

#[derive(Parser)]
struct VerifyArgs {
    #[arg(required = true, long = "committee-log", help = "dora committee log")]
    committee_log: CommitteeLog,
}

#[derive(Parser)]
struct ApiSendArgs {
    #[arg(required = true, long, help = "action")]
    action: ApiAction,

    #[arg(long, help = "message id", default_value = "")]
    message_id: String,

    #[arg(default_value = "", long, help = "input uri")]
    input_uri: String,

    #[arg(long, help = "storage id", default_value = None)]
    storage_id: Option<String>,

    #[arg(
        long = "committee-index",
        default_value = "dora-governor-test",
        long,
        help = "index"
    )]
    committee_index: String,

    #[arg(long, help = "node DIDs")]
    nodes: Option<String>,
}

#[derive(Clone)]
enum ApiAction {
    Store,
    Get,
    Delete,
    Generic,
    GenericGet,
    GenericStore,
    NewCommittee,
}

impl FromStr for ApiAction {
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "store" => Ok(ApiAction::Store),
            "get" => Ok(ApiAction::Get),
            "delete" => Ok(ApiAction::Delete),
            "generic" => Ok(ApiAction::Generic),
            "generic-get" => Ok(ApiAction::GenericGet),
            "generic-store" => Ok(ApiAction::GenericStore),
            "new-committee" => Ok(ApiAction::NewCommittee),
            _ => Err("not a valid action".to_owned()),
        }
    }

    type Err = String;
}

fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();

    match args.action {
        Action::Node(args) => run_node(args)?,
        Action::Api(args) => run_api(args)?,
        Action::IotaNode(args) => run_iota::run_node(args)?,
        Action::ApiSend(args) => api_send(args)?,
        Action::Verify(args) => verify(args)?,
        Action::VerifyLog(args) => verify_log(args)?,
    }

    Ok(())
}

fn run_api(args: ApiArgs) -> Result<()> {
    let is_finished = Arc::new(AtomicBool::new(false));

    // let (inbound_sender, inbound_receiver) = std::sync::mpsc::channel();
    let (inbound_sender, _) = tokio::sync::broadcast::channel(1024);
    let (outbound_sender, outbound_receiver) = tokio::sync::broadcast::channel(1024);

    let peers = args.nodes.into_iter().map(|h| h.into()).collect();

    let mut broadcast = net::relay::BroadcastRelay::new(outbound_receiver, peers);
    let listener =
        net::relay::ListenRelay::new(args.host.clone(), inbound_sender.clone(), is_finished);

    let broadcast_handler = thread::spawn(move || broadcast.broadcast().unwrap());
    let listener_handler = thread::spawn(move || listener.listen().unwrap());

    let is = Arc::new(inbound_sender);

    let sr = actix_web::rt::System::new();
    sr.block_on(
        HttpServer::new(move || {
            let app_data = actix_web::web::Data::new(AppData {
                nodes_sender: outbound_sender.clone(),
                nodes_receiver: Mutex::new(is.subscribe()),
            });
            App::new()
                .service(api::routes::save::save)
                .app_data(app_data)
        })
        .bind(SocketAddr::from(args.host.with_port(8080)))?
        .run(),
    )?;

    broadcast_handler.join().unwrap();
    listener_handler.join().unwrap();

    Ok(())
}

fn api_send(args: ApiSendArgs) -> Result<()> {
    let request = match args.action {
        ApiAction::Store => {
            let message_id = args.message_id.clone();
            let request = NodeMessage::StoreRequest(api::routes::save::StoreRequest {
                input: InputUri::Iota(IotaMessageUri(args.message_id.clone())),
                storage_uri: StorageUri::Storage(StorageLocalUri(args.message_id)),
            });
            serde_json::to_vec(&request)?
        }
        ApiAction::Get => {
            let request = NodeMessage::GetRequest(api::routes::get::GetRequest {
                input: InputUri::Iota(IotaMessageUri(args.message_id)),
            });
            serde_json::to_vec(&request)?
        }
        ApiAction::Delete => {
            let request = NodeMessage::DeleteRequest(api::routes::delete::DeleteRequest {
                message_id: args.message_id,
            });
            serde_json::to_vec(&request)?
        }
        ApiAction::GenericGet => {
            let request = GenericRequest {
                input_uri: InputUri::Local(StorageLocalUri(args.message_id)),
                output_uri: OutputUri::None,
                execution: Execution::None,
                signature: false,
                storage_uri: StorageUri::None,
            };
            serde_json::to_vec(&request)?
        }
        ApiAction::GenericStore => {
            let request = GenericRequest {
                input_uri: InputUri::Iota(IotaMessageUri(args.message_id.clone())),
                output_uri: OutputUri::None,
                execution: Execution::None,
                signature: false,
                storage_uri: StorageUri::Storage(StorageLocalUri(args.message_id)),
            };
            serde_json::to_vec(&request)?
        }
        ApiAction::Generic => {
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
            serde_json::to_vec(&request)?
        }
        ApiAction::NewCommittee => {
            let nodes = match args.nodes {
                Some(n) => n,
                None => return Err(anyhow::Error::msg("Missing node dids")),
            };

            let nodes = nodes
                .split(',')
                .map(|d| format!("\"did:iota:{}\"", d))
                .collect::<Vec<String>>()
                .join(",");

            format!("{{\"nodes\": [{}]}}", nodes).as_bytes().to_owned()
        }
    };
    let publisher = Publisher::new(Network::Mainnet, None)?;
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(publisher.publish(&request, Some(args.committee_index)))?;
    println!("{}", result);
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let mut response = args.committee_log;
    let committee_did_url = response.committee_did.clone();

    println!("Retreivieng committee's public key from DID document");
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

    println!("Retrievieng node's public key from DID document");
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
