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
use anyhow::{Result, bail};

use api::routes::{AppData, request::GenericResponse};

use clap::Parser;
use demo::{
    run::{run_node, NodeArgs},
    run_iota::{self, IotaNodeArgs},
};

use did::resolve_document;
use dlt::iota::{client::iota_client, Publisher, resolve_did};
use identity_iota::{iota_core::{Network, IotaDID}, core::ToJson};
use kyber_rs::sign::eddsa;
use net::host::Host;
use s3::request;
use states::dkg;

use crate::api::routes::{
    request::{
        DoraLocalUri, Execution, InputUri, IotaIndexUri, IotaMessageUri, OutputUri, StorageUri,
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
}

#[derive(Parser)]
struct VerifyArgs {
    #[arg(required = true, long = "committee-did-url", help = "did url of the committee")]
    committee_did_url: String,

    #[arg(required = true, long = "dora-response", help = "response from a dora committee")]
    dora_response: GenericResponse,   
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

    #[arg(long = "governor-index", default_value = "dora-governor-test", long, help = "index")]
    governor_index: String,

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
    Connect,
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
            "connect" => Ok(ApiAction::Connect),
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
        Action::Verify(args) => (),
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
                storage_uri: StorageUri::Dora(DoraLocalUri(args.message_id)),
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
                input: InputUri::Local(DoraLocalUri(args.message_id)),
                output: OutputUri::None,
                execution: Execution::None,
                signature: false,
                store: StorageUri::None,
            };
            serde_json::to_vec(&request)?
        }
        ApiAction::GenericStore => {
            let request = GenericRequest {
                input: InputUri::Iota(IotaMessageUri(args.message_id.clone())),
                output: OutputUri::None,
                execution: Execution::None,
                signature: false,
                store: StorageUri::Dora(DoraLocalUri(args.message_id)),
            };
            serde_json::to_vec(&request)?
        }
        ApiAction::Generic => {
            let mut storage_id = StorageUri::None;
            if let Some(id) = args.storage_id {
                storage_id = StorageUri::Dora(DoraLocalUri(id));
            }
            let request = GenericRequest {
                input: InputUri::from_str(&args.input_uri).unwrap(),
                output: OutputUri::None,
                execution: Execution::None,
                signature: false,
                store: storage_id,
            };
            serde_json::to_vec(&request)?
        }
        ApiAction::Connect => {
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
    let result = rt.block_on(publisher.publish(&request, Some(args.governor_index)))?;
    println!("{}", result);
    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let public_key = resolve_document(args.committee_did_url, None)?.public_key()?;

    let mut response = args.dora_response;
    if let Some(signature_hex) = response.signature_hex.clone() {
        response.signature_hex = None;    
        eddsa::verify(&public_key, &response.to_jcs()?, &hex::decode(signature_hex)?)?;
        println!("Signature is valid")
    } else {
        bail!("Missing signature")
    }

    Ok(())
}
