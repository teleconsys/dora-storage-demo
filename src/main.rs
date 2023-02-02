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
use anyhow::Result;

use api::routes::AppData;

use clap::Parser;
use demo::{
    run::{run_node, NodeArgs},
    run_iota::{self, IotaNodeArgs},
};

use dlt::iota::{client::iota_client, Publisher};
use identity_iota::iota_core::Network;
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
}

#[derive(Parser)]
struct ApiSendArgs {
    #[arg(required = true, long, help = "action")]
    action: ApiAction,

    #[arg(required = true, long, help = "message id")]
    message_id: String,

    #[arg(required = true, long, help = "index")]
    index: String,
}

#[derive(Clone)]
enum ApiAction {
    Store,
    Get,
    Delete,
    GenericGet,
    GenericStore,
}

impl FromStr for ApiAction {
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "store" => Ok(ApiAction::Store),
            "get" => Ok(ApiAction::Get),
            "delete" => Ok(ApiAction::Delete),
            "generic-get" => Ok(ApiAction::GenericGet),
            "generic-store" => Ok(ApiAction::GenericStore),
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
    };
    let publisher = Publisher::new(Network::Mainnet)?;
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(publisher.publish(&request, Some(args.index)))?;
    println!("{}", result);
    Ok(())
}
