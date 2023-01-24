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
    sync::{atomic::AtomicBool, Arc, Mutex},
    thread,
};

use actix_web::{App, HttpServer};
use anyhow::Result;

use api::routes::AppData;

use clap::Parser;
use demo::{
    run::{run_node, NodeArgs},
    run_iota::{IotaNodeArgs, self},
};

use net::host::Host;
use states::dkg;

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
}

fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();

    match args.action {
        Action::Node(args) => run_node(args)?,
        Action::Api(args) => run_api(args)?,
        Action::IotaNode(args) => run_iota::run_node(args)?,
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
