extern crate log;
extern crate pretty_env_logger;

mod api;
mod demo;
mod did;
mod net;
mod pkg;
mod states;

use std::{
    net::Ipv4Addr,
    sync::{atomic::AtomicBool, Arc},
    thread,
};

use actix_web::{App, HttpServer};
use anyhow::Result;

use api::routes::AppData;

use clap::Parser;
use demo::run::{run_node, NodeArgs};

use net::host::Host;
use states::dkg;

#[derive(Parser)]
struct ApiArgs {
    #[arg(required = true, value_name = "HOST:PORT")]
    #[command()]
    hosts: Vec<Host>,
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
}

fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();

    match args.action {
        Action::Node(args) => run_node(args)?,
        Action::Api(args) => run_api(args)?,
    }

    Ok(())
}

fn run_api(args: ApiArgs) -> Result<()> {
    let is_finished = Arc::new(AtomicBool::new(false));

    // let (inbound_sender, inbound_receiver) = std::sync::mpsc::channel();
    let (inbound_sender, inbound_receiver) = tokio::sync::broadcast::channel(1024);
    let (outbound_sender, outbound_receiver) = tokio::sync::broadcast::channel(1024);

    let peers = args.hosts.into_iter().map(|h| h.into()).collect();

    let mut broadcast = net::relay::BroadcastRelay::new(outbound_receiver, peers);
    let listener = net::relay::ListenRelay::new(8000, inbound_sender.clone(), is_finished);

    let h = thread::spawn(move || broadcast.broadcast().unwrap());

    let is = Arc::new(inbound_sender);

    let sr = actix_web::rt::System::new();
    sr.block_on(
        HttpServer::new(move || {
            let app_data = actix_web::web::Data::new(AppData {
                nodes_sender: outbound_sender.clone(),
                nodes_receiver: is.subscribe(),
            });
            App::new()
                .service(api::routes::save::save)
                .app_data(app_data)
        })
        .bind((Ipv4Addr::LOCALHOST, 8080))?
        .run(),
    )?;

    h.join().unwrap();

    Ok(())
}
