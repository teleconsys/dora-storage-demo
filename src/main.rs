extern crate log;
extern crate pretty_env_logger;

mod api;
mod demo;
mod did;
mod net;
mod pkg;
mod states;

use std::{
    fmt::Display,
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender},
        Arc,
    },
    time::Duration,
};

use actix_web::{App, HttpServer};
use anyhow::Result;

use api::routes::StoreData;

use clap::Parser;
use demo::run::{run_node, NodeArgs};
use kyber_rs::{group::edwards25519::SuiteEd25519, util::key::new_key_pair};
use net::host::Host;
use serde::{de::DeserializeOwned, Serialize};
use states::dkg;

#[derive(Parser)]
struct ApiArgs {}

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
    let sr = actix_web::rt::System::new();
    sr.block_on(
        HttpServer::new(|| {
            App::new()
                .service(api::routes::store)
                .app_data(actix_web::web::Data::new(StoreData {
                    dkg_initial_state: dkg::Initializing::new(
                        new_key_pair(&SuiteEd25519::new_blake3_sha256_ed25519()).unwrap(),
                        3,
                    ),
                }))
        })
        .bind((Ipv4Addr::LOCALHOST, 8080))?
        .run(),
    )?;
    Ok(())
}
