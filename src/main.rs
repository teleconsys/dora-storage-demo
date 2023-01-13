extern crate log;
extern crate pretty_env_logger;

mod broadcast;
mod did;
mod dkg;
mod feed;
mod fsm;
mod host;
mod node;
mod pkg;
mod sign;
mod strg;

use std::{
    fmt::Display,
    io::{self, Read, Write},
    iter::repeat_with,
    net::{
        Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
        UdpSocket, IpAddr,
    },
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use anyhow::{Error, Result};

use broadcast::LocalBroadcast;

use clap::{Arg, Args, Parser};
use host::Host;
use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    sign::eddsa,
    util::key::new_key_pair,
};
use node::Node;
use serde::{de::DeserializeOwned, Serialize};
use sign::Signature;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[group()]
struct NodeArgs {
    /// Hosts to connect to
    #[arg(required = true, value_name = "HOST:PORT")]
    #[command()]
    hosts: Vec<Host>,

    #[arg(required = true, short, long)]
    port: u16,

    #[arg(required = true, short, long)]
    storage: String,

    #[arg(required = true, short, long)]
    ip: String
}

struct ListenRelay<T> {
    output: Sender<T>,
    ip: String,
    port: u16,
    is_closed: Arc<AtomicBool>,
}

impl<T: DeserializeOwned + Display> ListenRelay<T> {
    pub fn new(ip: String, port: u16, output: Sender<T>, is_closed: Arc<AtomicBool>) -> Self {
        Self {
            output,
            ip,
            port,
            is_closed,
        }
    }

    pub fn listen(&self) -> Result<()> {
        let listener =
            match TcpListener::bind(SocketAddr::new(IpAddr::from_str(&self.ip)?, self.port)) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("Could not listen on port {}: {}", self.port, e);
                    return Err(e.into());
                }
            };

        log::info!("Listeninig at {}", listener.local_addr()?);
        listener.set_nonblocking(true)?;
        for stream in listener.incoming() {
            if self.is_closed.load(Ordering::SeqCst) {
                return Ok(());
            }
            match stream {
                Ok(stream) => self.handle_stream(stream)?,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    log::error!("Could not get incoming stream: {}", e);
                    return Err(e.into());
                }
            }
        }

        Ok(())
    }

    fn handle_stream(&self, mut stream: TcpStream) -> Result<()> {
        log::info!("Receiving message from {}", &stream.peer_addr()?);
        let mut buf = vec![];
        stream.read_to_end(&mut buf)?;
        let message = serde_json::from_slice(&buf)?;
        log::trace!("Message received: {}", &message);
        let res = self.output.send(message);
        if let Err(e) = res {
            log::error!("Could not relay message: {}", e);
        }
        Ok(())
    }
}

struct BroadcastRelay<T> {
    input: Receiver<T>,
    destinations: Vec<SocketAddr>,
}

impl<T: Serialize + Display> BroadcastRelay<T> {
    pub fn new(input: Receiver<T>, destinations: Vec<SocketAddr>) -> Self {
        Self {
            input,
            destinations,
        }
    }

    pub fn broadcast(&self) -> Result<()> {
        std::thread::sleep(Duration::from_secs(3));

        for message in &self.input {
            log::info!("Relaying message: {}", message);
            let serialized = serde_json::to_string(&message)?;

            for destination in &self.destinations {
                log::trace!("Sending to peer {}", destination);
                match TcpStream::connect(destination) {
                    Ok(mut socket) => {
                        log::info!("Relaying message to {}", socket.peer_addr()?);
                        socket.write_all(serialized.as_bytes())?;
                    }
                    Err(e) => {
                        log::error!("Could not connect to destination {}: {}", destination, e);
                    }
                }
            }
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = NodeArgs::parse();

    print!("Connecting to hosts:");
    args.hosts.iter().for_each(|h| print!(" {}", h));
    println!();

    println!("Listening on port {}", args.port);

    let suite = SuiteEd25519::new_blake3_sha256_ed25519();
    let keypair = new_key_pair(&suite)?;

    let is_completed = Arc::new(AtomicBool::new(false));

    let (dkg_input_channel_sender, dkg_input_channel) = mpsc::channel();
    let (dkg_output_channel, dkg_input_channel_receiver) = mpsc::channel();

    let dkg_listen_relay =
        ListenRelay::new(args.ip.clone(), args.port, dkg_input_channel_sender, is_completed.clone());
    let dkg_broadcast_relay = BroadcastRelay::new(
        dkg_input_channel_receiver,
        args.hosts.iter().map(Into::into).collect(),
    );

    let dkg_listen_relay_handle = thread::spawn(move || dkg_listen_relay.listen());
    let dkg_broadcast_relay_handle = thread::spawn(move || dkg_broadcast_relay.broadcast());

    let (sign_input_channel_sender, sign_input_channel) = mpsc::channel();
    let (sign_output_channel, sign_input_channel_receiver) = mpsc::channel();

    let sign_listen_relay = ListenRelay::new(
        args.ip,
        args.port - 1000,
        sign_input_channel_sender,
        is_completed.clone(),
    );
    let sign_broadcast_relay = BroadcastRelay::new(
        sign_input_channel_receiver,
        args.hosts
            .into_iter()
            .map(|h| h.with_port(h.port() - 1000))
            .map(Into::into)
            .collect(),
    );

    let sign_listen_relay_handle = thread::spawn(move || sign_listen_relay.listen());
    let sign_broadcast_relay_handle = thread::spawn(move || sign_broadcast_relay.broadcast());

    let node = Node::new(
        keypair,
        dkg_input_channel,
        dkg_output_channel,
        sign_input_channel,
        sign_output_channel,
        args.port as usize,
    );

    let (signature, public_key) = node.run(args.storage, 3)?;

    is_completed.store(true, Ordering::SeqCst);

    dkg_broadcast_relay_handle.join().unwrap()?;
    dkg_listen_relay_handle.join().unwrap()?;
    sign_broadcast_relay_handle.join().unwrap()?;
    sign_listen_relay_handle.join().unwrap()?;

    //println!("Public key: {:?}", public_key);
    //println!("Signature: {}", signature);

    Ok(())
}

fn run_demo() -> Result<(), anyhow::Error> {
    let num_nodes = 10;
    let message = "Hello, world!".as_bytes();

    let suite = &SuiteEd25519::new_blake3_sha256_ed25519();
    let keypairs = repeat_with(|| new_key_pair(suite)).flatten();

    let mut dkg_broadcast = LocalBroadcast::new();
    let mut sign_broadcast = LocalBroadcast::new();

    let nodes: Vec<Node> = keypairs
        .into_iter()
        .enumerate()
        .map(|(i, keypair)| Node::new_local(keypair, i, &mut dkg_broadcast, &mut sign_broadcast))
        .take(num_nodes)
        .collect();

    let sign_broadcast_handle = sign_broadcast.start();
    let dkg_broadcast_handle = dkg_broadcast.start();

    let outputs: Vec<(Signature, Point)> = nodes
        .into_iter()
        .map(|n| thread::spawn(move || n.run("message".to_owned(), num_nodes)))
        .collect::<Vec<JoinHandle<_>>>()
        .into_iter()
        .map(JoinHandle::join)
        .map(Result::unwrap)
        .collect::<Result<_, _>>()?;

    for (signature, dist_public_key) in outputs {
        println!("Signature: {}", signature);

        let is_valid = eddsa::verify(&dist_public_key, message, (&signature).into()).is_ok();
        println!("Valid: {}", is_valid)
    }

    dkg_broadcast_handle.join().unwrap();
    sign_broadcast_handle.join().unwrap();

    Ok(())
}
