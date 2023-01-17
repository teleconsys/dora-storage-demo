use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

use clap::Parser;
use kyber_rs::{group::edwards25519::SuiteEd25519, util::key::new_key_pair};

use crate::{
    demo::node::Node,
    net::{
        host::Host,
        relay::{BroadcastRelay, ListenRelay},
    },
};
use anyhow::Result;

#[derive(Parser)]
#[command(author, version, about = "node", long_about = None)]
#[group()]
pub struct NodeArgs {
    /// Hosts to connect to
    #[arg(required = true, value_name = "HOST:PORT")]
    #[command()]
    hosts: Vec<Host>,

    #[arg(required = true, short, long)]
    port: u16,
}

pub fn run_node(args: NodeArgs) -> Result<()> {
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
        ListenRelay::new(args.port, dkg_input_channel_sender, is_completed.clone());
    let dkg_broadcast_relay = BroadcastRelay::new(
        dkg_input_channel_receiver,
        args.hosts.iter().map(Into::into).collect(),
    );

    let dkg_listen_relay_handle = thread::spawn(move || dkg_listen_relay.listen());
    let dkg_broadcast_relay_handle = thread::spawn(move || dkg_broadcast_relay.broadcast());

    let (sign_input_channel_sender, sign_input_channel) = mpsc::channel();
    let (sign_output_channel, sign_input_channel_receiver) = mpsc::channel();

    let sign_listen_relay = ListenRelay::new(
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

    let (signature, public_key) = node.run("Hello".into(), 3)?;

    is_completed.store(true, Ordering::SeqCst);

    dkg_broadcast_relay_handle.join().unwrap()?;
    dkg_listen_relay_handle.join().unwrap()?;
    sign_broadcast_relay_handle.join().unwrap()?;
    sign_listen_relay_handle.join().unwrap()?;

    println!("Public key: {:?}", public_key);
    println!("Signature: {}", signature);

    Ok(())
}
