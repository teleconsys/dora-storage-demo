use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

use clap::Parser;
use kyber_rs::{
    encoding::BinaryMarshaler, group::edwards25519::SuiteEd25519, sign::eddsa::EdDSA,
    util::key::new_key_pair,
};

use crate::{
    demo::node::Node,
    did::new_document,
    net::{
        host::Host,
        relay::{BroadcastRelay, ListenRelay},
    },
    store::new_storage,
};
use anyhow::Result;

#[derive(Parser)]
#[command(author, version, about = "node", long_about = None)]
#[group()]
pub struct NodeArgs {
    /// Hosts to connect to
    #[arg(required = true, value_name = "HOST:PORT")]
    #[command()]
    peers: Vec<Host>,

    #[arg(required = true, long)]
    host: Host,

    #[arg(short, long, default_value = None)]
    storage: Option<String>,

    #[arg(long = "storage-endpoint", default_value = None)]
    storage_endpoint: Option<String>,

    #[arg(long = "storage-access-key", default_value = None)]
    storage_access_key: Option<String>,

    #[arg(long = "storage-secret-key", default_value = None)]
    storage_secret_key: Option<String>,

    #[arg(long = "did-network", default_value = None)]
    did_network: Option<String>,

    #[arg(long = "signature-sleep-time", default_value = "5")]
    signature_sleep_time: u64,
}

pub fn run_node(args: NodeArgs) -> Result<()> {
    let mut storage = None;
    if let Some(strg) = args.storage {
        println!("Setting up storage... ");
        storage = Some(new_storage(
            &strg,
            args.storage_access_key,
            args.storage_secret_key,
            args.storage_endpoint,
        )?);
        println!("OK");

        println!("Checking storage health... ");
        storage.clone().unwrap().health_check()?;
        println!("OK");
    }

    println!("Connecting to hosts:");
    args.peers.iter().for_each(|h| print!(" {}", h));

    println!("Listening on port {}", args.host.port());

    let suite = SuiteEd25519::new_blake3_sha256_ed25519();
    let keypair = new_key_pair(&suite)?;

    let is_completed = Arc::new(AtomicBool::new(false));

    let (dkg_input_channel_sender, dkg_input_channel) = mpsc::channel();
    let (dkg_output_channel, dkg_output_channel_receiver) = mpsc::channel();

    let dkg_listen_relay = ListenRelay::new(
        args.host.clone(),
        dkg_input_channel_sender,
        is_completed.clone(),
    );
    let mut dkg_broadcast_relay = BroadcastRelay::new(
        dkg_output_channel_receiver,
        args.peers.iter().map(Into::into).collect(),
    );

    let dkg_listen_relay_handle = thread::spawn(move || dkg_listen_relay.listen());
    let dkg_broadcast_relay_handle = thread::spawn(move || dkg_broadcast_relay.broadcast());

    let (sign_input_channel_sender, sign_input_channel) = mpsc::channel();
    let (sign_output_channel, sign_input_channel_receiver) = mpsc::channel();

    let sign_listen_relay = ListenRelay::new(
        args.host.with_port(args.host.port() - 1000),
        sign_input_channel_sender.clone(),
        is_completed.clone(),
    );
    let mut sign_broadcast_relay = BroadcastRelay::new(
        sign_input_channel_receiver,
        args.peers
            .into_iter()
            .map(|h| h.with_port(h.port() - 1000))
            .map(Into::into)
            .collect(),
    );

    let sign_listen_relay_handle = thread::spawn(move || sign_listen_relay.listen());
    let sign_broadcast_relay_handle = thread::spawn(move || sign_broadcast_relay.broadcast());

    let node = Node::new(
        keypair.clone(),
        dkg_input_channel,
        dkg_output_channel,
        sign_input_channel,
        sign_output_channel,
        args.host.port() as usize,
    );

    let mut did_url = None;
    if let Some(network) = args.did_network.clone() {
        let eddsa = EdDSA::from(keypair);
        let document = new_document(&eddsa.public.marshal_binary()?, &network, None, None)?;
        let signature = eddsa.sign(&document.to_bytes()?)?;
        did_url = Some(document.did_url());
        document.publish(&signature)?;
        log::info!(
            "node's DID has been published, DID URL: {}",
            did_url.clone().unwrap()
        );
    }

    let (_signature, _public_key) = node.run(
        storage,
        args.did_network,
        did_url,
        3,
        sign_input_channel_sender,
        args.signature_sleep_time,
    )?;

    is_completed.store(true, Ordering::SeqCst);

    // dkg_broadcast_relay_handle.join().unwrap()?;
    // dkg_listen_relay_handle.join().unwrap()?;
    // sign_broadcast_relay_handle.join().unwrap()?;
    // sign_listen_relay_handle.join().unwrap()?;

    //println!("Public key: {:?}", public_key);
    //println!("Signature: {}", signature);

    Ok(())
}
