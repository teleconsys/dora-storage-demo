use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

use identity_iota::iota_core::Network;

use clap::Parser;
use kyber_rs::{
    encoding::BinaryMarshaler, group::edwards25519::SuiteEd25519, sign::eddsa::EdDSA,
    util::key::new_key_pair,
};
use serde::{Deserialize, Serialize};

use crate::{
    demo::node::{Node, NodeChannels, NodeNetworkParams, NodeProtocolParams},
    did::new_document,
    dlt::iota::Listener,
    net::relay::{IotaBroadcastRelay, IotaListenRelay},
    store::new_storage,
};
use anyhow::Result;

#[derive(Parser)]
#[command(author, version, about = "node", long_about = None)]
#[group()]
pub struct NodeArgs {
    /// governor to connect to
    #[arg(short, long, required = true)]
    governor: String,

    #[arg(short, long, default_value = None)]
    storage: Option<String>,

    #[arg(long = "storage-endpoint", default_value = None)]
    storage_endpoint: Option<String>,

    #[arg(long = "storage-access-key", default_value = None)]
    storage_access_key: Option<String>,

    #[arg(long = "storage-secret-key", default_value = None)]
    storage_secret_key: Option<String>,

    #[arg(long = "node-url", default_value = None)]
    node_url: Option<String>,

    #[arg(long = "did-network", default_value = "iota-dev")]
    did_network: String,

    #[arg(short, long = "nodes-number", default_value = "3")]
    nodes_number: usize,

    #[arg(short, long = "time-resolution", default_value = "20")]
    time_resolution: usize,

    #[arg(long = "signature-sleep-time", default_value = "5")]
    signature_sleep_time: u64,
}

pub fn run_node(args: NodeArgs) -> Result<()> {
    let mut storage = None;
    if let Some(strg) = args.storage {
        storage = Some(new_storage(
            &strg,
            args.storage_access_key,
            args.storage_secret_key,
            args.storage_endpoint,
        )?);
        log::trace!("storage is set");

        storage.clone().unwrap().health_check()?;
        log::trace!("storage is healthy");
    }

    log::info!("generating node's keypair");
    let suite = SuiteEd25519::new_blake3_sha256_ed25519();
    let keypair = new_key_pair(&suite)?;

    let network = args.did_network.clone();
    let eddsa = EdDSA::from(keypair.clone());
    log::info!("creating node's DID document");
    let document = new_document(&eddsa.public.marshal_binary()?, &network, None, None)?;
    let signature = eddsa.sign(&document.to_bytes()?)?;

    let did_url = document.did_url();
    document.publish(&signature, args.node_url.clone())?;
    log::info!("node's DID document has been published: {}", did_url);

    let is_completed = Arc::new(AtomicBool::new(false));

    let mut all_dids = listen_governor_instructions(
        args.governor,
        did_url.clone(),
        network.clone(),
        args.node_url.clone(),
    )?;

    // get only peers dids
    let mut peers_dids = all_dids.clone();
    peers_dids.retain(|x| *x != did_url);

    // peers dids to indexes
    let mut peers_indexes = Vec::new();
    for peer in peers_dids.clone() {
        peers_indexes.push(peer.split(':').last().unwrap().to_string());
    }

    // own did to indexes
    let own_idx = did_url.split(':').last().unwrap().to_string();

    let (dkg_input_channel_sender, dkg_input_channel) = mpsc::channel();
    let (dkg_output_channel, dkg_output_channel_receiver) = mpsc::channel();

    let dkg_listen_relay = IotaListenRelay::new(
        dkg_input_channel_sender,
        is_completed.clone(),
        peers_indexes.clone(),
        args.did_network.clone(),
        args.node_url.clone(),
    );
    let mut dkg_broadcast_relay = IotaBroadcastRelay::new(
        own_idx.clone(),
        dkg_output_channel_receiver,
        args.did_network.clone(),
        args.node_url.clone(),
    )?;

    let dkg_listen_relay_handle = thread::spawn(move || dkg_listen_relay.listen());
    let dkg_broadcast_relay_handle = thread::spawn(move || dkg_broadcast_relay.broadcast());

    let (sign_input_channel_sender, sign_input_channel) = mpsc::channel();
    let (sign_output_channel, sign_input_channel_receiver) = mpsc::channel();

    let sign_listen_relay = IotaListenRelay::new(
        sign_input_channel_sender.clone(),
        is_completed.clone(),
        peers_indexes,
        args.did_network.clone(),
        args.node_url.clone(),
    );
    let mut sign_broadcast_relay = IotaBroadcastRelay::new(
        own_idx,
        sign_input_channel_receiver,
        args.did_network.clone(),
        args.node_url.clone(),
    )?;

    let sign_listen_relay_handle = thread::spawn(move || sign_listen_relay.listen());
    let sign_broadcast_relay_handle = thread::spawn(move || sign_broadcast_relay.broadcast());

    // get node's id in the committee
    all_dids.sort();
    let mut id = 0;
    for (i, did) in all_dids.iter().enumerate() {
        if did == &did_url {
            id = i + 1;
        }
    }

    let channels = NodeChannels {
        dkg_input_channel,
        sign_input_channel,
        dkg_output_channel,
        sign_output_channel,
        sign_input_channel_sender,
    };

    let network_params = NodeNetworkParams {
        network,
        node_url: args.node_url,
    };

    let protocol_params = NodeProtocolParams {
        own_did_url: did_url,
        did_urls: peers_dids,
        num_participants: args.nodes_number,
        time_resolution: args.time_resolution,
        signature_sleep_time: args.signature_sleep_time,
    };

    let node = Node::new(keypair, channels, network_params, protocol_params, id);

    let (_signature, _public_key) = node.run(storage)?;

    is_completed.store(true, Ordering::SeqCst);

    dkg_broadcast_relay_handle.join().unwrap()?;
    sign_broadcast_relay_handle.join().unwrap()?;
    dkg_listen_relay_handle.join().unwrap()?;
    sign_listen_relay_handle.join().unwrap()?;

    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
struct DkgInit {
    nodes: Vec<String>,
}

fn listen_governor_instructions(
    governor_index: String,
    own_did: String,
    network: String,
    node_url: Option<String>,
) -> Result<Vec<String>> {
    let net = match network.as_str() {
        "iota-main" => Network::Mainnet,
        "iota-dev" => Network::Devnet,
        _ => panic!("unsupported network"),
    };
    let mut init_listener = Listener::new(net, node_url)?;
    log::info!(
        "listening for instructions on governor index: {}",
        governor_index
    );
    let receiver = tokio::runtime::Runtime::new()?.block_on(init_listener.start(governor_index))?;
    loop {
        if let Some(data) = receiver.iter().next() {
            let mut deserializer = serde_json::Deserializer::from_slice(&data.0);
            if let Ok(message) = DkgInit::deserialize(&mut deserializer) {
                for node in message.nodes.iter() {
                    if own_did == *node {
                        log::info!(
                            "requested DKG from governor, committe's nodes: {:?}",
                            message.nodes
                        );
                        return Ok(message.nodes);
                    }
                }
            }
        }
    }
}
