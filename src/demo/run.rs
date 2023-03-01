use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
};

use clap::Parser;
use futures::executor::block_on;
use iota_client::{
    block::{
        address::{Address, Ed25519Address},
        output::Output,
    },
    crypto::{
        hashes::{blake2b::Blake2b256, Digest},
        signatures::ed25519::PUBLIC_KEY_LENGTH,
    },
    node_api::indexer::query_parameters::QueryParameter,
    Client,
};
use kyber_rs::{
    encoding::BinaryMarshaler,
    group::edwards25519::SuiteEd25519,
    sign::eddsa::EdDSA,
    util::key::{new_key_pair, Pair},
};
use serde::{Deserialize, Serialize};

use crate::{
    demo::{
        node::{Node, NodeChannels, NodeNetworkParams, NodeProtocolParams},
        NodeState, SaveData,
    },
    did::new_document,
    dlt::iota::Listener,
    net::relay::{IotaBroadcastRelay, IotaListenRelay},
    store::new_storage,
};
use anyhow::{Context, Result};

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

    #[arg(
        long = "node-url",
        default_value = "https://api.testnet.shimmer.network"
    )]
    node_url: String,

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

    let mut save_data = SaveData::load_or_create();

    let keypair = get_keypair(&mut save_data, suite)?;

    let address = get_address(&keypair.public.marshal_binary()?);
    let client = Client::builder().with_node(&args.node_url)?.finish()?;

    let rt = tokio::runtime::Runtime::new()?;
    let balance = rt.block_on(get_address_balance(&client, &address))?;
    if balance < 10000000 {
        rt.block_on(request_faucet_funds(
            &client,
            address,
            "https://faucet.testnet.shimmer.network/api/enqueue",
        ))?
    }

    let did_url = get_did(&keypair, &args.node_url, &mut save_data)?;

    log::info!("Node DID: {}", did_url);

    let is_completed = Arc::new(AtomicBool::new(false));

    let mut all_dids = match save_data.committee_state {
        Some(cs) => cs.did_urls,
        None => {
            listen_governor_instructions(args.governor, did_url.clone(), args.node_url.clone())?
        }
    };

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
        args.node_url.clone(),
    );
    let mut dkg_broadcast_relay = IotaBroadcastRelay::new(
        own_idx.clone(),
        dkg_output_channel_receiver,
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
        args.node_url.clone(),
    );
    let mut sign_broadcast_relay =
        IotaBroadcastRelay::new(own_idx, sign_input_channel_receiver, args.node_url.clone())?;

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
        node_url: args.node_url,
    };

    let protocol_params = NodeProtocolParams {
        own_did_url: did_url,
        did_urls: peers_dids,
        num_participants: all_dids.len(),
        time_resolution: args.time_resolution,
        signature_sleep_time: args.signature_sleep_time,
    };

    let save_data = SaveData::load_or_create();
    let node =
        Node::new(keypair, channels, network_params, protocol_params, id).with_save_data(save_data);

    node.run(storage)?;

    is_completed.store(true, Ordering::SeqCst);

    dkg_broadcast_relay_handle.join().unwrap()?;
    sign_broadcast_relay_handle.join().unwrap()?;
    dkg_listen_relay_handle.join().unwrap()?;
    sign_listen_relay_handle.join().unwrap()?;

    Ok(())
}

fn get_keypair(
    save_data: &mut SaveData,
    suite: SuiteEd25519,
) -> Result<Pair<kyber_rs::group::edwards25519::Point>, anyhow::Error> {
    let keypair = match save_data.node_state {
        Some(ref node_state) => {
            log::info!("Loaded keypair");
            Pair {
                private: node_state.private_key,
                public: node_state.public_key,
            }
        }
        None => {
            let pair = new_key_pair(&suite)?;
            log::info!("Created new keypair");
            save_data.node_state = Some(NodeState {
                private_key: pair.private,
                public_key: pair.public,
                did_document: None,
            });
            pair
        }
    };
    if let Err(e) = &save_data.save() {
        log::warn!("{}", e);
    };
    Ok(keypair)
}

fn get_did(
    keypair: &Pair<kyber_rs::group::edwards25519::Point>,
    node_url: &str,
    save_data: &mut SaveData,
) -> Result<String, anyhow::Error> {
    let eddsa = EdDSA::from(keypair.clone());
    let did = match &mut save_data.node_state {
        Some(NodeState {
            did_document: Some(document),
            ..
        }) => {
            log::info!("Using existing node DID");
            document.did()
        }
        _ => {
            log::info!("creating node's DID document",);
            let mut document =
                new_document(&eddsa.public.marshal_binary()?, None, None, node_url, false)?;
            document.sign(keypair.clone(), node_url)?;

            document.publish(node_url)?;
            let did = document.did();
            log::info!("node's DID document has been published: {}", did);

            if let Some(ref mut node_state) = save_data.node_state {
                node_state.did_document = Some(document);
            }
            if let Err(e) = save_data.save() {
                log::warn!("{}", e);
            }
            did
        }
    };
    Ok(did)
}

#[derive(Clone, Serialize, Deserialize)]
struct DkgInit {
    nodes: Vec<String>,
}

fn listen_governor_instructions(
    governor_index: String,
    own_did: String,
    node_url: String,
) -> Result<Vec<String>> {
    let mut init_listener = Listener::new(&node_url)?;
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

/// Requests funds from the faucet for the given `address`.
async fn request_faucet_funds(
    client: &Client,
    address: Address,
    faucet_endpoint: &str,
) -> anyhow::Result<()> {
    let address_bech32 = address.to_bech32(client.get_bech32_hrp().await?);

    iota_client::request_funds_from_faucet(faucet_endpoint, &address_bech32).await?;

    tokio::time::timeout(std::time::Duration::from_secs(300), async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let balance = get_address_balance(client, &address)
                .await
                .context("failed to get address balance")?;
            if balance > 0 {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("maximum timeout exceeded")??;

    Ok(())
}

/// Returns the balance of the given Bech32-encoded `address`.
async fn get_address_balance(client: &Client, address: &Address) -> anyhow::Result<u64> {
    let address_bech32 = address.to_bech32(client.get_bech32_hrp().await?);
    let output_ids = client
        .basic_output_ids(vec![
            QueryParameter::Address(address_bech32.to_owned()),
            QueryParameter::HasExpiration(false),
            QueryParameter::HasTimelock(false),
            QueryParameter::HasStorageDepositReturn(false),
        ])
        .await?;

    let outputs_responses = client.get_outputs(output_ids).await?;

    let mut total_amount = 0;
    for output_response in outputs_responses {
        let output =
            Output::try_from_dto(&output_response.output, client.get_token_supply().await?)?;
        total_amount += output.amount();
    }

    Ok(total_amount)
}

/// Get an address
pub fn get_address(public_key: &[u8]) -> Address {
    Address::Ed25519(Ed25519Address::new(Blake2b256::digest(public_key).into()))
    // Hash the public key to get the address.
}
