use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender}, Arc,
    },
    thread,
};

use identity_iota::iota_core::Network;

use clap::Parser;
use kyber_rs::{
    encoding::BinaryMarshaler, group::edwards25519::SuiteEd25519, sign::eddsa::EdDSA,
    util::key::new_key_pair,
};
use serde::{Serialize, Deserialize};

use crate::{
    demo::node::Node,
    did::new_document,
    net::{
        relay::{IotaBroadcastRelay, IotaListenRelay},
    },
    store::new_storage, dlt::iota::Listener, states::feed::MessageWrapper,
};
use anyhow::Result;

#[derive(Clone, Serialize, Deserialize)]
struct DkgInit {
    nodes: Vec<String>
}

#[derive(Parser)]
#[command(author, version, about = "node", long_about = None)]
#[group()]
pub struct IotaNodeArgs {
    /// Hosts to connect to
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

    #[arg(long = "did-network", default_value = "iota-dev")]
    did_network: String,
}

pub fn run_node(args: IotaNodeArgs) -> Result<()> {
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

    let suite = SuiteEd25519::new_blake3_sha256_ed25519();
    let keypair = new_key_pair(&suite)?;

    let network = args.did_network.clone();
    let eddsa = EdDSA::from(keypair.clone());
    let document = new_document(&eddsa.public.marshal_binary()?, &network, None, None)?;
    let signature = eddsa.sign(&document.to_bytes()?)?;
    let did_url = document.did_url();
    document.publish(&signature)?;
    log::info!(
        "Node's DID has been published, DID URL: {}",
        did_url
    );

    let is_completed = Arc::new(AtomicBool::new(false));

    let peers = listen_governor_instructions(args.governor, did_url.clone(), network)?;
    let tmp: Vec<&str> = did_url.split(':').collect();
    let own_idx = tmp[tmp.len() -1].to_string();

    let (dkg_input_channel_sender, dkg_input_channel) = mpsc::channel();
    let (dkg_output_channel, dkg_output_channel_receiver) = mpsc::channel();

    let dkg_listen_relay = IotaListenRelay::new(
        dkg_input_channel_sender,
        is_completed.clone(),
        peers.clone(),
        args.did_network.clone()
    );
    let mut dkg_broadcast_relay =
        IotaBroadcastRelay::new(own_idx.clone(), dkg_output_channel_receiver, args.did_network.clone())?;

    let dkg_listen_relay_handle = thread::spawn(move || dkg_listen_relay.listen());
    let dkg_broadcast_relay_handle = thread::spawn(move || dkg_broadcast_relay.broadcast());

    let (sign_input_channel_sender, sign_input_channel) = mpsc::channel();
    let (sign_output_channel, sign_input_channel_receiver) = mpsc::channel();

    let sign_listen_relay =
        IotaListenRelay::new(sign_input_channel_sender, is_completed.clone(), peers, args.did_network.clone());
    let mut sign_broadcast_relay =
        IotaBroadcastRelay::new(own_idx, sign_input_channel_receiver, args.did_network.clone())?;

    let sign_listen_relay_handle = thread::spawn(move || sign_listen_relay.listen());
    let sign_broadcast_relay_handle = thread::spawn(move || sign_broadcast_relay.broadcast());


    let node = Node::new(
        keypair,
        dkg_input_channel,
        dkg_output_channel,
        sign_input_channel,
        sign_output_channel,
        *(did_url.as_bytes().last().unwrap()) as usize,
    );
    

    let (_signature, _public_key) = node.run(storage, Some(args.did_network), Some(did_url), 3)?;

    is_completed.store(true, Ordering::SeqCst);

    dkg_broadcast_relay_handle.join().unwrap()?;
    sign_broadcast_relay_handle.join().unwrap()?;
    dkg_listen_relay_handle.join().unwrap()?;
    sign_listen_relay_handle.join().unwrap()?;

    //println!("Public key: {:?}", public_key);
    //println!("Signature: {}", signature);

    Ok(())
}


fn listen_governor_instructions(governor_index: String, own_did: String, network: String) -> Result<Vec<String>> {
    let net = match network.as_str() {
        "iota-main" => Network::Mainnet,
        "iota-dev" => Network::Devnet,
        _ => panic!("unsupported network"), 
    };
    let tmp: Vec<&str> = own_did.split(':').collect();
    let own_idx = tmp[tmp.len() -1].to_string();
    let mut init_listener =  Listener::new(net)?;
    log::trace!("Listening on governor index");
    let receiver = tokio::runtime::Runtime::new()?.block_on(init_listener.start(governor_index))?;
    let mut b = false;
    let mut pos = 0;
    loop {
        if let Some(data) = receiver.iter().next() {
            let message: DkgInit = serde_json::from_slice(&data).unwrap();   
            for (i, node) in message.nodes.iter().enumerate() {
                if own_idx == *node {
                    b = true;
                    pos = i;
                }
            }
            if b {
                log::trace!("Requested DKG from governor");
                let mut tmp = message.nodes;
                tmp.remove(pos);
                return Ok(tmp)  
            }      
        }
    }
}
