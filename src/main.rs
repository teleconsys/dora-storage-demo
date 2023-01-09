extern crate log;
extern crate pretty_env_logger;

mod broadcast;
mod dkg;
mod feed;
mod fsm;
mod node;
mod sign;

use std::{
    iter::repeat_with,
    thread::{self, JoinHandle},
};

use anyhow::{Ok, Result};

use broadcast::LocalBroadcast;

use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    sign::eddsa,
    util::key::new_key_pair,
};
use node::Node;
use sign::Signature;

const NUM_NODES: usize = 10;

fn main() -> Result<()> {
    pretty_env_logger::init();
    let message = "Hello, world!".as_bytes();

    let suite = &SuiteEd25519::new_blake_sha256ed25519();
    let keypairs = repeat_with(|| new_key_pair(suite)).flatten();

    let mut dkg_broadcast = LocalBroadcast::new();
    let mut sign_broadcast = LocalBroadcast::new();

    let nodes: Vec<Node> = keypairs
        .into_iter()
        .enumerate()
        .map(|(i, keypair)| Node::new_local(keypair, i, &mut dkg_broadcast, &mut sign_broadcast))
        .take(NUM_NODES)
        .collect();

    let sign_broadcast_handle = sign_broadcast.start();
    let dkg_broadcast_handle = dkg_broadcast.start();

    let outputs: Vec<(Signature, Point)> = nodes
        .into_iter()
        .map(|n| thread::spawn(|| n.run(message.to_vec(), NUM_NODES)))
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
