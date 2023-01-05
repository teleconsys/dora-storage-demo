extern crate log;
extern crate pretty_env_logger;

mod dkg;
mod feed;
mod fsm;
mod sign;

use std::{iter::repeat_with, sync::Arc};

use anyhow::{Ok, Result};
use dkg::{DkgTerminalStates, DkgTypes, Initializing};
use feed::Feed;
use fsm::{IoBus, StateMachine};
use futures::{executor::block_on, lock::Mutex};

use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    share::dkg::rabin::DistKeyGenerator,
    util::key::{new_key_pair, Pair},
};
use sign::{SignTypes, Signature};

#[test]
fn test_main() -> Result<()> {
    main()
}

const NUM_NODES: usize = 5;

fn main() -> Result<()> {
    pretty_env_logger::init();

    let message = "Hello, world!";

    let suite = &SuiteEd25519::new_blake_sha256ed25519();
    let keypair_generator = repeat_with(|| new_key_pair(suite)).flatten();

    let messages = Arc::new(Mutex::new(Vec::new()));

    let keypairs: Vec<Pair<Point>> = keypair_generator.take(NUM_NODES).collect();
    let mut nodes: Vec<StateMachine<DkgTypes>> = keypairs
        .iter()
        .enumerate()
        .map(|(i, keypair)| {
            StateMachine::new(
                Box::new(Initializing::new(keypair.clone(), NUM_NODES)),
                Feed::new(IoBus::new(messages.clone(), keypair.public.clone())),
                Box::new(IoBus::new(messages.clone(), keypair.public.clone())),
                i,
            )
        })
        .take(NUM_NODES)
        .collect();

    let dkg_results = nodes.iter_mut().map(|n| n.run());

    let completed_dkgs = block_on(futures::future::join_all(dkg_results))
        .into_iter()
        .map(|t| match t? {
            DkgTerminalStates::Completed { dkg } => Ok(dkg),
        })
        .collect::<Result<Vec<DistKeyGenerator<SuiteEd25519>>>>()?;

    let messages = Arc::new(Mutex::new(Vec::new()));
    let mut sign_state_machines = completed_dkgs
        .into_iter()
        .map(sign::InitializingBuilder::try_from)
        .zip(keypairs.clone())
        .map(|(builder, k)| {
            builder?
                .with_secret(k.private)
                .with_message(message.into())
                .build()
        })
        .enumerate()
        .map(|(i, initial_state)| {
            Ok(StateMachine::new(
                Box::new(initial_state?),
                Feed::new(IoBus::new(
                    messages.to_owned(),
                    keypairs.get(i).unwrap().public.clone(),
                )),
                Box::new(IoBus::new(
                    messages.to_owned(),
                    keypairs.get(i).unwrap().public.clone(),
                )),
                i,
            ))
        })
        .collect::<Result<Vec<StateMachine<SignTypes>>>>()?;
    let signatures = block_on(futures::future::join_all(
        sign_state_machines.iter_mut().map(|s| s.run()),
    ))
    .into_iter()
    .map(|r| match r? {
        sign::SignTerminalStates::Completed(sig) => Ok(sig),
    })
    .collect::<Result<Vec<Signature>>>()?;

    for signature in signatures {
        println!("Signature: {}", signature)
    }

    Ok(())
}
