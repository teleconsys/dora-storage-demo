extern crate log;
extern crate pretty_env_logger;

mod dkg;
mod feed;
mod fsm;

use std::{iter::repeat_with, sync::Arc};

use anyhow::{Ok, Result};
use dkg::{DkgMessage, Initializing};
use feed::Feed;
use fsm::{IoBus, StateMachine};
use futures::{executor::block_on, lock::Mutex};
use kyber_rs::{group::edwards25519::SuiteEd25519, util::key::new_key_pair};

#[test]
fn test_main() -> Result<()> {
    main()
}

const NUM_NODES: usize = 5;

fn main() -> Result<()> {
    pretty_env_logger::init();

    let suite = &SuiteEd25519::new_blake_sha256ed25519();
    let messages = Arc::new(Mutex::new(Vec::new()));
    let keypairs = repeat_with(|| new_key_pair(suite)).flatten();
    let mut nodes: Vec<StateMachine<DkgMessage, IoBus<DkgMessage>>> = keypairs
        .enumerate()
        .map(|(i, keypair)| {
            StateMachine::new(
                Box::new(Initializing::new(keypair.clone(), NUM_NODES)),
                Feed::new(IoBus::new(messages.clone(), keypair.public.clone())),
                Box::new(IoBus::new(messages.clone(), keypair.public)),
                i,
            )
        })
        .take(NUM_NODES)
        .collect();

    let futures = nodes.iter_mut().map(|n| n.run());
    let results = block_on(futures::future::join_all(futures));

    for r in results {
        r?;
    }

    Ok(())
}
