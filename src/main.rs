extern crate log;
extern crate pretty_env_logger;

mod dkg;
mod feed;
mod fsm;

use std::sync::Arc;

use anyhow::{Ok, Result};
use dkg::{DkgMessage, Initializing};
use feed::Feed;
use fsm::{IoBus, StateMachine};
use futures::{executor::block_on, lock::Mutex};
use kyber_rs::{
    group::edwards25519::{Point as EdPoint, SuiteEd25519},
    util::key::Pair,
    Group, Point, Random, Scalar,
};

type Suite = kyber_rs::group::edwards25519::SuiteEd25519;

#[test]
fn test_main() -> Result<()> {
    main()
}

fn main() -> Result<()> {
    pretty_env_logger::init();

    let suite = &SuiteEd25519::new_blake_sha256ed25519();
    let messages = Arc::new(Mutex::new(Vec::new()));
    let mut nodes: Vec<StateMachine<DkgMessage, IoBus<DkgMessage>>> = (0..5)
        .into_iter()
        .map(|i| {
            StateMachine::new(
                Box::new(Initializing::new(new_key_pair(suite), 5)),
                Feed::new(IoBus::new(messages.clone())),
                Box::new(IoBus::new(messages.clone())),
                i,
            )
        })
        .collect();

    let futures = nodes.iter_mut().map(|n| n.run());
    let results = block_on(futures::future::join_all(futures));

    for r in results {
        r?;
    }

    Ok(())
}

fn new_key_pair(suite: &Suite) -> Pair<EdPoint> {
    let private = suite.scalar().pick(&mut suite.random_stream());
    let public = suite.point().mul(&private, None);
    Pair { private, public }
}
