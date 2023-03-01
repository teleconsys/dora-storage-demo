use std::fmt::Display;

use anyhow::{Error, Result};
use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    share::dkg::rabin::new_dist_key_generator,
    util::key::Pair,
};

use crate::{
    did::resolve_document,
    states::fsm::{DeliveryStatus, State, Transition},
};

use super::{processing_deals::ProcessingDeals, DkgMessage, DkgTypes};

pub struct InitializingIota {
    key: Pair<Point>,
    num_participants: usize,
    public_keys: Vec<Point>,
    did_urls: Vec<String>,
}

impl Display for InitializingIota {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("initializing (nodes: {})", self.num_participants))
    }
}

impl InitializingIota {
    pub fn new(
        key: Pair<Point>,
        own_did_url: String,
        peers_did_urls: Vec<String>,
        num_participants: usize,
        node_url: String,
    ) -> Result<InitializingIota> {
        let mut public_keys = Vec::with_capacity(num_participants);
        public_keys.push(key.public.clone());
        for url in peers_did_urls.clone() {
            public_keys.push(resolve_document(url, &node_url)?.public_key()?);
        }
        let mut did_urls = peers_did_urls;
        did_urls.push(own_did_url);
        Ok(Self {
            key,
            num_participants,
            public_keys,
            did_urls,
        })
    }
}

impl State<DkgTypes> for InitializingIota {
    fn initialize(&self) -> Vec<DkgMessage> {
        vec![]
    }

    fn deliver(&mut self, message: DkgMessage) -> DeliveryStatus<DkgMessage> {
        let m = message;
        DeliveryStatus::Unexpected(m)
    }

    fn advance(&mut self) -> Result<Transition<DkgTypes>, Error> {
        if self.public_keys.len() == self.num_participants {
            let mut public_keys = self.public_keys.clone();
            public_keys.sort_by_key(|pk| pk.to_string());
            let dkg = new_dist_key_generator(
                &SuiteEd25519::new_blake3_sha256_ed25519(),
                &self.key.private,
                &public_keys,
                self.num_participants / 2 + 1,
            )?;
            Ok(Transition::Next(Box::new(ProcessingDeals::new(
                dkg,
                self.did_urls.clone(),
            )?)))
        } else {
            Ok(Transition::Same)
        }
    }
}
