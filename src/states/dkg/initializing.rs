use std::fmt::Display;

use anyhow::Error;
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

pub struct Initializing {
    key: Pair<Point>,
    did_url: Option<String>,
    num_participants: usize,
    public_keys: Vec<Point>,
    did_urls: Vec<String>,
    node_url: String,
}

impl Display for Initializing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("initializing (nodes: {})", self.num_participants))
    }
}

impl Initializing {
    pub fn new(
        key: Pair<Point>,
        did_url: Option<String>,
        num_participants: usize,
        node_url: String,
    ) -> Initializing {
        let mut public_keys = Vec::with_capacity(num_participants);
        public_keys.push(key.public);
        let mut did_urls = Vec::with_capacity(num_participants);
        if let Some(url) = did_url.clone() {
            did_urls.push(url)
        };
        Self {
            key,
            did_url,
            num_participants,
            public_keys,
            did_urls,
            node_url,
        }
    }
}

impl State<DkgTypes> for Initializing {
    fn initialize(&self) -> Vec<DkgMessage> {
        match &self.did_url {
            Some(url) => vec![DkgMessage::DIDUrl(url.to_string())],
            None => vec![DkgMessage::PublicKey(self.key.public)],
        }
    }

    fn deliver(&mut self, message: DkgMessage) -> DeliveryStatus<DkgMessage> {
        match message {
            DkgMessage::PublicKey(k) => {
                if self.did_url.is_none() {
                    self.public_keys.push(k);
                }
                DeliveryStatus::Delivered
            }
            DkgMessage::DIDUrl(did_url) => {
                self.did_urls.push(did_url.clone());
                self.public_keys.push(
                    resolve_document(did_url, &self.node_url)
                        .unwrap()
                        .public_key()
                        .unwrap(),
                );
                DeliveryStatus::Delivered
            }
            m => DeliveryStatus::Unexpected(m),
        }
    }

    fn advance(&mut self) -> Result<Transition<DkgTypes>, Error> {
        if self.public_keys.len() == self.num_participants
            || self.did_urls.len() == self.num_participants
        {
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
