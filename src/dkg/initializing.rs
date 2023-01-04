use std::fmt::Display;

use anyhow::Error;
use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    share::dkg::rabin::new_dist_key_generator,
    util::key::Pair,
};

use crate::fsm::{DeliveryStatus, State, Transition};

use super::{processing_deals::ProcessingDeals, DkgMessage};

pub struct Initializing {
    key: Pair<Point>,
    num_participants: usize,
    public_keys: Vec<Point>,
}

impl Display for Initializing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("Initializing (nodes: {})", self.num_participants))
    }
}

impl Initializing {
    pub fn new(key: Pair<Point>, num_participants: usize) -> Initializing {
        let mut public_keys = Vec::with_capacity(num_participants);
        public_keys.push(key.public.clone());
        Self {
            key,
            num_participants,
            public_keys,
        }
    }
}

impl State<DkgMessage> for Initializing {
    fn initialize(&self) -> Vec<DkgMessage> {
        vec![DkgMessage::PublicKey(self.key.public.clone())]
    }

    fn deliver(&mut self, message: DkgMessage) -> DeliveryStatus<DkgMessage> {
        match message {
            DkgMessage::PublicKey(k) => {
                self.public_keys.push(k);
                DeliveryStatus::Delivered
            }
            m => DeliveryStatus::Unexpected(m),
        }
    }

    fn advance(&self) -> Result<Transition<DkgMessage>, Error> {
        match self.public_keys.len() {
            n if n == self.num_participants => {
                let mut public_keys = self.public_keys.clone();
                public_keys.sort_by_key(|pk| pk.string());
                let dkg = new_dist_key_generator(
                    &SuiteEd25519::new_blake_sha256ed25519(),
                    &self.key.private,
                    &public_keys,
                    self.num_participants / 2 + 1,
                )?;
                Ok(Transition::Next(Box::new(ProcessingDeals::new(dkg)?)))
            }
            _ => Ok(Transition::Same),
        }
    }
}
