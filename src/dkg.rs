use std::{
    collections::HashMap,
    fmt::{Debug, Display},
};

use anyhow::Error;
use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    share::dkg::rabin::{new_dist_key_generator, Deal, DistKeyGenerator, Justification, Response},
    util::key::Pair,
};

use crate::fsm::{DeliveryStatus, State, Transition};

#[derive(Clone)]
pub enum DkgMessage {
    PublicKey(Point),
    Deal {
        destination: Point,
        deal: Deal<Point>,
    },
    Response {
        source: Point,
        response: Response,
    },
    Justification(Justification<SuiteEd25519>),
}

pub struct Initializing {
    key: Pair<Point>,
    num_participants: usize,
    public_keys: Vec<Point>,
}

impl Display for Initializing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Initializing with {} participants",
            self.num_participants
        ))
    }
}

impl Initializing {
    pub fn new(key: Pair<Point>, num_participants: usize) -> Initializing {
        Self {
            key,
            num_participants,
            public_keys: Vec::with_capacity(num_participants),
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
                let mut dkg = new_dist_key_generator(
                    &SuiteEd25519::new_blake_sha256ed25519(),
                    &self.key.private,
                    &self.public_keys,
                    self.num_participants / 2 + 1,
                )?;
                let deals = dkg.deals()?;
                Ok(Transition::Next(Box::new(ProcessingDeals {
                    deals,
                    dkg,
                    responses: vec![],
                })))
            }
            _ => Ok(Transition::Same),
        }
    }
}

pub struct ProcessingDeals {
    pub deals: HashMap<usize, Deal<Point>>,
    pub dkg: DistKeyGenerator<SuiteEd25519>,
    pub responses: Vec<Response>,
}

impl Display for ProcessingDeals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Processing deals with {} deals generated",
            self.deals.len()
        ))
    }
}

impl State<DkgMessage> for ProcessingDeals {
    fn initialize(&self) -> Vec<DkgMessage> {
        self.deals
            .iter()
            .map(|(i, v)| DkgMessage::Deal {
                destination: self.dkg.participants[*i].clone(),
                deal: v.clone(),
            })
            .collect()
    }

    fn deliver(&mut self, message: DkgMessage) -> DeliveryStatus<DkgMessage> {
        let result = match message {
            DkgMessage::Deal {
                destination: pub_key,
                deal,
            } => match pub_key {
                p if p == self.dkg.pubb => self.dkg.process_deal(&deal),
                _ => {
                    return DeliveryStatus::Delivered;
                }
            },
            _ => return DeliveryStatus::Unexpected(message),
        };
        match result {
            Ok(r) => {
                self.responses.push(r);
                DeliveryStatus::Delivered
            }
            Err(e) => DeliveryStatus::Error(e),
        }
    }

    fn advance(&self) -> Result<Transition<DkgMessage>, Error> {
        match self.responses.len() {
            n if n == self.dkg.participants.len() - 1 => {
                Ok(Transition::Next(Box::new(ProcessingResponses {
                    dkg: self.dkg.clone(),
                    responses: self.responses.clone(),
                    justifications: vec![],
                })))
            }
            _ => Ok(Transition::Same),
        }
    }
}

struct ProcessingResponses {
    dkg: DistKeyGenerator<SuiteEd25519>,
    responses: Vec<Response>,
    justifications: Vec<Option<Justification<SuiteEd25519>>>,
}

impl Display for ProcessingResponses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Processing responses with {} responses generated",
            self.responses.len()
        ))
    }
}

impl State<DkgMessage> for ProcessingResponses {
    fn initialize(&self) -> Vec<DkgMessage> {
        self.responses
            .iter()
            .map(|r| DkgMessage::Response {
                source: self.dkg.pubb.clone(),
                response: r.clone(),
            })
            .collect()
    }

    fn deliver(&mut self, message: DkgMessage) -> DeliveryStatus<DkgMessage> {
        match message {
            DkgMessage::Response { source, .. } if source == self.dkg.pubb => {
                println!("skipping own response");
                DeliveryStatus::Delivered
            }
            DkgMessage::Response { response, .. } => match self.dkg.process_response(&response) {
                Ok(justification) => {
                    self.justifications.push(justification);
                    DeliveryStatus::Delivered
                }
                Err(e) => DeliveryStatus::Error(e),
            },
            DkgMessage::Deal { destination, .. } if destination == self.dkg.pubb => {
                DeliveryStatus::Error(Error::msg(format!(
                    "Received deal while processing responses"
                )))
            }
            DkgMessage::Deal { .. } => DeliveryStatus::Delivered,
            m => DeliveryStatus::Unexpected(m),
        }
    }

    fn advance(&self) -> Result<Transition<DkgMessage>, Error> {
        match self.justifications.len() {
            n if n == self.responses.len() => {
                // Ok(Transition::Next(Box::new(ProcessingSecretCommits {})))
                Ok(Transition::Terminal)
            }
            _ => Ok(Transition::Same),
        }
    }
}

struct ProcessingSecretCommits {}

impl Display for ProcessingSecretCommits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl State<DkgMessage> for ProcessingSecretCommits {
    fn initialize(&self) -> Vec<DkgMessage> {
        todo!()
    }

    fn deliver(&mut self, message: DkgMessage) -> DeliveryStatus<DkgMessage> {
        todo!()
    }

    fn advance(&self) -> Result<Transition<DkgMessage>, Error> {
        todo!()
    }
}
