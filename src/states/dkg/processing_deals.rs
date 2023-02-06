use anyhow::{Error, Result};
use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    share::dkg::rabin::{Deal, DistKeyGenerator, Response},
};
use std::{collections::HashMap, fmt::Display};

use crate::states::{
    dkg::log_target,
    fsm::{DeliveryStatus, State, Transition},
};

use super::{processing_responses::ProcessingResponses, DkgMessage, DkgTypes};

pub struct ProcessingDeals {
    deals: HashMap<usize, Deal<Point>>,
    dkg: DistKeyGenerator<SuiteEd25519>,
    responses: Vec<Response>,
    did_urls: Vec<String>,
}

impl ProcessingDeals {
    pub fn new(
        mut dkg: DistKeyGenerator<SuiteEd25519>,
        did_urls: Vec<String>,
    ) -> Result<ProcessingDeals> {
        let deals = dkg.deals()?;
        Ok(ProcessingDeals {
            deals,
            dkg,
            responses: Vec::new(),
            did_urls,
        })
    }
}

impl Display for ProcessingDeals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("processing deals (own: {})", self.deals.len()))
    }
}

impl State<DkgTypes> for ProcessingDeals {
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
        match message {
            DkgMessage::Deal { destination, deal } if destination == self.dkg.pubb => {
                match self.dkg.process_deal(&deal) {
                    Ok(response) => {
                        self.responses.push(response);
                        DeliveryStatus::Delivered
                    }
                    Err(e) => DeliveryStatus::Error(e),
                }
            }
            DkgMessage::Deal { .. } => {
                log::trace!(target: &log_target(), "skipping deal meant for other node");
                DeliveryStatus::Delivered
            }
            m => DeliveryStatus::Unexpected(m),
        }
    }

    fn advance(&mut self) -> Result<Transition<DkgTypes>, Error> {
        match self.responses.len() {
            n if n == self.dkg.participants.len() - 1 => {
                Ok(Transition::Next(Box::new(ProcessingResponses::new(
                    self.dkg.to_owned(),
                    self.responses.to_owned(),
                    self.did_urls.clone(),
                ))))
            }
            _ => Ok(Transition::Same),
        }
    }
}
