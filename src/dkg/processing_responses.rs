use std::fmt::Display;

use anyhow::Error;
use kyber_rs::{
    group::edwards25519::SuiteEd25519,
    share::dkg::rabin::{DistKeyGenerator, Justification, Response},
};

use crate::fsm::{DeliveryStatus, State, Transition};

use super::{processing_justifications::ProcessingJustifications, DkgMessage, DkgTypes};

pub struct ProcessingResponses {
    dkg: DistKeyGenerator<SuiteEd25519>,
    responses_for_other_nodes: Vec<Response>,
    optional_justifications: Vec<Option<Justification<SuiteEd25519>>>,
    did_urls: Vec<String>,
}

impl ProcessingResponses {
    pub fn new(
        dkg: DistKeyGenerator<SuiteEd25519>,
        responses: Vec<Response>,
        did_urls: Vec<String>,
    ) -> ProcessingResponses {
        ProcessingResponses {
            dkg,
            responses_for_other_nodes: responses,
            optional_justifications: Vec::new(),
            did_urls,
        }
    }
}

impl Display for ProcessingResponses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Processing responses (own: {})",
            self.responses_for_other_nodes.len()
        ))
    }
}

impl State<DkgTypes> for ProcessingResponses {
    fn initialize(&self) -> Vec<DkgMessage> {
        self.responses_for_other_nodes
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
                log::trace!("Skipping own response");
                DeliveryStatus::Delivered
            }
            DkgMessage::Response { response, .. } => match self.dkg.process_response(&response) {
                Ok(justification) => {
                    self.optional_justifications.push(justification);
                    DeliveryStatus::Delivered
                }
                Err(e) if e.to_string() == "vss: already existing response from same origin" => {
                    DeliveryStatus::Delivered
                }
                Err(e) => DeliveryStatus::Error(e),
            },
            m => DeliveryStatus::Unexpected(m),
        }
    }

    fn advance(&self) -> Result<Transition<DkgTypes>, Error> {
        let number_of_other_nodes = self.dkg.participants.len() - 1;
        if self.optional_justifications.len() == number_of_other_nodes * number_of_other_nodes {
            return Ok(Transition::Next(Box::new(ProcessingJustifications::new(
                self.dkg.to_owned(),
                self.optional_justifications
                    .iter()
                    .flatten()
                    .cloned()
                    .collect(),
                self.did_urls.clone(),
            ))));
        }
        Ok(Transition::Same)
    }
}
