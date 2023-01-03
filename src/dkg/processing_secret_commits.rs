use crate::fsm::{DeliveryStatus, State, Transition};
use anyhow::Error;
use kyber_rs::{
    group::edwards25519::SuiteEd25519,
    share::dkg::rabin::{ComplaintCommits, DistKeyGenerator, SecretCommits},
};
use std::fmt::Display;

use super::{processing_complaints::ProcessingComplaints, DkgMessage};

pub struct ProcessingSecretCommits {
    dkg: DistKeyGenerator<SuiteEd25519>,
    secret_commits: SecretCommits<SuiteEd25519>,
    optional_complaints: Vec<Option<ComplaintCommits<SuiteEd25519>>>,
}

impl ProcessingSecretCommits {
    pub fn new(
        dkg: DistKeyGenerator<SuiteEd25519>,
        secret_commits: SecretCommits<SuiteEd25519>,
    ) -> ProcessingSecretCommits {
        ProcessingSecretCommits {
            dkg,
            secret_commits,
            optional_complaints: Vec::new(),
        }
    }
}

impl Display for ProcessingSecretCommits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("Processing secret commits",))
    }
}

impl State<DkgMessage> for ProcessingSecretCommits {
    fn initialize(&self) -> Vec<DkgMessage> {
        vec![DkgMessage::SecretCommits {
            secret_commits: self.secret_commits.to_owned(),
            source: self.dkg.pubb.to_owned(),
        }]
    }

    fn deliver(&mut self, message: DkgMessage) -> DeliveryStatus<DkgMessage> {
        match message {
            DkgMessage::SecretCommits { source, .. } if source == self.dkg.pubb => {
                log::trace!("Skipping own message");
                DeliveryStatus::Delivered
            }
            DkgMessage::SecretCommits {
                secret_commits: sc, ..
            } => {
                let result = self.dkg.process_secret_commits(&sc);
                match result {
                    Ok(optional_complaint) => {
                        self.optional_complaints.push(optional_complaint);
                        DeliveryStatus::Delivered
                    }
                    Err(e) => DeliveryStatus::Error(e),
                }
            }
            m => DeliveryStatus::Unexpected(m),
        }
    }

    fn advance(&self) -> Result<Transition<DkgMessage>, Error> {
        let num_other_nodes = self.dkg.participants.len() - 1;
        if self.optional_complaints.len() == num_other_nodes {
            let transition = Transition::Next(Box::new(ProcessingComplaints::new(
                self.dkg.to_owned(),
                self.optional_complaints
                    .to_owned()
                    .into_iter()
                    .flatten()
                    .collect(),
            )?));
            return Ok(transition);
        }
        Ok(Transition::Same)
    }
}
