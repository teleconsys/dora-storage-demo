use std::fmt::Display;

use kyber_rs::{
    group::edwards25519::SuiteEd25519,
    share::dkg::rabin::{DistKeyGenerator, ReconstructCommits},
};

use crate::fsm::{State, Transition};

use super::{DkgMessage, DkgTerminalStates, DkgTypes};

pub struct ProcessingReconstructCommits {
    dkg: DistKeyGenerator<SuiteEd25519>,
    reconstruct_commits: Vec<ReconstructCommits<SuiteEd25519>>,
}

impl ProcessingReconstructCommits {
    pub fn new(dkg: DistKeyGenerator<SuiteEd25519>) -> ProcessingReconstructCommits {
        ProcessingReconstructCommits {
            dkg,
            reconstruct_commits: Vec::new(),
        }
    }
}

impl Display for ProcessingReconstructCommits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Processing Reconstruct Commits (own: {})",
            self.reconstruct_commits.len()
        ))
    }
}

impl State<DkgTypes> for ProcessingReconstructCommits {
    fn initialize(&self) -> Vec<DkgMessage> {
        self.reconstruct_commits
            .iter()
            .cloned()
            .map(DkgMessage::ReconstructCommits)
            .collect()
    }

    fn deliver(&mut self, message: DkgMessage) -> crate::fsm::DeliveryStatus<DkgMessage> {
        match message {
            DkgMessage::ReconstructCommits(rc) => match self.dkg.process_reconstruct_commits(&rc) {
                Ok(()) => crate::fsm::DeliveryStatus::Delivered,
                Err(e) => crate::fsm::DeliveryStatus::Error(e),
            },
            m => crate::fsm::DeliveryStatus::Unexpected(m),
        }
    }

    fn advance(&self) -> Result<crate::fsm::Transition<DkgTypes>, anyhow::Error> {
        match self.dkg.dist_key_share() {
            Ok(_) => Ok(Transition::Terminal(DkgTerminalStates::Completed {
                dkg: self.dkg.clone(),
            })),
            Err(_) => Ok(Transition::Same),
        }
    }
}
