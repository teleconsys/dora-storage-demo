use std::fmt::Display;

use anyhow::Result;
use kyber_rs::group::edwards25519::SuiteEd25519;
use kyber_rs::share::dkg::rabin::ComplaintCommits;
use kyber_rs::share::dkg::rabin::DistKeyGenerator;
use kyber_rs::share::dkg::rabin::ReconstructCommits;

use crate::fsm::DeliveryStatus;
use crate::fsm::State;
use crate::fsm::Transition;

use super::processing_reconstruct_commits::ProcessingReconstructCommits;
use super::DkgMessage;
use super::DkgTypes;

pub struct ProcessingComplaints {
    dkg: DistKeyGenerator<SuiteEd25519>,
    complaints: Vec<ComplaintCommits<SuiteEd25519>>,
    reconstruct_commits: Vec<ReconstructCommits<SuiteEd25519>>,
}

impl ProcessingComplaints {
    pub fn new(
        dkg: DistKeyGenerator<SuiteEd25519>,
        complaints: Vec<ComplaintCommits<SuiteEd25519>>,
    ) -> Result<ProcessingComplaints> {
        Ok(ProcessingComplaints {
            dkg,
            complaints,
            reconstruct_commits: Vec::new(),
        })
    }
}

impl Display for ProcessingComplaints {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Processing complaints (own: {})",
            self.complaints.len()
        ))
    }
}

impl State<DkgTypes> for ProcessingComplaints {
    fn initialize(&self) -> Vec<DkgMessage> {
        self.complaints
            .iter()
            .cloned()
            .map(DkgMessage::ComplaintCommits)
            .collect()
    }

    fn deliver(&mut self, message: DkgMessage) -> crate::fsm::DeliveryStatus<DkgMessage> {
        match message {
            DkgMessage::ComplaintCommits(c) => match self.dkg.process_complaint_commits(&c) {
                Ok(reconstruct_commits) => {
                    self.reconstruct_commits.push(reconstruct_commits);
                    DeliveryStatus::Delivered
                }
                Err(e) => DeliveryStatus::Error(e),
            },
            m => crate::fsm::DeliveryStatus::Unexpected(m),
        }
    }

    fn advance(&self) -> Result<crate::fsm::Transition<DkgTypes>, anyhow::Error> {
        Ok(Transition::Next(Box::new(
            ProcessingReconstructCommits::new(self.dkg.to_owned()),
        )))
    }
}
