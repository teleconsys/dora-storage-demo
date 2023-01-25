use std::fmt::Display;

use anyhow::Result;
use kyber_rs::group::edwards25519::SuiteEd25519;
use kyber_rs::share::dkg::rabin::ComplaintCommits;
use kyber_rs::share::dkg::rabin::DistKeyGenerator;
use kyber_rs::share::dkg::rabin::ReconstructCommits;

use crate::states::fsm::DeliveryStatus;
use crate::states::fsm::State;
use crate::states::fsm::Transition;

use super::processing_reconstruct_commits::ProcessingReconstructCommits;
use super::DkgMessage;
use super::DkgTypes;

pub struct ProcessingComplaints {
    dkg: DistKeyGenerator<SuiteEd25519>,
    complaints: Vec<ComplaintCommits<SuiteEd25519>>,
    reconstruct_commits: Vec<ReconstructCommits<SuiteEd25519>>,
    did_urls: Vec<String>,
}

impl ProcessingComplaints {
    pub fn new(
        dkg: DistKeyGenerator<SuiteEd25519>,
        complaints: Vec<ComplaintCommits<SuiteEd25519>>,
        did_urls: Vec<String>,
    ) -> Result<ProcessingComplaints> {
        Ok(ProcessingComplaints {
            dkg,
            complaints,
            reconstruct_commits: Vec::new(),
            did_urls,
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

    fn deliver(&mut self, message: DkgMessage) -> DeliveryStatus<DkgMessage> {
        match message {
            DkgMessage::ComplaintCommits(c) => match self.dkg.process_complaint_commits(&c) {
                Ok(reconstruct_commits) => {
                    self.reconstruct_commits.push(reconstruct_commits);
                    DeliveryStatus::Delivered
                }
                Err(e) => DeliveryStatus::Error(e),
            },
            m => DeliveryStatus::Unexpected(m),
        }
    }

    fn advance(&mut self) -> Result<Transition<DkgTypes>, anyhow::Error> {
        Ok(Transition::Next(Box::new(
            ProcessingReconstructCommits::new(self.dkg.to_owned(), self.did_urls.clone()),
        )))
    }
}
