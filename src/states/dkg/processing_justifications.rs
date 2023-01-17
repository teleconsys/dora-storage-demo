use std::fmt::Display;

use anyhow::bail;
use kyber_rs::group::edwards25519::SuiteEd25519;
use kyber_rs::share::dkg::rabin::DistKeyGenerator;
use kyber_rs::share::dkg::rabin::Justification;

use crate::states::fsm::DeliveryStatus;
use crate::states::fsm::State;
use crate::states::fsm::Transition;

use super::processing_secret_commits::ProcessingSecretCommits;
use super::DkgMessage;
use super::DkgTypes;

pub struct ProcessingJustifications {
    dkg: DistKeyGenerator<SuiteEd25519>,
    own_justifications: Vec<Justification<SuiteEd25519>>,
}

impl ProcessingJustifications {
    pub fn new(
        dkg: DistKeyGenerator<SuiteEd25519>,
        own_justifications: Vec<Justification<SuiteEd25519>>,
    ) -> ProcessingJustifications {
        ProcessingJustifications {
            dkg,
            own_justifications,
        }
    }
}

impl State<DkgTypes> for ProcessingJustifications {
    fn initialize(&self) -> Vec<DkgMessage> {
        self.own_justifications
            .iter()
            .map(|j| DkgMessage::Justification(j.to_owned()))
            .collect()
    }

    fn deliver(&mut self, _message: DkgMessage) -> DeliveryStatus<DkgMessage> {
        todo!()
    }

    fn advance(&self) -> Result<Transition<DkgTypes>, anyhow::Error> {
        if !self.dkg.certified() {
            bail!("Deal not certified")
        }
        if self.dkg.participants.len() != self.dkg.qual().len() {
            bail!(
                "Only {} nodes are qualified out of {}",
                self.dkg.qual().len(),
                self.dkg.participants.len()
            )
        }
        let mut dkg = self.dkg.to_owned();
        let secret_commits = dkg.secret_commits()?;
        Ok(Transition::Next(Box::new(ProcessingSecretCommits::new(
            dkg,
            secret_commits,
        ))))
    }
}

impl Display for ProcessingJustifications {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Processing justifications (own: {})",
            self.own_justifications.len()
        ))
    }
}
