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
    did_urls: Vec<String>,
}

impl ProcessingJustifications {
    pub fn new(
        dkg: DistKeyGenerator<SuiteEd25519>,
        own_justifications: Vec<Justification<SuiteEd25519>>,
        did_urls: Vec<String>,
    ) -> ProcessingJustifications {
        ProcessingJustifications {
            dkg,
            own_justifications,
            did_urls,
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

    fn advance(&mut self) -> Result<Transition<DkgTypes>, anyhow::Error> {
        if !self.dkg.certified() {
            bail!("deal not certified")
        }
        if self.dkg.participants.len() != self.dkg.qual().len() {
            bail!(
                "only {} nodes are qualified out of {}",
                self.dkg.qual().len(),
                self.dkg.participants.len()
            )
        }
        let mut dkg = self.dkg.to_owned();
        let secret_commits = dkg.secret_commits()?;
        Ok(Transition::Next(Box::new(ProcessingSecretCommits::new(
            dkg,
            secret_commits,
            self.did_urls.clone(),
        ))))
    }
}

impl Display for ProcessingJustifications {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "processing justifications (own: {})",
            self.own_justifications.len()
        ))
    }
}
