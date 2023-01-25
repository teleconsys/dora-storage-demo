use anyhow::Result;

use std::fmt::Display;
use thiserror::Error;

use kyber_rs::{
    group::edwards25519::{Point, Scalar, SuiteEd25519},
    share::dkg::rabin::{DistKeyGenerator, DistKeyShare},
    sign::dss::{new_dss, PartialSig, DSS},
};

use crate::states::fsm::{DeliveryStatus, State, Transition};

use super::{messages::SignMessage, SignTerminalStates, SignTypes, Signature};

pub struct Initializing {
    dss: DSS<SuiteEd25519, DistKeyShare<SuiteEd25519>>,
    partial_signature: PartialSig<SuiteEd25519>,
}

impl Initializing {
    pub fn _new(
        suite: SuiteEd25519,
        secret: &Scalar,
        participants: &[Point],
        dks: &DistKeyShare<SuiteEd25519>,
        msg: &[u8],
        threshold: usize,
    ) -> Result<Self> {
        let mut dss = new_dss(suite, secret, participants, dks, dks, msg, threshold)?;
        let partial_signature = dss.partial_sig()?;
        Ok(Initializing {
            dss,
            partial_signature,
        })
    }
}

pub struct InitializingBuilder {
    suite: SuiteEd25519,
    secret: Option<Scalar>,
    participants: Vec<Point>,
    dks: DistKeyShare<SuiteEd25519>,
    threshold: usize,
    message: Option<Vec<u8>>,
}

#[derive(Debug, Error)]
enum MissingField {
    Secret,
    Message,
}

impl Display for MissingField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MissingField::Secret => f.write_str("Missing field: Secret"),
            MissingField::Message => f.write_str("Missing field: Message"),
        }
    }
}

impl InitializingBuilder {
    pub fn build(self) -> Result<Initializing> {
        let mut dss = new_dss(
            self.suite,
            &self.secret.ok_or(MissingField::Secret)?,
            &self.participants,
            &self.dks,
            &self.dks,
            &self.message.ok_or(MissingField::Message)?,
            self.threshold,
        )?;
        let partial_signature = dss.partial_sig()?;
        Ok(Initializing {
            dss,
            partial_signature,
        })
    }

    pub fn with_secret(self, secret: Scalar) -> Self {
        Self {
            secret: Some(secret),
            ..self
        }
    }

    pub fn with_message(self, message: Vec<u8>) -> Self {
        Self {
            message: Some(message),
            ..self
        }
    }
}

impl TryFrom<DistKeyGenerator<SuiteEd25519>> for InitializingBuilder {
    type Error = anyhow::Error;

    fn try_from(dkg: DistKeyGenerator<SuiteEd25519>) -> Result<Self> {
        let dks = dkg.dist_key_share()?;
        Ok(Self {
            suite: dkg.suite,
            secret: None,
            participants: dkg.participants,
            dks,
            threshold: dkg.t,
            message: None,
        })
    }
}

impl Display for Initializing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Initializing")
    }
}

impl State<SignTypes> for Initializing {
    fn initialize(&self) -> Vec<SignMessage> {
        vec![SignMessage::PartialSignature(
            self.partial_signature.to_owned(),
        )]
    }

    fn deliver(&mut self, message: SignMessage) -> DeliveryStatus<SignMessage> {
        match message {
            SignMessage::PartialSignature(ps) => match self.dss.process_partial_sig(ps) {
                Ok(()) => DeliveryStatus::Delivered,
                Err(e) => {
                    if e.to_string() == "dss: partial signature not valid" {
                        DeliveryStatus::Delivered
                    } else {
                        DeliveryStatus::Error(e)
                    }
                }
            },
        }
    }

    fn advance(&self) -> Result<Transition<SignTypes>, anyhow::Error> {
        if self.dss.enough_partial_sig() {
            let signature = self.dss.signature()?;
            return Ok(Transition::Terminal(SignTerminalStates::Completed(
                Signature(signature),
            )));
        }
        Ok(Transition::Same)
    }
}
