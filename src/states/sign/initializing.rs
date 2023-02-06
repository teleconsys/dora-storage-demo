use anyhow::Result;
use colored::Colorize;

use std::{fmt::Display, sync::mpsc::Sender, thread, vec};
use thiserror::Error;

use kyber_rs::{
    group::edwards25519::{Point, Scalar, SuiteEd25519},
    share::dkg::rabin::{DistKeyGenerator, DistKeyShare},
    sign::dss::{new_dss, PartialSig, DSS},
};

use crate::states::{
    feed::MessageWrapper,
    fsm::{DeliveryStatus, State, Transition},
};

use super::{messages::SignMessage, SignTerminalStates, SignTypes, Signature};

enum WaitingState {
    Waiting,
    Done,
}

pub struct Initializing {
    dss: DSS<SuiteEd25519, DistKeyShare<SuiteEd25519>>,
    session_id: String,
    partial_signature: PartialSig<SuiteEd25519>,
    processed_partial_owners: Vec<Point>,
    bad_signers: Vec<Point>,
    waiting: WaitingState,
    sender: Sender<MessageWrapper<SignMessage>>,
    sleep_time: u64,
}

impl Initializing {
    pub fn new(
        suite: SuiteEd25519,
        secret: &Scalar,
        session_id: String,
        participants: &[Point],
        dks: &DistKeyShare<SuiteEd25519>,
        msg: &[u8],
        threshold: usize,
        sender: Sender<MessageWrapper<SignMessage>>,
        sleep_time: u64,
    ) -> Result<Self> {
        let mut sorted_participants = participants.to_vec();
        sorted_participants.sort_by_key(|pk| pk.to_string());
        let mut dss = new_dss(
            suite,
            secret,
            &sorted_participants,
            dks,
            dks,
            msg,
            threshold,
        )?;
        let partial_signature = dss.partial_sig()?;
        Ok(Initializing {
            dss,
            session_id,
            partial_signature,
            processed_partial_owners: vec![],
            bad_signers: vec![],
            waiting: WaitingState::Waiting,
            sender,
            sleep_time,
        })
    }
}

pub struct InitializingBuilder {
    suite: SuiteEd25519,
    session_id: Option<String>,
    secret: Option<Scalar>,
    participants: Vec<Point>,
    dks: DistKeyShare<SuiteEd25519>,
    threshold: usize,
    message: Option<Vec<u8>>,
    sender: Option<Sender<MessageWrapper<SignMessage>>>,
    sleep_time: Option<u64>,
}

#[derive(Debug, Error)]
enum MissingField {
    Secret,
    Message,
    Sender,
    SleepTime,
    SessionId,
}

impl Display for MissingField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MissingField::Secret => f.write_str("Missing field: Secret"),
            MissingField::Message => f.write_str("Missing field: Message"),
            MissingField::Sender => f.write_str("Missing field: Sender"),
            MissingField::SleepTime => f.write_str("Missing field: SleepTime"),
            MissingField::SessionId => f.write_str("Missing field: SessionId"),
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
        let own_index = dss.index;
        let partecipants = dss.participants.clone();
        Ok(Initializing {
            dss,
            partial_signature,
            processed_partial_owners: vec![partecipants[own_index].clone()],
            bad_signers: vec![],
            session_id: self.session_id.ok_or(MissingField::SessionId)?,
            waiting: WaitingState::Waiting,
            sender: self.sender.ok_or(MissingField::Sender)?,
            sleep_time: self.sleep_time.ok_or(MissingField::SleepTime)?,
        })
    }

    pub fn with_id(self, id: String) -> Self {
        Self {
            session_id: Some(id),
            ..self
        }
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

    pub fn with_sender(self, sender: Sender<MessageWrapper<SignMessage>>) -> Self {
        Self {
            sender: Some(sender),
            ..self
        }
    }

    pub fn with_sleep_time(self, sleep_time: u64) -> Self {
        Self {
            sleep_time: Some(sleep_time),
            ..self
        }
    }
}

impl TryFrom<DistKeyGenerator<SuiteEd25519>> for InitializingBuilder {
    type Error = anyhow::Error;

    fn try_from(dkg: DistKeyGenerator<SuiteEd25519>) -> Result<Self> {
        let mut sorted_participants = dkg.participants.to_vec();
        sorted_participants.sort_by_key(|pk| pk.to_string());
        let dks = dkg.dist_key_share()?;
        Ok(Self {
            suite: dkg.suite,
            session_id: None,
            secret: None,
            participants: sorted_participants,
            dks,
            threshold: dkg.t,
            message: None,
            sender: None,
            sleep_time: None,
        })
    }
}

impl Display for Initializing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Initializing signature")
    }
}

impl State<SignTypes> for Initializing {
    fn initialize(&self) -> Vec<SignMessage> {
        let sleep_time = self.sleep_time;
        let session_id = self.session_id.clone();
        let sender = self.sender.clone();

        log::trace!(target: &log_target(&self.session_id),
                    "starting partial signatures countdown, {} seconds", sleep_time);
        thread::spawn(move || {
            // sleeps to give time to the missing nodes

            std::thread::sleep(std::time::Duration::from_secs(sleep_time));
            // trigger advance messages in the case that no partial signature is received in the meantime
            sender
                .send(MessageWrapper {
                    session_id,
                    message: SignMessage::WaitingDone,
                })
                .unwrap();
        });

        vec![SignMessage::PartialSignature(
            self.partial_signature.to_owned(),
        )]
    }

    fn deliver(&mut self, message: SignMessage) -> DeliveryStatus<SignMessage> {
        match message {
            SignMessage::PartialSignature(ps) => match self.dss.process_partial_sig(ps.clone()) {
                Ok(()) => {
                    self.processed_partial_owners
                        .push(self.dss.participants[ps.partial.i].clone());
                    DeliveryStatus::Delivered
                }
                Err(e) => {
                    if e.to_string() == "dss: partial signature not valid" {
                        self.bad_signers
                            .push(self.dss.participants[ps.partial.i].clone());
                        self.processed_partial_owners
                            .push(self.dss.participants[ps.partial.i].clone());
                        DeliveryStatus::Delivered
                    } else {
                        DeliveryStatus::Error(e)
                    }
                }
            },
            SignMessage::WaitingDone => {
                self.waiting = WaitingState::Done;
                DeliveryStatus::Delivered
            }
        }
    }

    fn advance(&mut self) -> Result<Transition<SignTypes>, anyhow::Error> {
        match self.waiting {
            WaitingState::Waiting => {
                if self.processed_partial_owners.len() == self.dss.participants.len() {
                    let signature = self.dss.signature()?;
                    Ok(Transition::Terminal(SignTerminalStates::Completed(
                        Signature(signature),
                        self.processed_partial_owners.clone(),
                        self.bad_signers.clone(),
                    )))
                } else {
                    Ok(Transition::Same)
                }
            }
            WaitingState::Done => {
                if self.dss.enough_partial_sig() {
                    let signature = self.dss.signature()?;
                    Ok(Transition::Terminal(SignTerminalStates::Completed(
                        Signature(signature),
                        self.processed_partial_owners.clone(),
                        self.bad_signers.clone(),
                    )))
                } else {
                    log::info!(target: &log_target(&self.session_id),
                        "partial signatures timeout");
                    Ok(Transition::Terminal(SignTerminalStates::Failed))
                }
            }
        }
    }
}

fn log_target(session_id: &str) -> String {
    format!(
        "fsm:{}:signature",
        session_id.chars().take(10).collect::<String>().yellow()
    )
}
