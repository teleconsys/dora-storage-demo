mod initializing;
mod initializing_iota;
mod messages;
mod processing_complaints;
mod processing_deals;
mod processing_justifications;
mod processing_reconstruct_commits;
mod processing_responses;
mod processing_secret_commits;

pub use initializing::Initializing;
pub use initializing_iota::InitializingIota;
use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    share::dkg::rabin::DistKeyGenerator,
};
pub use messages::DkgMessage;

use crate::states::fsm::StateMachineTypes;

pub struct DkgTypes {}

impl StateMachineTypes for DkgTypes {
    type Message = DkgMessage;
    type TerminalStates = DkgTerminalStates;
}

pub enum DkgTerminalStates {
    Completed {
        dkg: DistKeyGenerator<SuiteEd25519>,
        did_urls: Vec<String>,
    },
}

pub type DistPublicKey = Point;

pub(crate) fn log_target() -> String {
    "fsm:dkg".to_owned()
}