mod initializing;
mod messages;
mod processing_complaints;
mod processing_deals;
mod processing_justifications;
mod processing_reconstruct_commits;
mod processing_responses;
mod processing_secret_commits;

pub use initializing::Initializing;
use kyber_rs::{group::edwards25519::SuiteEd25519, share::dkg::rabin::DistKeyGenerator};
pub use messages::DkgMessage;

use crate::fsm::{IoBus, StateMachineTypes};

pub struct DkgTypes {}

impl StateMachineTypes for DkgTypes {
    type Message = DkgMessage;

    type Receiver = IoBus<DkgMessage>;

    type TerminalStates = DkgTerminalStates;
}

pub enum DkgTerminalStates {
    Completed { dkg: DistKeyGenerator<SuiteEd25519> },
}
