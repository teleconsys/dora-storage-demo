use std::fmt::Display;

use crate::states::fsm::StateMachineTypes;

mod initializing;
mod messages;

pub use messages::SignMessage;

pub use initializing::Initializing;
pub use initializing::InitializingBuilder;

pub struct SignTypes {}

impl StateMachineTypes for SignTypes {
    type Message = SignMessage;
    type TerminalStates = SignTerminalStates;
}

pub struct Signature(Vec<u8>);

impl Signature {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl From<Vec<u8>> for Signature {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl<'a> From<&'a Signature> for &'a [u8] {
    fn from(value: &'a Signature) -> Self {
        value.0.as_slice()
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

pub enum SignTerminalStates {
    Completed(Signature),
}
