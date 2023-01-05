use std::fmt::Display;

use crate::fsm::{IoBus, StateMachineTypes};

use self::messages::SignMessage;

mod initializing;
mod messages;

pub use initializing::Initializing;
pub use initializing::InitializingBuilder;

pub struct SignTypes {}

impl StateMachineTypes for SignTypes {
    type Message = SignMessage;

    type Receiver = IoBus<Self::Message>;

    type TerminalStates = SignTerminalStates;
}

pub struct Signature(Vec<u8>);

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}

pub enum SignTerminalStates {
    Completed(Signature),
}
