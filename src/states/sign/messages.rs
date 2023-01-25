use enum_display::EnumDisplay;
use kyber_rs::{group::edwards25519::SuiteEd25519, sign::dss::PartialSig};
use serde::{Deserialize, Serialize};

#[derive(Clone, EnumDisplay, Serialize, Deserialize)]
pub enum SignMessage {
    PartialSignature(PartialSig<SuiteEd25519>),
    WaitingDone,
}
