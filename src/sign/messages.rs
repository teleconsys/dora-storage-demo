use enum_display::EnumDisplay;
use kyber_rs::{group::edwards25519::SuiteEd25519, sign::dss::PartialSig};

#[derive(Clone, EnumDisplay)]
pub enum SignMessage {
    PartialSignature(PartialSig<SuiteEd25519>),
}
