use enum_display::EnumDisplay;
use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    share::dkg::rabin::{
        ComplaintCommits, Deal, Justification, ReconstructCommits, Response, SecretCommits,
    },
};
use serde::{Deserialize, Serialize};

#[derive(Clone, EnumDisplay, Serialize, Deserialize)]
pub enum DkgMessage {
    PublicKey(Point),
    DIDUrl(String),
    Deal {
        destination: Point,
        #[serde(deserialize_with = "Deal::deserialize")]
        deal: Deal<Point>,
    },
    Response {
        source: Point,
        response: Response,
    },
    Justification(Justification<SuiteEd25519>),
    SecretCommits {
        source: Point,
        secret_commits: SecretCommits<SuiteEd25519>,
    },
    ComplaintCommits(ComplaintCommits<SuiteEd25519>),
    ReconstructCommits(ReconstructCommits<SuiteEd25519>),
}
