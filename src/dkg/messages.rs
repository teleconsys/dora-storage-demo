use enum_display::EnumDisplay;
use kyber_rs::{
    group::edwards25519::{Point, SuiteEd25519},
    share::dkg::rabin::{
        ComplaintCommits, Deal, Justification, ReconstructCommits, Response, SecretCommits,
    },
};

#[derive(Clone, EnumDisplay)]
pub enum DkgMessage {
    PublicKey(Point),
    Deal {
        destination: Point,
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
