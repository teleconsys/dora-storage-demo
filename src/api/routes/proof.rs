use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProofRequest {
    message_id: String,
}

#[derive(Serialize, Deserialize)]
pub enum ProofResponse {
    Success(ProofOfInclusion),
    Failure(ProofError),
}

#[derive(Serialize, Deserialize)]
pub enum ProofError {}

#[derive(Serialize, Deserialize)]
pub struct ProofOfInclusion {}
