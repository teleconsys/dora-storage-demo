use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetRequest {
    pub message_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GetResponse {
    Success { signature: Vec<u8>, data: Vec<u8> },
    Failure(GetError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GetError {
    Message(String),
}
