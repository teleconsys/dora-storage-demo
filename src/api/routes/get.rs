use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GetRequest {
    message_id: String,
}

#[derive(Serialize, Deserialize)]
pub enum GetResponse {
    Success { signature: Vec<u8>, data: Vec<u8> },
    Failure(GetError),
}

#[derive(Serialize, Deserialize)]
pub enum GetError {}
