use serde::{Deserialize, Serialize};

use super::request::{InputUri};


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetRequest {
    pub input: InputUri,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GetResponse {
    Success { data: String, signature: Vec<u8> },
    Failure(GetError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum GetError {
    Message(String),
    CouldNotRetrieveFromStorage(String),
}
