use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::request::{GenericRequest, InputUri, IotaMessageUri};

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
