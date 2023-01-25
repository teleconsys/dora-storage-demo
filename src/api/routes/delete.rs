use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub message_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DeleteResponse {
    Success,
    Failure(DeleteError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DeleteError {}
