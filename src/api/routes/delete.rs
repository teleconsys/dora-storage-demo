use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct DeleteRequest {
    message_id: String,
}

#[derive(Serialize, Deserialize)]
pub enum DeleteResponse {
    Success,
    Failure(DeleteError),
}

#[derive(Serialize, Deserialize)]
pub enum DeleteError {}
