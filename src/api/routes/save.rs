use actix_web::{put, web, ResponseError};
use enum_display::EnumDisplay;
use serde::{Deserialize, Serialize};

use crate::api::routes::{listen_for_message, AppData, NodeMessage};

use super::CommunicationError;

#[put("/save")]
pub async fn save(
    req_body: web::Json<StoreRequest>,
    data: web::Data<AppData>,
) -> Result<web::Json<StoreResponse>, StoreRequestError> {
    data.nodes_sender
        .send(NodeMessage::SaveRequest(req_body.message_id.clone()))
        .map_err(|e| CommunicationError::SendError(e))?;
    let nodes_response =
        listen_for_message(&mut data.nodes_receiver.lock().unwrap(), |m| match m {
            NodeMessage::SaveResponse(_) => Some(m),
            _ => None,
        })
        .await?;
    let response = StoreResponse::Success(format!(
        "Saved message with id {}: {}",
        req_body.message_id, nodes_response
    ));
    Ok(actix_web::web::Json(response))
}

#[derive(Serialize, Deserialize)]
pub struct StoreRequest {
    message_id: String,
}

#[derive(Serialize, Deserialize)]
pub enum StoreResponse {
    Success(String),
    Failure(StoreError),
}

#[derive(Serialize, Deserialize)]
pub enum StoreError {
    NotFoundOnIOTA,
    CouldNotSign,
}

#[derive(Debug, EnumDisplay)]
pub enum StoreRequestError {
    CommunicationError(CommunicationError),
}

impl ResponseError for StoreRequestError {}

impl From<CommunicationError> for StoreRequestError {
    fn from(value: CommunicationError) -> Self {
        StoreRequestError::CommunicationError(value)
    }
}

impl From<serde_json::Error> for CommunicationError {
    fn from(value: serde_json::Error) -> Self {
        CommunicationError::SerializationError(value)
    }
}
