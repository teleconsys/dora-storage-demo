use actix_web::{post, put, web, ResponseError};
use enum_display::EnumDisplay;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::SendError;

use crate::api::routes::{AppData, NodeMessage};

#[put("/save")]
pub async fn save(
    req_body: web::Json<StoreRequest>,
    data: web::Data<AppData>,
) -> Result<web::Json<StoreResponse>, StoreError> {
    data.nodes_sender
        .send(NodeMessage::SaveRequest(req_body.message_id.clone()))
        .map_err(|e| StoreError::CommunicationError(e))?;
    let response = StoreResponse {
        data: format!("Saved message with id {}", req_body.message_id),
    };
    Ok(actix_web::web::Json(response))
}

#[derive(Deserialize)]
pub struct StoreRequest {
    message_id: String,
}

#[derive(Serialize)]
pub struct StoreResponse {
    data: String,
}

#[derive(Debug, EnumDisplay)]
pub enum StoreError {
    NotFoundOnIOTA,
    CouldNotSign,
    SerializationError(serde_json::Error),
    CommunicationError(SendError<NodeMessage>),
}

impl ResponseError for StoreError {}

impl From<serde_json::Error> for StoreError {
    fn from(value: serde_json::Error) -> Self {
        StoreError::SerializationError(value)
    }
}
