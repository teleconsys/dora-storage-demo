use actix_web::{put, web, ResponseError};
use enum_display::EnumDisplay;
use serde::{Deserialize, Serialize};

use crate::api::routes::{listen_for_message, AppData, NodeMessage};

use super::{
    request::{InputUri, StorageUri},
    CommunicationError,
};

#[put("/save")]
pub async fn save(
    req_body: web::Json<StoreRequest>,
    data: web::Data<AppData>,
) -> Result<web::Json<StoreResponse>, StoreRequestError> {
    data.nodes_sender
        .send(NodeMessage::StoreRequest(StoreRequest {
            input: req_body.input.clone(),
            storage_uri: req_body.storage_uri.clone(),
        }))
        .map_err(CommunicationError::Send)?;
    let nodes_response =
        listen_for_message(&mut data.nodes_receiver.lock().unwrap(), |m| match m {
            NodeMessage::StoreResponse(_) => Some(m),
            _ => None,
        })
        .await?;
    let response = StoreResponse::Success(format!(
        "Saved message with id {:?}: {}",
        &req_body.0.input, nodes_response
    ));
    Ok(actix_web::web::Json(response))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoreRequest {
    pub input: InputUri,
    pub storage_uri: StorageUri,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StoreResponse {
    Success(String),
    Failure(StoreError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StoreError {
    NotFoundOnIOTA,
    CouldNotSign,
    StorageError(String),
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
        CommunicationError::Serialization(value)
    }
}
