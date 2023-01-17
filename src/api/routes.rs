use actix_web::{post, web, ResponseError};
use enum_display::EnumDisplay;
use serde::{Deserialize, Serialize};

use crate::dkg;

pub struct StoreData {
    pub dkg_initial_state: dkg::Initializing,
}

#[post("/store")]
pub async fn store(
    req_body: web::Json<StoreRequest>,
    data: web::Data<StoreData>,
) -> Result<String, StoreError> {
    let response = serde_json::to_string(&StoreResponse {
        data: "Hello!".to_string(),
    })?;
    println!("{:?}", data.dkg_initial_state.to_string());
    Ok(response)
    // Ok(HttpResponse::Ok()
    //     .content_type(ContentType::json())
    //     .body(response))
    // Either::Left(StoreResponse {})
}

#[derive(Deserialize)]
pub struct StoreRequest {}

#[derive(Serialize)]
struct StoreResponse {
    data: String,
}

#[derive(Debug, EnumDisplay)]
pub enum StoreError {
    NotFoundOnIOTA,
    CouldNotSign,
    SerializationError(serde_json::Error),
}

impl ResponseError for StoreError {}

impl From<serde_json::Error> for StoreError {
    fn from(value: serde_json::Error) -> Self {
        StoreError::SerializationError(value)
    }
}
