use std::sync::Mutex;

use enum_display::EnumDisplay;
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::{RecvError, SendError};
use tokio::sync::broadcast::{Receiver, Sender};

use self::delete::{DeleteRequest, DeleteResponse};
use self::get::{GetRequest, GetResponse};
pub use self::request::GenericRequest;
use self::save::{StoreRequest, StoreResponse};

pub mod delete;
pub mod get;
pub mod request;
pub mod save;

pub struct AppData {
    pub nodes_sender: Sender<NodeMessage>,
    pub nodes_receiver: Mutex<Receiver<NodeMessage>>,
}

#[derive(Clone, Debug, EnumDisplay, Serialize, Deserialize)]
pub enum NodeMessage {
    StoreRequest(StoreRequest),
    StoreResponse(StoreResponse),
    GetRequest(GetRequest),
    GetResponse(GetResponse),
    DeleteRequest(DeleteRequest),
    DeleteResponse(DeleteResponse),
}

pub async fn listen_for_message<T: Clone, F: Fn(T) -> Option<T>>(
    nodes_receiver: &mut Receiver<T>,
    matcher: F,
) -> Result<T, CommunicationError> {
    loop {
        let m = nodes_receiver
            .recv()
            .map_err(CommunicationError::Receive)
            .await?;
        if let Some(m) = matcher(m) {
            break Ok(m);
        }
    }
}

#[derive(Debug)]
pub enum CommunicationError {
    Serialization(serde_json::Error),
    Send(SendError<NodeMessage>),
    Receive(RecvError),
}

