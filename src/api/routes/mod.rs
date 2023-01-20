use std::sync::Mutex;

use enum_display::EnumDisplay;
use futures::TryFutureExt;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::{RecvError, SendError};
use tokio::sync::broadcast::{Receiver, Sender};

pub mod delete;
pub mod get;
pub mod save;

pub struct AppData {
    pub nodes_sender: Sender<NodeMessage>,
    pub nodes_receiver: Mutex<Receiver<NodeMessage>>,
}

#[derive(Clone, Debug, EnumDisplay, Serialize, Deserialize)]
pub enum NodeMessage {
    SaveRequest(String),
    SaveResponse(String),
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
