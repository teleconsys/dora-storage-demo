use enum_display::EnumDisplay;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{Receiver, Sender};

pub mod delete;
pub mod get;
pub mod proof;
pub mod save;

pub struct AppData {
    pub nodes_sender: Sender<NodeMessage>,
    pub nodes_receiver: Receiver<NodeMessage>,
}

#[derive(Clone, Debug, EnumDisplay, Serialize, Deserialize)]
pub enum NodeMessage {
    SaveRequest(String),
}
