use enum_display::EnumDisplay;

use serde::{Deserialize, Serialize};

use self::messages::CommitteeLog;
pub use self::messages::GenericRequest;

pub mod messages;

mod node;
pub use node::*;

#[derive(Clone, Debug, EnumDisplay, Serialize, Deserialize)]
pub enum NodeMessage {
    GenericRequest(GenericRequest),
    GenericResponse(CommitteeLog),
}
