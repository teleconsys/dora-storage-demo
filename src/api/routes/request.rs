use core::fmt;
use std::str::FromStr;

use enum_display::EnumDisplay;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::demo::node::Node;

use super::{get::GetRequest, save::StoreRequest, NodeMessage};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DoraLocalUri(String);
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct IotaIndexUri(String);
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct IotaMessageUri(pub String);

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum InputUri {
    Iota(IotaMessageUri),
    Local(DoraLocalUri),
}

#[derive(Error, Debug)]
pub enum UriDeserializeError {
    #[error("not a valid URI")]
    InvalidUri,
}

fn deserialize_input_uri<'de, D>(deserializer: D) -> Result<InputUri, D::Error>
where
    D: Deserializer<'de>,
{
    struct InputUriVisitor;

    impl<'de> serde::de::Visitor<'de> for InputUriVisitor {
        type Value = InputUri;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string containing input uri")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            InputUri::from_str(v).map_err(E::custom)
        }
    }

    deserializer.deserialize_any(InputUriVisitor)
}

fn deserialize_output_uri<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<OutputUri, D::Error> {
    struct OutputUriVisitor;

    impl<'de> serde::de::Visitor<'de> for OutputUriVisitor {
        type Value = OutputUri;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string containing output uri")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if let Ok(uri) = IotaIndexUri::from_str(v) {
                return Ok(OutputUri::Iota(uri));
            }

            Err(E::custom(UriDeserializeError::InvalidUri.to_string()))
        }
    }

    deserializer.deserialize_any(OutputUriVisitor)
}

fn deserialize_storage_uri<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<StorageUri, D::Error> {
    struct StorageUriVisitor;

    impl<'de> serde::de::Visitor<'de> for StorageUriVisitor {
        type Value = StorageUri;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string containing output uri")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if let Ok(uri) = DoraLocalUri::from_str(v) {
                return Ok(StorageUri::Dora(uri));
            }

            Err(E::custom(UriDeserializeError::InvalidUri.to_string()))
        }
    }

    deserializer.deserialize_any(StorageUriVisitor)
}

impl FromStr for DoraLocalUri {
    type Err = UriDeserializeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return Err(UriDeserializeError::InvalidUri);
        }

        if let ("dora", "local", index) = (parts[0], parts[1], parts[2]) {
            return Ok(DoraLocalUri(index.to_owned()));
        }

        Err(UriDeserializeError::InvalidUri)
    }
}

impl FromStr for IotaIndexUri {
    type Err = UriDeserializeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return Err(UriDeserializeError::InvalidUri);
        }

        if let ("iota", "index", index) = (parts[0], parts[1], parts[2]) {
            return Ok(IotaIndexUri(index.to_owned()));
        }

        Err(UriDeserializeError::InvalidUri)
    }
}

impl FromStr for IotaMessageUri {
    type Err = UriDeserializeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return Err(UriDeserializeError::InvalidUri);
        }

        if let ("iota", "message", index) = (parts[0], parts[1], parts[2]) {
            return Ok(IotaMessageUri(index.to_owned()));
        }

        Err(UriDeserializeError::InvalidUri)
    }
}

impl FromStr for InputUri {
    type Err = UriDeserializeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(uri) = IotaMessageUri::from_str(s) {
            return Ok(InputUri::Iota(uri));
        }

        if let Ok(uri) = DoraLocalUri::from_str(s) {
            return Ok(InputUri::Local(uri));
        }

        Err(UriDeserializeError::InvalidUri)
    }
}

#[derive(Serialize, Deserialize)]
pub enum OutputUri {
    None,
    Iota(IotaIndexUri),
    Dora(DoraLocalUri),
}

impl Default for OutputUri {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum StorageUri {
    None,
    Dora(DoraLocalUri),
}

impl Default for StorageUri {
    fn default() -> Self {
        StorageUri::None
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub enum Execution {
    None,
}

impl Default for Execution {
    fn default() -> Self {
        Self::None
    }
}

pub struct RequestId(String);

pub struct Signature(String);

pub enum ResponseState {}

fn default_signature_flag() -> bool {
    false
}

#[derive(Serialize, Deserialize)]
pub struct GenericRequest {
    #[serde(deserialize_with = "deserialize_input_uri")]
    pub input: InputUri,
    #[serde(default = "Default::default")]
    #[serde(deserialize_with = "deserialize_output_uri")]
    pub output: OutputUri,
    #[serde(default = "Default::default")]
    pub execution: Execution,
    #[serde(default = "default_signature_flag")]
    pub signature: bool,
    #[serde(default = "Default::default")]
    #[serde(deserialize_with = "deserialize_storage_uri")]
    pub store: StorageUri,
}

#[test]
fn test_generic_get_request() {
    let request_json =
        r#"{ "input": "dora:local:asdf", "output": "iota:index:asdf", "execution": "None" }"#;
    let request: GenericRequest =
        serde_json::from_str(request_json).expect("could not deserialize into generic request");
    assert_eq!(request.execution, Execution::None);
    assert_eq!(request.store, StorageUri::None);
    assert!(!request.signature);
    assert_eq!(
        request.input,
        InputUri::Local(DoraLocalUri("asdf".to_owned()))
    );

    let node_message: NodeMessage = request
        .try_into()
        .expect("could not convert generic request into a specific one");

    assert!(matches!(
        node_message,
        NodeMessage::GetRequest(GetRequest { message_id }) if message_id == "asdf"
    ))
}

#[test]
fn test_generic_store_request() {
    let request_json = r#"{ "input": "iota:message:asdf", "store": "dora:local:asdf" }"#;
    let request: GenericRequest =
        serde_json::from_str(request_json).expect("could not deserialize into generic request");
    assert_eq!(request.execution, Execution::None);
    assert_eq!(
        request.store,
        StorageUri::Dora(DoraLocalUri("asdf".to_owned()))
    );
    assert!(!request.signature);
    assert_eq!(
        request.input,
        InputUri::Iota(IotaMessageUri("asdf".to_owned()))
    );

    let node_message: NodeMessage = request
        .try_into()
        .expect("could not convert generic request into a specific one");

    assert!(matches!(
        node_message,
        NodeMessage::StoreRequest(StoreRequest { message_id }) if message_id == "asdf"
    ))
}

pub struct GenericResponse {
    request_id: RequestId,
    result: ResponseState,
    signature: Signature,
    output_location: Option<OutputUri>,
}

#[derive(Error, Debug, EnumDisplay)]
pub enum GenericRequestParsingError {
    RequestNotSupported,
    LocalInputInStoreRequest,
    DifferentIndexInStoreInputAndStorage,
}

impl TryInto<NodeMessage> for GenericRequest {
    type Error = GenericRequestParsingError;

    fn try_into(self) -> Result<NodeMessage, Self::Error> {
        if let InputUri::Local(DoraLocalUri(index)) = self.input {
            return Ok(NodeMessage::GetRequest(GetRequest { message_id: index }));
        }

        if let StorageUri::Dora(DoraLocalUri(storage_index)) = self.store {
            match self.input {
                InputUri::Iota(IotaMessageUri(index)) => {
                    if index != storage_index {
                        return Err(
                            GenericRequestParsingError::DifferentIndexInStoreInputAndStorage,
                        );
                    }
                    return Ok(NodeMessage::StoreRequest(StoreRequest {
                        message_id: index,
                    }));
                }
                InputUri::Local(_) => {
                    return Err(GenericRequestParsingError::LocalInputInStoreRequest)
                }
            }
        }

        Err(GenericRequestParsingError::RequestNotSupported)
    }
}
