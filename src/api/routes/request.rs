use core::fmt;
use std::str::FromStr;

use enum_display::EnumDisplay;
use iota_client::bee_message::prelude::Output;
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use thiserror::Error;

use super::{
    get::{GetRequest, GetResponse},
    save::StoreRequest,
    NodeMessage,
};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DoraLocalUri(pub String);
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct IotaIndexUri(String);
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct IotaMessageUri(pub String);

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub enum InputUri {
    Iota(IotaMessageUri),
    Local(DoraLocalUri),
}

impl Serialize for InputUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            InputUri::Iota(ref iota) => match iota {
                IotaMessageUri(index) => {
                    serializer.serialize_str(&format!("iota:message:{}", index))
                }
            },
            InputUri::Local(ref local) => match local {
                DoraLocalUri(index) => serializer.serialize_str(&format!("dora:local:{}", index)),
            },
        }
    }
}

impl Serialize for OutputUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            OutputUri::Iota(ref iota) => match iota {
                IotaIndexUri(index) => serializer.serialize_str(&format!("iota:index:{}", index)),
            },
            OutputUri::Dora(ref local) => match local {
                DoraLocalUri(index) => serializer.serialize_str(&format!("dora:local:{}", index)),
            },
            OutputUri::None => serializer.serialize_str("none"),
        }
    }
}

impl Serialize for StorageUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            StorageUri::Dora(ref local) => match local {
                DoraLocalUri(index) => serializer.serialize_str(&format!("dora:local:{}", index)),
            },
            StorageUri::None => serializer.serialize_str("none"),
        }
    }
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
            if v.is_empty() {
                return Ok(OutputUri::None);
            }

            if v == "none" {
                return Ok(OutputUri::None);
            }

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
            if v.is_empty() {
                return Ok(StorageUri::None);
            }

            if v == "none" {
                return Ok(StorageUri::None);
            }

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

#[derive(Deserialize)]
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

#[derive(Deserialize, Debug, PartialEq, Eq)]
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

#[derive(Serialize, Deserialize)]
pub struct RequestId(pub String);

#[derive(Serialize, Deserialize)]
pub struct Signature(pub Vec<u8>);

#[derive(Serialize, Deserialize)]
pub enum ResponseState {
    Success,
    Failure,
}

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
    let request_json = r#"{ "input": "dora:local:asdf", "output": "iota:index:asdf", "execution": "None", "store": "none" }"#;
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
    let request_json =
        r#"{ "input": "iota:message:asdf", "store": "dora:local:asdf", "output": "" }"#;
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

#[derive(Serialize, Deserialize)]
pub struct GenericResponse {
    pub(crate) request_id: RequestId,
    pub(crate) result: ResponseState,
    pub(crate) output_location: Option<OutputUri>,
    pub(crate) data: Option<String>,
    pub(crate) signature: Signature,
}

#[derive(Error, Debug, EnumDisplay)]
pub enum GenericResponseParseError {
    NotAValidResponse,
}

// TODO: Finish implementing
impl TryFrom<NodeMessage> for GenericResponse {
    type Error = GenericResponseParseError;

    fn try_from(value: NodeMessage) -> Result<Self, Self::Error> {
        match value {
            NodeMessage::StoreResponse(r) => Ok(Self {
                request_id: RequestId("".to_owned()),
                result: ResponseState::Success,
                signature: Signature(vec![]),
                output_location: None,
                data: None,
            }),
            NodeMessage::GetResponse(r) => match r {
                GetResponse::Success { data, signature } => Ok(Self {
                    request_id: RequestId("".to_owned()),
                    result: ResponseState::Success,
                    signature: Signature(signature),
                    output_location: None,
                    data: None,
                }),
                GetResponse::Failure(f) => Ok(Self {
                    request_id: RequestId("".to_owned()),
                    result: ResponseState::Failure,
                    signature: Signature(vec![]),
                    output_location: None,
                    data: None,
                }),
            },
            NodeMessage::DeleteResponse(r) => Ok(Self {
                request_id: RequestId("".to_owned()),
                result: ResponseState::Success,
                signature: Signature(Default::default()),
                output_location: None,
                data: None,
            }),
            _ => Err(GenericResponseParseError::NotAValidResponse),
        }
    }
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
