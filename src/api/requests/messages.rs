use core::fmt;
use std::str::FromStr;

use enum_display::EnumDisplay;

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use url::Url;

use super::NodeMessage;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct StorageLocalUri(pub String);
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct IotaIndexUri(String);
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]

pub struct IotaMessageUri(pub String);

impl ToString for IotaMessageUri {
    fn to_string(&self) -> String {
        format!("iota:message:{}", self.0)
    }
}

#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
pub enum InputUri {
    Iota(IotaMessageUri),
    Local(StorageLocalUri),
    Literal(String),
    Url(Url),
}

impl Serialize for InputUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            InputUri::Iota(ref iota) => match iota {
                IotaMessageUri(index) => serializer.serialize_str(&format!("iota:message:{index}")),
            },
            InputUri::Local(ref local) => match local {
                StorageLocalUri(index) => {
                    serializer.serialize_str(&format!("storage:local:{index}"))
                }
            },
            InputUri::Literal(s) => serializer.serialize_str(&format!("literal:string:{s}")),
            InputUri::Url(u) => serializer.serialize_str(u.as_str()),
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
                IotaIndexUri(index) => serializer.serialize_str(&format!("iota:index:{index}")),
            },
            OutputUri::Storage(ref local) => match local {
                StorageLocalUri(index) => {
                    serializer.serialize_str(&format!("storage:local:{index}"))
                }
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
            StorageUri::Storage(ref local) => match local {
                StorageLocalUri(index) => {
                    serializer.serialize_str(&format!("storage:local:{index}"))
                }
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

            if let Ok(uri) = StorageLocalUri::from_str(v) {
                return Ok(StorageUri::Storage(uri));
            }

            Err(E::custom(UriDeserializeError::InvalidUri.to_string()))
        }
    }

    deserializer.deserialize_any(StorageUriVisitor)
}

impl FromStr for StorageLocalUri {
    type Err = UriDeserializeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return Err(UriDeserializeError::InvalidUri);
        }

        if let ("storage", "local", index) = (parts[0], parts[1], parts[2]) {
            return Ok(StorageLocalUri(index.to_owned()));
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

        if let Ok(uri) = StorageLocalUri::from_str(s) {
            return Ok(InputUri::Local(uri));
        }

        {
            let parts: Vec<_> = s.split(':').collect();
            if let ("literal", "string") = (parts[0], parts[1]) {
                return Ok(InputUri::Literal(parts[2..].join(":")));
            }
        }

        if let Ok(uri) = Url::from_str(s) {
            return Ok(InputUri::Url(uri));
        }

        Err(UriDeserializeError::InvalidUri)
    }
}

#[derive(Deserialize, Clone, Debug)]
pub enum OutputUri {
    None,
    Iota(IotaIndexUri),
    Storage(StorageLocalUri),
}

impl Default for OutputUri {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Clone, Deserialize, Debug, PartialEq, Eq)]
pub enum StorageUri {
    None,
    Storage(StorageLocalUri),
}

impl Default for StorageUri {
    fn default() -> Self {
        StorageUri::None
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Execution {
    None,
}

impl Default for Execution {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RequestId(pub String);

#[derive(Serialize, Deserialize)]
pub struct Signature(pub Vec<u8>);

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum ResponseState {
    Success,
    Failure,
}

impl Default for ResponseState {
    fn default() -> Self {
        ResponseState::Failure
    }
}

fn default_signature_flag() -> bool {
    false
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GenericRequest {
    #[serde(deserialize_with = "deserialize_input_uri")]
    pub input_uri: InputUri,
    #[serde(default = "Default::default")]
    pub execution: Execution,
    #[serde(default = "default_signature_flag")]
    pub signature: bool,
    #[serde(default = "Default::default")]
    #[serde(deserialize_with = "deserialize_output_uri")]
    pub output_uri: OutputUri,
    #[serde(default = "Default::default")]
    #[serde(deserialize_with = "deserialize_storage_uri")]
    pub storage_uri: StorageUri,
}

#[derive(Error, Debug, EnumDisplay)]
pub enum GenericRequestParseError {
    NotAValidRequest,
}

impl TryInto<NodeMessage> for GenericRequest {
    type Error = GenericRequestParseError;

    fn try_into(self) -> Result<NodeMessage, Self::Error> {
        Ok(NodeMessage::GenericRequest(self))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct CommitteeLog {
    pub(crate) committee_did: String,
    pub(crate) request_id: RequestId,
    pub(crate) result: ResponseState,
    pub(crate) output_uri: Option<OutputUri>,
    pub(crate) data: Option<String>,
    pub(crate) signature_hex: Option<String>,
}

#[derive(Error, Debug, EnumDisplay)]
pub enum CommitteeLogParseError {
    NotAValidResponse,
}

impl FromStr for CommitteeLog {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::de::from_str(s)
    }
}
