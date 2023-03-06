use std::fs;

use kyber_rs::{
    encoding::BinaryUnmarshaler,
    group::edwards25519::{Point as EdPoint, Scalar as EdScalar, SuiteEd25519},
    share::dkg::rabin::DistKeyGenerator,
    Point, Scalar,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::did::Document;

pub mod node;
pub mod run;

const SAVE_FILE: &str = "node-state.json";
const SAVE_FILE_DIR_CONFIG: &str = "DORA_SAVE_DIR";
fn save_location() -> String {
    match std::env::var(SAVE_FILE_DIR_CONFIG) {
        Ok(dir) => dir + "/" + SAVE_FILE,
        Err(_) => SAVE_FILE.to_owned(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SaveData {
    node_state: Option<NodeState>,
    committee_state: Option<CommitteeState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeState {
    #[serde(
        serialize_with = "serialize_scalar",
        deserialize_with = "deserialize_scalar"
    )]
    private_key: EdScalar,
    #[serde(
        serialize_with = "serialize_point",
        deserialize_with = "deserialize_point"
    )]
    public_key: EdPoint,
    did_document: Option<Document>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CommitteeState {
    dkg: DistKeyGenerator<SuiteEd25519>,
    dist_key: EdPoint,
    did_urls: Vec<String>,
    committee_did: Option<String>,
}

#[derive(Debug, Error)]
enum SaveDataError {
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),
}

impl SaveData {
    fn load_or_create() -> Self {
        match Self::load() {
            Ok(save_data) => save_data,
            Err(e) => {
                log::debug!("could not load save data: {:?}", e);
                let save_data = Self::default();
                if let Err(e) = save_data.save() {
                    log::warn!("could not save save data: {:?}", e);
                };
                save_data
            }
        }
    }

    fn load() -> Result<Self, SaveDataError> {
        let data = fs::read_to_string(save_location())?;
        let save_data: Self = serde_json::de::from_str(&data)?;
        log::debug!("loaded save data from: {:?}", save_location());
        Ok(save_data)
    }

    fn save(&self) -> Result<(), SaveDataError> {
        let data = serde_json::ser::to_string_pretty(self)?;
        fs::write(save_location(), data)?;
        log::debug!("saved data to: {:?}", save_location());
        Ok(())
    }
}

fn serialize_scalar<S, T: Scalar>(scalar: &T, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bin = scalar
        .marshal_binary()
        .map_err(|e| serde::ser::Error::custom(format!("could not serialize: {e}")))?;
    ser.serialize_bytes(&bin)
}

fn deserialize_scalar<'de, D>(de: D) -> Result<EdScalar, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::Deserialize::deserialize(de)?;
    let mut scalar = EdScalar::default();
    scalar
        .unmarshal_binary(&bytes)
        .map_err(|e| serde::de::Error::custom(format!("could not deserialize: {e}")))?;
    Ok(scalar)
}

fn serialize_point<S, T: Point>(scalar: &T, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bin = scalar
        .marshal_binary()
        .map_err(|e| serde::ser::Error::custom(format!("could not serialize: {e}")))?;
    ser.serialize_bytes(&bin)
}

fn deserialize_point<'de, D>(de: D) -> Result<EdPoint, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes: Vec<u8> = serde::Deserialize::deserialize(de)?;
    let mut scalar = EdPoint::default();
    scalar
        .unmarshal_binary(&bytes)
        .map_err(|e| serde::de::Error::custom(format!("could not deserialize: {e}")))?;
    Ok(scalar)
}
