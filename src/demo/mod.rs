use std::fs;

use kyber_rs::{
    encoding::BinaryUnmarshaler,
    group::edwards25519::{Point as EdPoint, Scalar as EdScalar},
    Point, Scalar,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::did::Document;

pub mod node;
pub mod run;

const SAVE_FILE: &str = "node-state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SaveData {
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
struct CommitteeState {}

impl SaveData {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(SAVE_FILE)?;
        let save_data: Self = serde_json::de::from_str(&data)?;
        Ok(save_data)
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let data = serde_json::ser::to_string_pretty(self)?;
        fs::write(SAVE_FILE, data)?;
        Ok(())
    }
}

fn serialize_scalar<S, T: Scalar>(scalar: &T, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bin = scalar
        .marshal_binary()
        .map_err(|e| serde::ser::Error::custom(format!("could not serialize: {}", e)))?;
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
        .map_err(|e| serde::de::Error::custom(format!("could not deserialize: {}", e)))?;
    Ok(scalar)
}

fn serialize_point<S, T: Point>(scalar: &T, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let bin = scalar
        .marshal_binary()
        .map_err(|e| serde::ser::Error::custom(format!("could not serialize: {}", e)))?;
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
        .map_err(|e| serde::de::Error::custom(format!("could not deserialize: {}", e)))?;
    Ok(scalar)
}
