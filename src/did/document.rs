use identity_iota::{core::ToJson, prelude::IotaDocument};

use crate::dlt::iota::{create_unsigned_did, publish_did, resolve_did};
use anyhow::Result;

pub enum Document {
    IotaDocument {
        document: IotaDocument,
        network: String,
    },
}

pub fn new_document(
    public_key_bytes: &[u8],
    network: &str,
    time_resolution: Option<u32>,
) -> Result<Document> {
    let document: Document = match network {
        "iota-main" => Document::IotaDocument {
            document: create_unsigned_did(public_key_bytes, "main".to_string(), time_resolution)?,
            network: "main".to_string(),
        },
        "iota-dev" => Document::IotaDocument {
            document: create_unsigned_did(public_key_bytes, "dev".to_string(), time_resolution)?,
            network: "dev".to_string(),
        },
        _ => panic!("{} network is not supported", network),
    };
    Ok(document)
}

pub fn resolve_document(did_url: String) -> Result<Document> {
    let did_network: Vec<&str> = did_url.split(':').collect();
    let document: Document = match did_network[1] {
        "iota" => {
            let doc = resolve_did(did_url)?;
            Document::IotaDocument {
                document: doc.clone(),
                network: doc.id().network_str().to_owned(),
            }
        }
        _ => todo!(),
    };

    Ok(document)
}

impl Document {
    pub fn publish(self, signature: &[u8]) -> Result<()> {
        match self {
            Document::IotaDocument {
                mut document,
                network,
            } => publish_did(&mut document, signature, network)?,
        };
        Ok(())
    }

    pub fn did_url(&self) -> String {
        match self {
            Document::IotaDocument {
                document,
                network: _,
            } => document.id().to_string(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Document::IotaDocument {
                document,
                network: _,
            } => Ok(document.to_jcs()?),
        }
    }
}
