use identity_iota::{core::ToJson, prelude::IotaDocument};
use kyber_rs::{encoding::BinaryUnmarshaler, group::edwards25519::Point};

use anyhow::Result;

use crate::{
    dlt::iota::{create_unsigned_did, publish_did, resolve_did},
    net::network::Network,
};

pub enum Document {
    IotaDocument {
        document: IotaDocument,
        network: Network,
    },
}

pub fn new_document(
    public_key_bytes: &[u8],
    network: &Network,
    time_resolution: Option<u32>,
    committee_nodes_dids: Option<Vec<String>>,
) -> Result<Document> {
    let document = Document::IotaDocument {
        document: create_unsigned_did(
            public_key_bytes,
            network
                .clone()
                .try_into()
                .map_err(|_| anyhow::Error::msg("invalid iota network"))?,
            time_resolution,
            committee_nodes_dids,
        )?,
        network: network.clone(),
    };
    Ok(document)
}

pub fn resolve_document(did_url: String, node_url: Option<String>) -> Result<Document> {
    let did_network: Vec<&str> = did_url.split(':').collect();
    let document: Document = match did_network[1] {
        "iota" => {
            let doc = resolve_did(did_url, node_url)?;
            Document::IotaDocument {
                document: doc.clone(),
                network: Network::IotaNetwork(doc.id().network()?),
            }
        }
        _ => todo!(),
    };

    Ok(document)
}

impl Document {
    pub fn publish(self, signature: &[u8], node_url: Option<String>) -> Result<()> {
        match self {
            Document::IotaDocument {
                mut document,
                network,
            } => publish_did(
                &mut document,
                signature,
                network
                    .try_into()
                    .map_err(|_| anyhow::Error::msg("invalid iota network"))?,
                node_url,
            )?,
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

    pub fn public_key(&self) -> Result<Point> {
        match self {
            Document::IotaDocument { document, .. } => {
                let mut p = Point::default();
                p.unmarshal_binary(
                    &document.extract_signing_keys()[0]
                        .expect("there is no public key")
                        .data()
                        .try_decode()?,
                )?;
                Ok(p)
            }
        }
    }
}
