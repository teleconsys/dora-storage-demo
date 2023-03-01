use identity_iota::{prelude::IotaDocument, verification::MethodScope};
use iota_client::{
    api::PreparedTransactionData,
    block::{address::Address, payload::Payload},
    Client,
};
use kyber_rs::{encoding::BinaryUnmarshaler, group::edwards25519::Point, util::key::Pair};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::dlt::iota::{create_unsigned_did, publish_did, resolve_did, sign_did};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Document {
    IotaDocument {
        address: Option<Address>,
        document: IotaDocument,
        document_transaction: Option<PreparedTransactionData>,
        document_payload: Option<Payload>,
        committee: bool,
    },
}

pub fn new_document(
    public_key_bytes: &[u8],
    time_resolution: Option<u32>,
    committee_nodes_dids: Option<Vec<String>>,
    node_url: &str,
    committee: bool,
) -> Result<Document> {
    let client = Client::builder().with_node(node_url)?.finish()?;
    let (address, document, prepared_transaction_data) = create_unsigned_did(
        public_key_bytes,
        client,
        time_resolution,
        committee_nodes_dids,
    )?;
    let document = Document::IotaDocument {
        address: Some(address),
        document,
        document_transaction: Some(prepared_transaction_data),
        document_payload: None,
        committee,
    };
    Ok(document)
}

pub fn resolve_document(did: String, node_url: &str) -> Result<Document> {
    let doc = resolve_did(did, node_url)?;

    Ok(Document::IotaDocument {
        document: doc.clone(),
        document_transaction: None,
        document_payload: None,
        address: None,
        committee: false,
    })
}

impl Document {
    pub fn sign(&mut self, keypair: Pair<Point>, node_url: &str) -> Result<()> {
        match self {
            Document::IotaDocument {
                document_transaction,
                committee,
                document_payload,
                ..
            } => {
                let prepared_data = match document_transaction {
                    Some(d) => d,
                    None => return Err(anyhow::Error::msg("No prepared transaction data")),
                };
                let r = tokio::runtime::Runtime::new()?;
                let payload = r.block_on(sign_did(
                    node_url,
                    prepared_data.clone(),
                    keypair,
                    *committee,
                ))?;
                *document_payload = Some(payload);
            }
        }
        Ok(())
    }

    pub fn publish(&mut self, node_url: &str) -> Result<()> {
        match self {
            Document::IotaDocument {
                document,
                document_payload,
                ..
            } => {
                let payload = match document_payload {
                    Some(p) => p,
                    None => return Err(anyhow::Error::msg("No payload")),
                };
                *document = publish_did(payload.clone(), node_url)?
            }
        };
        Ok(())
    }

    pub fn did(&self) -> String {
        match self {
            Document::IotaDocument { document, .. } => document.id().to_string(),
        }
    }

    pub fn public_key(&self) -> Result<Point> {
        match self {
            Document::IotaDocument { document, .. } => {
                let method = match document
                    .core_document()
                    .resolve_method("#key-1", Some(MethodScope::VerificationMethod))
                {
                    Some(m) => m,
                    None => return Err(anyhow::Error::msg("Can't find verification method")),
                };

                let mut p = Point::default();
                p.unmarshal_binary(&method.data().try_decode()?)?;
                Ok(p)
            }
        }
    }
}
