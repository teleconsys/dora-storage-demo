use anyhow::Result;
use identity_iota::{
    client::TangleResolve,
    core::{BaseEncoding, FromJson, Timestamp},
    crypto::{GetSignatureMut, Proof, ProofOptions, ProofValue, PublicKey, SetSignature},
    did::{Service, DID},
    iota_core::{IotaDID, IotaService, IotaVerificationMethod},
    prelude::{IotaDocument, KeyType},
};
use iota_client::{
    bee_message::prelude::{Address, Ed25519Address},
    crypto::hashes::{blake2b::Blake2b256, Digest},
};
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::client::identity_client;

pub fn create_unsigned_did(
    bytes_pub_key: &[u8],
    network_name: String,
    time_resolution: Option<u32>,
    committee_nodes_dids: Option<Vec<String>>,
) -> Result<IotaDocument> {
    let did = IotaDID::new_with_network(bytes_pub_key, network_name.clone())?;

    let public_key = &PublicKey::from(bytes_pub_key.to_vec());

    // Create new method for did initialization
    let method: IotaVerificationMethod =
        IotaVerificationMethod::new(did, KeyType::Ed25519, public_key, "sign-0")?;

    // Create a DID Document from public key (with verification method)
    let mut document = IotaDocument::from_verification_method(method).unwrap();

    // Manage custom resolution timestamp
    if let Some(resolution) = time_resolution {
        let mut now = OffsetDateTime::now_utc();
        now = now - time::Duration::nanoseconds(now.nanosecond() as i64);
        let rem = time::Duration::seconds(now.second() as i64).whole_seconds()
            % time::Duration::seconds(resolution as i64).whole_seconds();
        now -= time::Duration::seconds(rem);

        let now_str = now.format(&Rfc3339)?;
        let timestamp = Timestamp::parse(&now_str)?;

        document.metadata.created = Some(timestamp);
        document.metadata.updated = Some(timestamp);
    }

    let result = Blake2b256::digest(bytes_pub_key).try_into();

    let address_hash = Address::Ed25519(Ed25519Address::new(result?));

    // Get address hrp from network type
    let hrp_address = match network_name.as_str() {
        "main" => "iota",
        "dev" => "atoi",
        _ => todo!(),
    };

    let address = address_hash.to_bech32(hrp_address);

    // Create and add wallet address as a service
    let service_address: IotaService = Service::from_json_value(json!({
        "id": document.id().to_url().join("#iota-address-0")?,
        "type": "IotaAddress",
        "serviceEndpoint": "iota://".to_owned() + address.as_str(),
    }))?;
    document.insert_service(service_address);

    // insert committee's members did urls
    if let Some(mut urls) = committee_nodes_dids {
        urls.sort();
        document
            .properties_mut()
            .insert("committeeMembers".into(), urls.into());
    }

    // Set up proof field
    let proof: Proof = Proof::new_with_options(
        "JcsEd25519Signature2020",
        "#sign-0",
        ProofOptions::default(),
    );
    document.set_signature(proof);

    // Serialize bytes to sign
    Ok(document)
}

pub fn publish_did(
    document: &mut IotaDocument,
    signature: &[u8],
    network_name: String,
    node_url: Option<String>
) -> Result<()> {
    let sig_b58 = BaseEncoding::encode_base58(signature);

    // Insert computed signature
    let sig_ref: &mut Proof = document.signature_mut().unwrap();
    sig_ref.set_value(ProofValue::Signature(sig_b58));

    // Verify signature
    document.verify_document(document)?;

    let client = identity_client(&network_name, node_url)?;
    let r = tokio::runtime::Runtime::new()?;
    r.block_on(client.publish_document(document))?;

    Ok(())
}

pub fn resolve_did(did_url: String, node_url: Option<String>) -> Result<IotaDocument> {
    let iota_did = IotaDID::parse(did_url)?;
    let client = identity_client(iota_did.network_str(), node_url)?;
    let r = tokio::runtime::Runtime::new()?;
    let resolved_doc = r.block_on(client.resolve(&iota_did))?;

    Ok(resolved_doc.document)
}
