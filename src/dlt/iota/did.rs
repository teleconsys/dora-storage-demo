use std::{collections::HashMap, str::FromStr};

use anyhow::Result;
use identity_iota::{
    core::Timestamp,
    crypto::PublicKey,
    prelude::{IotaDID, IotaDocument, KeyType},
    verification::{MethodScope, VerificationMethod},
};
use iota_client::{
    api::{
        transaction::validate_transaction_payload_length, verify_semantic, ClientBlockBuilder,
        PreparedTransactionData,
    },
    block::{
        address::{Address, Ed25519Address},
        input::{UtxoInput, INPUT_COUNT_MAX},
        output::{
            feature::SenderFeature,
            unlock_condition::{
                GovernorAddressUnlockCondition, StateControllerAddressUnlockCondition,
            },
            AliasId, AliasOutput, AliasOutputBuilder, Feature, Output, RentStructure,
            UnlockCondition,
        },
        payload::{transaction::TransactionId, Payload, TransactionPayload},
        semantic::ConflictReason,
        signature::{Ed25519Signature, Signature},
        unlock::{AliasUnlock, NftUnlock, ReferenceUnlock, SignatureUnlock, Unlock, Unlocks},
    },
    crypto::hashes::{blake2b::Blake2b256, Digest},
    node_api::indexer::query_parameters::QueryParameter,
    Client,
};
use kyber_rs::{
    encoding::BinaryMarshaler, group::edwards25519::Point, sign::eddsa::EdDSA, util::key::Pair,
};

use identity_iota::iota::IotaIdentityClientExt;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub fn create_unsigned_did(
    bytes_pub_key: &[u8],
    client: Client,
    time_resolution: Option<u32>,
    committee_nodes_dids: Option<Vec<String>>,
) -> Result<(Address, IotaDocument, PreparedTransactionData)> {
    let public_key = &PublicKey::from(bytes_pub_key.to_vec());
    let address = Address::Ed25519(Ed25519Address::new(Blake2b256::digest(public_key).into()));

    // Get the Bech32 human-readable part (HRP) of the network.
    let rt = tokio::runtime::Runtime::new()?;
    let network_name = rt.block_on(client.network_name())?;

    // Create a new DID document with a placeholder DID.
    // The DID will be derived from the Alias Id of the Alias Output after publishing.
    let mut document: IotaDocument = IotaDocument::new(&network_name);

    // Create new method for did initialization
    let method: VerificationMethod = VerificationMethod::new(
        document.id().clone(),
        KeyType::Ed25519,
        &public_key,
        "#key-1",
    )?;
    document.insert_method(method, MethodScope::VerificationMethod)?;

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

    // let address = address_hash.to_bech32(hrp_address);

    // // Create and add wallet address as a service
    // let service_address: IotaService = Service::from_json_value(json!({
    //     "id": document.id().to_url().join("#iota-address-0")?,
    //     "type": "IotaAddress",
    //     "serviceEndpoint": "iota://".to_owned() + address.as_str(),
    // }))?;
    // document.insert_service(service_address);

    // insert committee's members did urls
    if let Some(mut urls) = committee_nodes_dids {
        urls.sort();
        document
            .properties_mut_unchecked()
            .insert("committeeMembers".into(), urls.into());
    }

    // Construct an Alias Output containing the DID document, with the wallet address
    // set as both the state controller and governor.
    println!("creating alias output");
    let alias_output: AliasOutput = rt.block_on(new_did_output(
        &client,
        address,
        document.clone(),
        None,
        None,
    ))?;

    let prepared_transaction_data = rt.block_on(prepare_transaction_data(
        &client,
        address,
        vec![Output::Alias(alias_output)],
    ))?;

    // prepared transaction data to sign
    Ok((address, document, prepared_transaction_data))
}

pub async fn sign_did(
    node_url: &str,
    prepared_transaction_data: PreparedTransactionData,
    key_pair: Pair<Point>,
    committee: bool,
) -> Result<Payload, anyhow::Error> {
    let hashed_essence = prepared_transaction_data.essence.hash();
    let mut blocks = Vec::new();
    let mut block_indexes = HashMap::<Address, usize>::new();

    // Assuming inputs_data is ordered by address type
    for (current_block_index, input) in prepared_transaction_data.inputs_data.iter().enumerate() {
        // Get the address that is required to unlock the input
        let (_, input_address) = Address::try_from_bech32(&input.bech32_address)?;

        // Check if we already added an [Unlock] for this address
        match block_indexes.get(&input_address) {
            // If we already have an [Unlock] for this address, add a [Unlock] based on the address type
            Some(block_index) => match input_address {
                Address::Alias(_alias) => {
                    blocks.push(Unlock::Alias(AliasUnlock::new(*block_index as u16)?))
                }
                Address::Ed25519(_ed25519) => {
                    blocks.push(Unlock::Reference(ReferenceUnlock::new(
                        *block_index as u16,
                    )?));
                }
                Address::Nft(_nft) => {
                    blocks.push(Unlock::Nft(NftUnlock::new(*block_index as u16)?))
                }
            },
            None => {
                // We can only sign ed25519 addresses and block_indexes needs to contain the alias or nft
                // address already at this point, because the reference index needs to be lower
                // than the current block index
                if !input_address.is_ed25519() {
                    return Err(anyhow::Error::from(
                        iota_client::Error::MissingInputWithEd25519Address,
                    ));
                }

                // HERE IS THE MAGIC
                // HERE IS THE MAGIC
                // HERE IS THE MAGIC

                // Get the Ed25519 public key from the derived SLIP-10 private key in the vault.
                //let public_key = self.ed25519_public_key(derive_location.clone()).await?;
                let mut public_key = [0u8; 32];
                for (i, b) in key_pair.public.clone().marshal_binary()?.iter().enumerate() {
                    public_key[i] = *b;
                }

                let signature = match committee {
                    true => todo!(),
                    false => EdDSA::from(key_pair.clone()).sign(&hashed_essence)?,
                };

                // Convert the raw bytes into [Unlock].
                let unlock = Unlock::Signature(SignatureUnlock::new(Signature::Ed25519(
                    Ed25519Signature::new(public_key, signature),
                )));

                blocks.push(unlock);

                // Add the ed25519 address to the block_indexes, so it gets referenced if further inputs have
                // the same address in their unlock condition
                block_indexes.insert(input_address, current_block_index);
            }
        }

        // When we have an alias or Nft output, we will add their alias or nft address to block_indexes,
        // because they can be used to unlock outputs via [Unlock::Alias] or [Unlock::Nft],
        // that have the corresponding alias or nft address in their unlock condition
        match &input.output {
            Output::Alias(alias_output) => block_indexes.insert(
                Address::Alias(alias_output.alias_address(input.output_id())),
                current_block_index,
            ),
            Output::Nft(nft_output) => block_indexes.insert(
                Address::Nft(nft_output.nft_address(input.output_id())),
                current_block_index,
            ),
            _ => None,
        };
    }

    let unlocks = Unlocks::new(blocks)?;

    // LAST STEPS TO BUILD PAYLOAD
    let tx_payload = TransactionPayload::new(prepared_transaction_data.essence.clone(), unlocks)?;

    validate_transaction_payload_length(&tx_payload)?;

    let client = Client::builder().with_node(node_url)?.finish()?;
    let current_time = client.get_time_checked().await?;

    let conflict = verify_semantic(
        &prepared_transaction_data.inputs_data,
        &tx_payload,
        current_time,
    )?;

    if conflict != ConflictReason::None {
        //log::debug!("[sign_transaction] conflict: {conflict:?} for {:#?}", tx_payload);
        return Err(anyhow::Error::from(
            iota_client::Error::TransactionSemantic(conflict),
        ));
    }

    Ok(Payload::from(tx_payload))
}

pub fn publish_did(did_payload: Payload, node_url: &str) -> Result<IotaDocument> {
    let client = Client::builder().with_node(node_url)?.finish()?;

    let r = tokio::runtime::Runtime::new()?;
    let block = r.block_on(client.block().finish_block(Some(did_payload)))?;
    let _ = r.block_on(client.retry_until_included(&block.id(), None, None))?;

    let document = IotaDocument::unpack_from_block(&r.block_on(client.network_name())?, &block)?
    .into_iter()
    .next()
    .ok_or(identity_iota::iota::Error::DIDUpdateError(
        "publish_did_output: no document found in published block",
        None,
    ))?;

    Ok(document)
}

pub fn resolve_did(did: String, node_url: &str) -> Result<IotaDocument> {
    let iota_did = IotaDID::parse(did)?;

    let client = Client::builder().with_node(node_url)?.finish()?;

    let r = tokio::runtime::Runtime::new()?;
    let document = r.block_on(client.resolve_did(&iota_did))?;

    Ok(document)
}

async fn new_did_output(
    client: &Client,
    address: Address,
    document: IotaDocument,
    governor_address: Option<Address>,
    rent_structure: Option<RentStructure>,
) -> Result<AliasOutput> {
    let rent_structure: RentStructure = if let Some(rent) = rent_structure {
        rent
    } else {
        client.get_rent_structure().await?
    };

    let mut alias_output_builder =
        AliasOutputBuilder::new_with_minimum_storage_deposit(rent_structure, AliasId::null())
            .map_err(identity_iota::iota::Error::AliasOutputBuildError)?
            .with_state_index(0)
            .with_foundry_counter(0)
            .with_state_metadata(document.pack()?)
            .add_feature(Feature::Sender(SenderFeature::new(address)))
            .add_unlock_condition(UnlockCondition::StateControllerAddress(
                StateControllerAddressUnlockCondition::new(address),
            ));

    match governor_address {
        Some(governor_address) => {
            alias_output_builder =
                alias_output_builder.add_unlock_condition(UnlockCondition::GovernorAddress(
                    GovernorAddressUnlockCondition::new(governor_address),
                ));
        }
        None => {
            alias_output_builder = alias_output_builder.add_unlock_condition(
                UnlockCondition::GovernorAddress(GovernorAddressUnlockCondition::new(address)),
            );
        }
    }

    let alias_output = alias_output_builder
        .finish(client.get_token_supply().await?)
        .map_err(identity_iota::iota::Error::AliasOutputBuildError)?;

    Ok(alias_output)
}

pub async fn prepare_transaction_data(
    client: &Client,
    address: Address,
    outputs: Vec<Output>,
) -> Result<PreparedTransactionData> {
    let mut total_amount = 0;
    for output in outputs.iter() {
        total_amount += output.amount();
    }

    let inputs = find_inputs(
        client,
        address.to_bech32(client.get_bech32_hrp().await?),
        total_amount,
    )
    .await?;

    let mut tx_builder = client.block();

    for input in inputs {
        tx_builder = tx_builder.with_input(input)?;
    }
    //.with_secret_manager(manager)
    let prepared_transaction_data = tx_builder
        .with_outputs(outputs.clone())?
        .prepare_transaction()
        .await?;

    Ok(prepared_transaction_data)
}

/// Function to find inputs from addresses for a provided amount (useful for offline signing), ignoring outputs with
/// additional unlock conditions
pub async fn find_inputs(client: &Client, address: String, amount: u64) -> Result<Vec<UtxoInput>> {
    // Get outputs from node and select inputs
    let mut available_outputs = Vec::new();

    let basic_output_ids = client
        .basic_output_ids(vec![
            QueryParameter::Address(address.to_string()),
            QueryParameter::HasExpiration(false),
            QueryParameter::HasTimelock(false),
            QueryParameter::HasStorageDepositReturn(false),
        ])
        .await?;

    available_outputs.extend(client.get_outputs(basic_output_ids).await?);

    let mut basic_outputs = Vec::new();
    let current_time = client.get_time_checked().await?;
    let token_supply = client.get_token_supply().await?;

    for output_resp in available_outputs {
        let (amount, _) = ClientBlockBuilder::get_output_amount_and_address(
            &Output::try_from_dto(&output_resp.output, token_supply)?,
            None,
            current_time,
        )?;
        basic_outputs.push((
            UtxoInput::new(
                TransactionId::from_str(&output_resp.metadata.transaction_id)?,
                output_resp.metadata.output_index,
            )?,
            amount,
        ));
    }
    basic_outputs.sort_by(|l, r| r.1.cmp(&l.1));

    let mut total_already_spent = 0;
    let mut selected_inputs = Vec::new();
    for (_offset, output_wrapper) in basic_outputs
        .into_iter()
        // Max inputs is 128
        .take(INPUT_COUNT_MAX.into())
        .enumerate()
    {
        // Break if we have enough funds and don't create dust for the remainder
        if total_already_spent == amount || total_already_spent >= amount {
            break;
        }
        selected_inputs.push(output_wrapper.0);
        total_already_spent += output_wrapper.1;
    }

    if total_already_spent < amount {
        return Err((iota_client::Error::InsufficientAmount {
            found: total_already_spent,
            required: amount,
        })
        .into());
    }

    Ok(selected_inputs)
}

//fn get_essence_distributed_signature() -> Result<(Vec<u8>)> {}
