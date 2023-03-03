use std::sync::mpsc::{Receiver, Sender};

use crate::api::requests::{ApiNode, ApiParams, GenericRequest, HandlerParams};
use crate::demo::run::{get_address, get_address_balance, request_faucet_funds};
use crate::demo::CommitteeState;
use crate::did::{new_document, resolve_document, Document};
use crate::dkg::{DkgMessage, DkgTerminalStates};
use crate::dlt::iota::{FsmSigner, Listener, Publisher};
use crate::logging::{new_node_signature_logger, new_signature_log, NodeSignatureLogger};
use crate::states::dkg::InitializingIota;
use crate::states::feed::{Feed, MessageWrapper};
use crate::states::fsm::StateMachine;
use crate::states::sign::{self, SignMessage, SignTerminalStates};
use crate::store::Storage;

use identity_iota::iota::NetworkName;
use identity_iota::prelude::IotaDID;
use iota_client::block::address::Address;
use iota_client::block::output::AliasId;
use iota_client::node_api::indexer::query_parameters::QueryParameter;
use iota_client::Client;
use kyber_rs::encoding::BinaryMarshaler;
use kyber_rs::group::edwards25519::SuiteEd25519;
use kyber_rs::share::dkg::rabin::DistKeyGenerator;
use kyber_rs::{group::edwards25519::Point, util::key::Pair};

use super::SaveData;

const DKG_ID: &str = "dkg";

pub struct NodeChannels {
    pub dkg_input_channel: Receiver<MessageWrapper<DkgMessage>>,
    pub sign_input_channel: Receiver<MessageWrapper<SignMessage>>,
    pub dkg_output_channel: Sender<MessageWrapper<DkgMessage>>,
    pub sign_output_channel: Sender<MessageWrapper<SignMessage>>,
    pub sign_input_channel_sender: Sender<MessageWrapper<SignMessage>>,
}

pub struct Node {
    pub keypair: Pair<Point>,
    pub channels: NodeChannels,
    pub network_params: NodeNetworkParams,
    pub protocol_params: NodeProtocolParams,
    pub id: usize,
    pub save_data: SaveData,
}

pub struct NodeNetworkParams {
    pub node_url: String,
}

pub struct NodeProtocolParams {
    pub own_did_url: String,
    pub did_urls: Vec<String>,
    pub num_participants: usize,
    pub time_resolution: usize,
    pub signature_sleep_time: u64,
}

impl Node {
    pub fn new(
        keypair: Pair<Point>,
        channels: NodeChannels,
        network_params: NodeNetworkParams,
        protocol_params: NodeProtocolParams,
        id: usize,
    ) -> Self {
        Self {
            keypair,
            channels,
            network_params,
            protocol_params,
            id,
            save_data: SaveData {
                node_state: None,
                committee_state: None,
            },
        }
    }

    pub fn with_save_data(self, save_data: SaveData) -> Self {
        Self { save_data, ..self }
    }

    pub fn run(mut self, storage: Option<Storage>) -> Result<(), anyhow::Error> {
        let secret = self.keypair.private;
        let public = self.keypair.public;

        let (dkg, did_urls, dist_pub_key) = match self.save_data.committee_state {
            Some(ref committee_state) => (
                committee_state.dkg.clone(),
                committee_state.did_urls.clone(),
                committee_state.dist_key,
            ),
            None => {
                let (dkg, did_urls, dist_key) = self
                    .run_dkg(&public)
                    .map_err(|e| anyhow::Error::msg("failed to run dkg").context(e))?;
                self.save_data.committee_state = Some(CommitteeState {
                    dkg: dkg.clone(),
                    did_urls: did_urls.clone(),
                    dist_key,
                    committee_did: None,
                });
                if let Err(e) = self.save_data.save() {
                    log::error!("Failed to save committee data: {}", e);
                };
                (dkg, did_urls, dist_key)
            }
        };

        // Create and publish DID
        let did_url = match self
            .save_data
            .committee_state
            .as_ref()
            .and_then(|cs| cs.committee_did.as_ref())
        {
            Some(did) => anyhow::Ok(did.to_owned()),
            None => Ok({
                log::debug!("Creating and publishing DID");
                let did = self
                    .create_did(
                        dist_pub_key,
                        &did_urls,
                        &self.network_params.node_url,
                        &dkg,
                        secret,
                        public,
                    )
                    .map_err(|e| {
                        anyhow::Error::msg("could not create and publish DID").context(e)
                    })?;
                if let Some(ref mut committee_state) = self.save_data.committee_state {
                    committee_state.committee_did = Some(did.clone())
                }
                if let Err(e) = self.save_data.save() {
                    log::warn!("Failed to save committee data: {}", e);
                }
                did
            }),
        }?;

        // Create a iota signature logger
        let iota_logger = new_node_signature_logger(
            self.protocol_params.own_did_url.clone(),
            did_url.clone(),
            self.keypair.clone(),
            self.network_params.node_url.clone(),
        );
        self.run_api_node(did_url, storage, dkg, iota_logger, did_urls)
            .map_err(|e| anyhow::Error::msg("failed to run api node").context(e))?;
        Ok(())
    }

    fn create_did(
        &self,
        dist_pub_key: Point,
        dids: &[String],
        node_url: &str,
        dkg: &DistKeyGenerator<SuiteEd25519>,
        secret: kyber_rs::group::edwards25519::Scalar,
        public: Point,
    ) -> Result<String, anyhow::Error> {
        let mut all_dids = self.protocol_params.did_urls.clone();
        all_dids.push(self.protocol_params.own_did_url.clone());
        all_dids.sort();

        let client = Client::builder().with_node(node_url)?.finish()?;
        let rt = tokio::runtime::Runtime::new()?;

        let address = get_address(&dist_pub_key.marshal_binary()?);
        let address_str = address.to_bech32(rt.block_on(client.get_bech32_hrp())?);

        let balance = rt.block_on(get_address_balance(&client, &address))?;
        log::trace!(
            "committee's address {} balance is: {}",
            address_str,
            balance
        );
        if balance < 10000000 {
            log::trace!("waiting for funds on committee's address {}", address_str);
            if self.protocol_params.own_did_url == all_dids[0] {
                rt.block_on(request_faucet_funds(
                    &client,
                    address,
                    "https://faucet.testnet.shimmer.network/api/enqueue",
                ))?
            } else {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    let balance = rt.block_on(get_address_balance(&client, &address))?;
                    if balance >= 10000000 {
                        break;
                    }
                }
            }
        }
        let mut document = new_document(
            &dist_pub_key
                .marshal_binary()
                .map_err(|e| anyhow::Error::msg("failed to marshal dist pub key").context(e))?,
            Some(self.protocol_params.time_resolution as u32),
            Some(dids.to_vec()),
            node_url,
            false,
        )
        .map_err(|e| anyhow::Error::msg("failed to create new DID document").context(e))?;
        log::info!("committee's DID document created");
        log::info!("signing committee's DID document...");

        let sign_initial_state = sign::InitializingBuilder::try_from(dkg.clone())?
            .with_secret(secret)
            .with_sender(self.channels.sign_input_channel_sender.clone())
            .with_sleep_time(self.protocol_params.signature_sleep_time)
            .with_id(DKG_ID.to_string());

        let signer = FsmSigner::new(
            sign_initial_state,
            &self.channels.sign_input_channel,
            self.channels.sign_output_channel.clone(),
        );

        log::debug!("signing committe's DID");
        document.sign(signer, &dist_pub_key, node_url)?;
        log::debug!("committe's DID signed");

        let mut did = "".to_owned();

        // Publish signed DID if the node is the first on the list
        if self.protocol_params.own_did_url == all_dids[0] {
            log::info!("publishing committee's DID...");
            did = document
                .publish(node_url)
                .map_err(|e| anyhow::Error::msg("failed to publish committee DID").context(e))?;
            log::info!("committee's DID has been published");
            log::info!("committee's DID is: {}", did);

            //let resolved_did = resolve_document(did_url.clone())?;
        } else {
            log::info!("waiting for committee's DID...");
            let c = Client::builder().with_node(node_url)?.finish()?;
            let rt = tokio::runtime::Runtime::new()?;
            let mut found = false;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let alias_ids = rt.block_on(find_alias_ids(
                    &c,
                    get_address(&dist_pub_key.marshal_binary()?),
                ))?;
                for id in alias_ids {
                    //let (_, alias) = rt.block_on(c.alias_output_id(id))?;
                    let name_string = match rt.block_on(c.get_network_name())?.as_ref() {
                        "shimmer" => todo!(),
                        "testnet" => "rms",
                        _ => return Err(anyhow::Error::msg("got unsupported network from client")),
                    };
                    let did_candidate = IotaDID::from_alias_id(
                        &id.to_string(),
                        &NetworkName::try_from(name_string)?,
                    );
                    let published_doc = resolve_document(did_candidate.to_string(), node_url);
                    match published_doc {
                        Ok(doc) => {
                            if doc.public_key()? == document.public_key()? {
                                found = true;
                                did = did_candidate.to_string();
                                break;
                            }
                        }
                        Err(_) => continue,
                    }
                }
                if found {
                    break;
                }
            }
            log::info!("committee's DID has been published");
            log::info!("committee's DID is: {}", did);

            //let resolved_did = resolve_document(did_url.clone())?;
        }
        Ok(did)
    }

    fn run_dkg(
        &mut self,
        public: &Point,
    ) -> Result<(DistKeyGenerator<SuiteEd25519>, Vec<String>, Point), anyhow::Error> {
        log::info!("starting DKG...");
        let dkg_initial_state = InitializingIota::new(
            self.keypair.clone(),
            self.protocol_params.own_did_url.clone(),
            self.protocol_params.did_urls.clone(),
            self.protocol_params.num_participants,
            self.network_params.node_url.clone(),
        )?;
        let mut dkg_fsm = StateMachine::new(
            Box::new(dkg_initial_state),
            DKG_ID.to_owned(),
            Feed::new(&self.channels.dkg_input_channel, DKG_ID.to_string()),
            self.channels.dkg_output_channel.clone(),
        );
        let dkg_terminal_state = dkg_fsm.run()?;
        let DkgTerminalStates::Completed { dkg, did_urls } = dkg_terminal_state;
        let dist_pub_key = dkg.dist_key_share()?.public();
        log::info!("DKG done");
        Ok((dkg, did_urls, dist_pub_key))
    }

    fn run_api_node(
        &self,
        did_url: String,
        storage: Option<Storage>,
        dkg: DistKeyGenerator<SuiteEd25519>,
        logger: NodeSignatureLogger,
        did_urls: Vec<String>,
    ) -> Result<(), anyhow::Error> {
        let binding = did_url.clone();
        let api_index = &binding.split(':').last().unwrap()[2..];
        let mut api_input = Listener::new(&self.network_params.node_url)?;
        let api_output = Publisher::new(&self.network_params.node_url)?;
        let api_params = ApiParams {
            client: Client::builder()
                .with_node(&self.network_params.node_url)?
                .finish()?,
            dkg,
            secret: self.keypair.private,
            public_key: self.keypair.public,
            id: self.id,
            signature_sender: self.channels.sign_input_channel_sender.clone(),
            signature_sleep_time: self.protocol_params.signature_sleep_time,
        };
        let api_node = ApiNode {
            storage: storage.unwrap(),
            api_params,
        };
        let rt = tokio::runtime::Runtime::new()?;
        log::info!("listening for committee requests on index: {}", api_index);
        for (message_data, req_id) in rt.block_on(api_input.start(api_index.to_owned()))? {
            let message: GenericRequest = match serde_json::from_slice(&message_data) {
                Ok(m) => m,
                Err(_) => {
                    continue;
                }
            };
            let request = match message.try_into() {
                Ok(r) => r,
                Err(e) => {
                    log::error!("could not parse request: {}", e);
                    continue;
                }
            };
            let session_id: String = hex::encode(req_id).chars().take(10).collect();
            log::info!("received a request for the committee (msg_id: {})", req_id);
            log::info!("handling request [{}]", session_id);
            let handler_params = HandlerParams {
                signature_logger: logger.clone(),
                committee_did: did_url.clone(),
                dids: did_urls.clone(),
                node_url: self.network_params.node_url.clone(),
            };
            let response = match api_node
                .handle_message(
                    request,
                    &self.channels.sign_input_channel,
                    self.channels.sign_output_channel.clone(),
                    &req_id.to_string(),
                    handler_params,
                )
                .map_err(|e| anyhow::Error::msg(format!("{e:?}")))
            {
                Ok(r) => r,
                Err(e) => {
                    log::error!("could not handle request [{}]: {}", session_id, e);
                    continue;
                }
            };
            if let Some((r, working_nodes)) = response {
                log::info!("request [{}] done", session_id);
                let encoded = serde_json::to_vec(&r)?;
                let mut wn = working_nodes.clone();
                // Publish signed DID if the node is the first on the list
                wn.sort();
                if self.protocol_params.own_did_url == wn[0] {
                    log::info!(
                        "publishing committee's task log for request [{}]...",
                        session_id
                    );
                    match rt.block_on(api_output.publish(&encoded, Some(api_index.to_owned()))) {
                        Ok(i) => log::info!(
                            "committee's task log for request [{}] published (msg_id: {})",
                            session_id,
                            i
                        ),
                        Err(e) => log::error!(
                            "could not publish committee's task log for request [{}]: {}",
                            session_id,
                            e
                        ),
                    };
                }
            }
        }
        Ok(())
    }
}

pub async fn find_alias_ids(
    client: &Client,
    address: Address,
) -> Result<Vec<AliasId>, anyhow::Error> {
    // Get outputs from node and select inputs
    let mut alias_ids = Vec::new();

    let alias_output_ids = client
        .alias_output_ids(vec![QueryParameter::Governor(
            address.to_bech32(client.get_bech32_hrp().await?),
        )])
        .await?;

    for output_id in alias_output_ids {
        alias_ids.push(AliasId::null().or_from_output_id(&output_id))
    }

    Ok(alias_ids)
}
