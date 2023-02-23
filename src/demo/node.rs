use std::sync::mpsc::{Receiver, Sender};

use crate::api::requests::{ApiNode, ApiParams, GenericRequest, HandlerParams};
use crate::did::new_document;
use crate::dkg::{DistPublicKey, DkgMessage, DkgTerminalStates};
use crate::dlt::iota::{Listener, Publisher};
use crate::logging::{new_node_signature_logger, new_signature_log, NodeSignatureLogger};
use crate::net::network::Network;
use crate::states::dkg::InitializingIota;
use crate::states::feed::{Feed, MessageWrapper};
use crate::states::fsm::StateMachine;
use crate::states::sign::{self, SignMessage, SignTerminalStates, Signature};
use crate::store::Storage;

use kyber_rs::encoding::BinaryMarshaler;
use kyber_rs::group::edwards25519::SuiteEd25519;
use kyber_rs::share::dkg::rabin::DistKeyGenerator;
use kyber_rs::{group::edwards25519::Point, util::key::Pair};

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
}

pub struct NodeNetworkParams {
    pub network: Network,
    pub node_url: Option<String>,
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
        }
    }

    pub fn run(
        self,
        storage: Option<Storage>,
    ) -> Result<(), anyhow::Error> {
        let secret = self.keypair.private.clone();
        let public = self.keypair.public.clone();

        log::info!("starting DKG...");
        let dkg_id = "dkg";
        let dkg_initial_state = InitializingIota::new(
            self.keypair.clone(),
            self.protocol_params.own_did_url.clone(),
            self.protocol_params.did_urls.clone(),
            self.protocol_params.num_participants,
            self.network_params.node_url.clone(),
        )?;
        let mut dkg_fsm = StateMachine::new(
            Box::new(dkg_initial_state),
            dkg_id.to_owned(),
            Feed::new(&self.channels.dkg_input_channel, dkg_id.to_string()),
            &self.channels.dkg_output_channel,
            self.id,
            public.clone(),
        );
        let dkg_terminal_state = dkg_fsm.run()?;
        let DkgTerminalStates::Completed { dkg, did_urls } = dkg_terminal_state;
        let dist_pub_key = dkg.dist_key_share()?.public();
        log::info!("DKG done");

        // Create unsigned DID
        let document = new_document(
            &dist_pub_key.marshal_binary()?,
            &self.network_params.network,
            Some(self.protocol_params.time_resolution as u32),
            Some(did_urls.clone()),
        )?;

        log::info!("committee's DID document created");
        log::info!("signing committee's DID document...");
        let sign_initial_state = sign::InitializingBuilder::try_from(dkg.clone())?
            .with_message(document.to_bytes()?)
            .with_secret(secret)
            .with_sender(self.channels.sign_input_channel_sender.clone())
            .with_sleep_time(self.protocol_params.signature_sleep_time)
            .with_id(dkg_id.to_string())
            .build()?;

        let mut sign_fsm = StateMachine::new(
            Box::new(sign_initial_state),
            dkg_id.to_owned(),
            Feed::new(&self.channels.sign_input_channel, dkg_id.to_string()),
            &self.channels.sign_output_channel,
            self.id,
            public,
        );

        let sign_terminal_state = sign_fsm.run()?;

        let did_url = document.did_url();

        // Create a iota signature logger
        let iota_logger = new_node_signature_logger(
            self.protocol_params.own_did_url.clone(),
            did_url.clone(),
            self.network_params.network.clone(),
            self.keypair.clone(),
        );

        if let SignTerminalStates::Completed(signature, processed_partial_owners, bad_signers) =
            sign_terminal_state
        {
            log::info!("committee's DID has been signed");
            // Publish DKG signature log
            let (mut dkg_log, mut working_nodes) = new_signature_log(
                "dkg".to_string(),
                processed_partial_owners,
                bad_signers,
                did_urls.clone(),
                self.network_params.node_url.clone(),
            )?;
            iota_logger.publish(&mut dkg_log, self.network_params.node_url.clone())?;

            log::info!("committee's DID is: {}", did_url);
            // Publish signed DID if the node is the first on the list
            working_nodes.sort();
            if self.protocol_params.own_did_url == working_nodes[0] {
                log::info!("publishing committee's DID...");
                document.publish(&signature.to_vec(), self.network_params.node_url.clone())?;
                log::info!("committee's DID has been published");
                //let resolved_did = resolve_document(did_url.clone())?;
            }

            self.run_api_node(did_url, storage, dkg, iota_logger, did_urls)?;
            Ok(())
        } else {
            log::error!("could not sign committee's DID");
            self.run_api_node(did_url, storage, dkg, iota_logger, did_urls)?;
            Ok(())
        }
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
        let api_index = binding.split(':').last().unwrap();
        let mut api_input = Listener::new(
            self.network_params
                .network
                .clone()
                .try_into()
                .map_err(|_| anyhow::Error::msg("invalid iota network"))?,
            self.network_params.node_url.clone(),
        )?;
        let api_output = Publisher::new(
            self.network_params
                .network
                .clone()
                .try_into()
                .map_err(|_| anyhow::Error::msg("invalid iota network"))?,
            self.network_params.node_url.clone(),
        )?;
        let api_params = ApiParams {
            iota_client: crate::dlt::iota::client::iota_client(
                &self.network_params.network.to_string(),
                self.network_params.node_url.clone(),
            )?,
            dkg,
            secret: self.keypair.private.clone(),
            public_key: self.keypair.public.clone(),
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
                    &self.channels.sign_output_channel,
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
