use std::io::Read;
use std::str::{FromStr, Utf8Error};
use std::sync::mpsc::{Receiver, Sender};

use crate::api::routes::delete::{DeleteRequest, DeleteResponse};
use crate::api::routes::get::{GetError, GetRequest, GetResponse};
use crate::api::routes::request::{
    self, DoraLocalUri, GenericResponse, InputUri, IotaMessageUri, StorageUri,
};
use crate::api::routes::save::{StoreError, StoreRequest, StoreResponse};
use crate::api::routes::{GenericRequest, NodeMessage};
use crate::did::{new_document, resolve_document};
use crate::dkg::{DistPublicKey, DkgMessage, DkgTerminalStates, Initializing};
use crate::dlt::iota::{Listener, Publisher};
use crate::net::broadcast::LocalBroadcast;
use crate::states::dkg::InitializingIota;
use crate::states::feed::{Feed, MessageWrapper};
use crate::states::fsm::{StateMachine, StateMachineTypes};
use crate::store::Storage;
use anyhow::bail;
use enum_display::EnumDisplay;
use identity_iota::core::ToJson;
use identity_iota::iota_core::MessageId;
use identity_iota::iota_core::Network;
use iota_client::Client;
use kyber_rs::encoding::{BinaryMarshaler, Marshaling, MarshallingError};
use kyber_rs::group::edwards25519::{Scalar, SuiteEd25519};
use kyber_rs::share::dkg::rabin::DistKeyGenerator;
use kyber_rs::sign::eddsa::{self, EdDSA};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::states::sign::{self, SignMessage, SignTerminalStates, SignTypes, Signature};
use kyber_rs::{group::edwards25519::Point, util::key::Pair};

pub struct Node {
    keypair: Pair<Point>,
    dkg_input_channel: Receiver<MessageWrapper<DkgMessage>>,
    sign_input_channel: Receiver<MessageWrapper<SignMessage>>,
    dkg_output_channel: Sender<MessageWrapper<DkgMessage>>,
    sign_output_channel: Sender<MessageWrapper<SignMessage>>,
    id: usize,
}

impl Node {
    pub fn new(
        keypair: Pair<Point>,
        dkg_input_channel: Receiver<MessageWrapper<DkgMessage>>,
        dkg_output_channel: Sender<MessageWrapper<DkgMessage>>,
        sign_input_channel: Receiver<MessageWrapper<SignMessage>>,
        sign_output_channel: Sender<MessageWrapper<SignMessage>>,
        id: usize,
    ) -> Self {
        Self {
            keypair,
            dkg_input_channel,
            sign_input_channel,
            dkg_output_channel,
            sign_output_channel,
            id,
        }
    }

    pub fn new_local(
        keypair: Pair<Point>,
        index: usize,
        dkg_broadcast: &mut LocalBroadcast<MessageWrapper<DkgMessage>>,
        sign_broadcast: &mut LocalBroadcast<MessageWrapper<SignMessage>>,
    ) -> Node {
        let (dkg_input_sender, dkg_input_receiver) = std::sync::mpsc::channel();
        dkg_broadcast.add_sender_of_receiving_channel(dkg_input_sender);

        let (sign_input_sender, sign_input_receiver) = std::sync::mpsc::channel();
        sign_broadcast.add_sender_of_receiving_channel(sign_input_sender);

        Node::new(
            keypair,
            dkg_input_receiver,
            dkg_broadcast.get_broadcast_sender(),
            sign_input_receiver,
            sign_broadcast.get_broadcast_sender(),
            index,
        )
    }

    pub fn run(
        self,
        storage: Option<Storage>,
        did_network: Option<String>,
        did_url: Option<String>,
        num_participants: usize,
        signature_sender: Sender<MessageWrapper<SignMessage>>,
        signature_sleep_time: u64,
    ) -> Result<(Signature, DistPublicKey), anyhow::Error> {
        let dkg_id = "First DKG";
        let secret = self.keypair.private.clone();
        let public = self.keypair.public.clone();
        let dkg_initial_state = Initializing::new(self.keypair.clone(), did_url, num_participants);
        let dkg_feed = Feed::new(&self.dkg_input_channel, dkg_id.to_string());
        let mut dkg_fsm = StateMachine::new(
            Box::new(dkg_initial_state),
            dkg_id.to_string(),
            dkg_feed,
            &self.dkg_output_channel,
            self.id,
            public.clone(),
        );
        let dkg_terminal_state = dkg_fsm.run()?;
        let DkgTerminalStates::Completed { dkg, did_urls } = dkg_terminal_state;
        let dist_pub_key = dkg.dist_key_share()?.public();

        let mut nodes_dids = None;
        let mut network = "iota-dev".to_owned();
        if let Some(net) = did_network.clone() {
            network = net;
            nodes_dids = Some(did_urls);
        }

        // Create unsigned DID
        let document = new_document(
            &dist_pub_key.marshal_binary()?,
            &network,
            Some(20),
            nodes_dids,
        )?;

        let sign_initial_state = sign::InitializingBuilder::try_from(dkg)?
            .with_message(document.to_bytes()?)
            .with_secret(secret)
            .with_sender(signature_sender)
            .with_sleep_time(signature_sleep_time)
            .build()?;

        let sign_feed = Feed::new(&self.sign_input_channel, dkg_id.to_string());
        let mut sign_fsm = StateMachine::new(
            Box::new(sign_initial_state),
            dkg_id.to_owned(),
            sign_feed,
            &self.sign_output_channel,
            self.id,
            public,
        );

        let sign_terminal_state = sign_fsm.run()?;

        if let SignTerminalStates::Completed(signature, _processed_partial_owners, _bad_signers) =
            sign_terminal_state
        {
            if did_network.is_some() {
                // Publish signed DID
                let did_url = document.did_url();
                document.publish(&signature.to_vec())?;
                log::info!("Committee's DID has been published, DID URL: {}", did_url);

                let resolved_did = resolve_document(did_url.clone())?;

                if let Some(strg) = storage {
                    strg.put(did_url, &resolved_did.to_bytes()?)?;
                }
            }
            Ok((signature, dist_pub_key))
        } else {
            let did_url = document.did_url();
            log::info!("Could not sign committee's DID, DID URL: {}", did_url);
            Ok((Signature::from(vec![]), dist_pub_key))
        }
    }

    pub fn run_iota(
        self,
        storage: Option<Storage>,
        did_network: String,
        own_did_url: String,
        did_urls: Vec<String>,
        num_participants: usize,
        time_resolution: usize,
        signature_sender: Sender<MessageWrapper<SignMessage>>,
        signature_sleep_time: u64,
    ) -> Result<(Signature, DistPublicKey), anyhow::Error> {
        let secret = self.keypair.private.clone();
        let public = self.keypair.public.clone();
        let dkg_id = "First DKG";
        let dkg_initial_state = InitializingIota::new(
            self.keypair.clone(),
            own_did_url.clone(),
            did_urls,
            num_participants,
        )?;
        let mut dkg_fsm = StateMachine::new(
            Box::new(dkg_initial_state),
            dkg_id.to_owned(),
            Feed::new(&self.dkg_input_channel, dkg_id.to_string()),
            &self.dkg_output_channel,
            self.id,
            public.clone(),
        );
        let dkg_terminal_state = dkg_fsm.run()?;
        let DkgTerminalStates::Completed { dkg, did_urls } = dkg_terminal_state;
        let dist_pub_key = dkg.dist_key_share()?.public();

        // Create unsigned DID
        let document = new_document(
            &dist_pub_key.marshal_binary()?,
            &did_network,
            Some(time_resolution as u32),
            Some(did_urls.clone()),
        )?;

        let sign_initial_state = sign::InitializingBuilder::try_from(dkg.clone())?
            .with_message(document.to_bytes()?)
            .with_secret(secret)
            .with_sender(signature_sender.clone())
            .with_sleep_time(signature_sleep_time)
            .with_id(dkg_id.to_string())
            .build()?;

        let mut sign_fsm = StateMachine::new(
            Box::new(sign_initial_state),
            dkg_id.to_owned(),
            Feed::new(&self.sign_input_channel, dkg_id.to_string()),
            &self.sign_output_channel,
            self.id,
            public,
        );

        let sign_terminal_state = sign_fsm.run()?;

        let did_url = document.did_url();

        // Create a iota signature logger
        let iota_logger = new_node_signature_logger(
            own_did_url.clone(),
            did_url.clone(),
            did_network.clone(),
            self.keypair.clone(),
        );

        if let SignTerminalStates::Completed(signature, processed_partial_owners, bad_signers) =
            sign_terminal_state
        {
            // Publish DKG signature log
            let (mut dkg_log, mut working_nodes) = new_signature_log(
                "First DKG".to_string(),
                processed_partial_owners,
                bad_signers,
                did_urls.clone(),
            )?;
            iota_logger.publish(&mut dkg_log)?;

            // Publish signed DID if the node is the first on the list
            working_nodes.sort();
            if own_did_url == working_nodes[0] {
                document.publish(&signature.to_vec())?;
                log::info!("Committee's DID has been published, DID URL: {}", did_url);
                //let resolved_did = resolve_document(did_url.clone())?;
            }

            self.run_api_node(
                did_url,
                own_did_url,
                storage,
                dkg,
                did_network,
                signature_sender,
                signature_sleep_time,
                iota_logger,
                did_urls,
            )?;
            Ok((signature, dist_pub_key))
        } else {
            log::info!("Could not sign committee's DID, DID URL: {}", did_url);
            self.run_api_node(
                did_url,
                own_did_url,
                storage,
                dkg,
                did_network,
                signature_sender,
                signature_sleep_time,
                iota_logger,
                did_urls,
            )?;
            Ok((Signature::from(vec![]), dist_pub_key))
        }
    }

    fn run_api_node(
        &self,
        did_url: String,
        own_did_url: String,
        storage: Option<Storage>,
        dkg: DistKeyGenerator<SuiteEd25519>,
        network_name: String,
        signature_sender: Sender<MessageWrapper<SignMessage>>,
        signature_sleep_time: u64,
        logger: NodeSignatureLogger,
        did_urls: Vec<String>,
    ) -> Result<(), anyhow::Error> {
        let network = match network_name.as_str() {
            "iota-main" => Network::Mainnet,
            "iota-dev" => Network::Devnet,
            _ => panic!("unsupported network"),
        };
        let api_index = did_url.split(':').last().unwrap();
        let mut api_input = Listener::new(network.clone())?;
        let api_output = Publisher::new(network.clone())?;
        let api_node = ApiNode {
            storage: storage.unwrap(),
            iota_client: crate::dlt::iota::client::iota_client(network.name_str())?,
            dkg,
            secret: self.keypair.private.clone(),
            public_key: self.keypair.public.clone(),
            id: self.id,
            signature_sender,
            signature_sleep_time,
        };
        let rt = tokio::runtime::Runtime::new()?;
        log::info!("Listening for committee requests on index: {}", api_index);
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
            log::info!("Received committee request: {:?}", request);
            let response = match api_node
                .handle_message(
                    request,
                    &self.sign_input_channel,
                    &self.sign_output_channel,
                    &req_id.to_string(),
                    logger.clone(),
                    did_urls.clone(),
                )
                .map_err(|e| anyhow::Error::msg(format!("{:?}", e)))
            {
                Ok(r) => r,
                Err(e) => {
                    log::error!("Could not handle request: {}", e);
                    continue;
                }
            };
            if let Some((r, working_nodes)) = response {
                let encoded = serde_json::to_vec(&r)?;
                let mut wn = working_nodes.clone();
                // Publish signed DID if the node is the first on the list
                wn.sort();
                if own_did_url == wn[0] {
                    match rt.block_on(api_output.publish(&encoded, Some(api_index.to_owned()))) {
                        Ok(i) => log::info!("Published response on: {}", i),
                        Err(e) => log::error!("Could not publish response: {}", e),
                    };
                }
            }
        }
        Ok(())
    }
}

fn public_to_did(did_urls: &[String], public_key: Point) -> anyhow::Result<String> {
    for did_url in did_urls.iter() {
        if resolve_document(did_url.to_string())?.public_key()? == public_key {
            return Ok(did_url.to_string());
        }
    }
    bail!("could not find the offending DID")
}

struct ApiNode {
    pub storage: Storage,
    pub iota_client: Client,
    pub dkg: DistKeyGenerator<SuiteEd25519>,
    pub secret: Scalar,
    pub public_key: Point,
    pub id: usize,
    signature_sender: Sender<MessageWrapper<SignMessage>>,
    signature_sleep_time: u64,
}

impl ApiNode {
    pub fn handle_message(
        &self,
        message: NodeMessage,
        nodes_input: &Receiver<MessageWrapper<SignMessage>>,
        nodes_output: &Sender<MessageWrapper<SignMessage>>,
        session_id: &str,
        signature_logger: NodeSignatureLogger,
        did_urls: Vec<String>,
    ) -> Result<Option<(GenericResponse, Vec<String>)>, ApiNodeError> {
        match message {
            NodeMessage::StoreRequest(r) => Ok(Some(self.handle_store_request(
                r,
                session_id,
                signature_logger,
                did_urls,
                nodes_input,
                nodes_output,
            )?)),
            NodeMessage::GetRequest(r) => Ok(Some(self.handle_get_request(
                r,
                nodes_input,
                nodes_output,
                session_id,
                signature_logger,
                did_urls,
            )?)),
            NodeMessage::DeleteRequest(r) => Ok(Some(self.handle_delete_request(
                r,
                signature_logger,
                did_urls,
            )?)),
            m => {
                log::warn!("Skipping unsupported request: {:?}", m);
                Ok(None)
            }
        }
    }

    fn handle_store_request(
        &self,
        request: StoreRequest,
        session_id: &str,
        logger: NodeSignatureLogger,
        did_urls: Vec<String>,
        sign_input: &Receiver<MessageWrapper<SignMessage>>,
        sign_output: &Sender<MessageWrapper<SignMessage>>,
    ) -> Result<(GenericResponse, Vec<String>), ApiNodeError> {
        let data = self.get_data(&request.input)?;
        if let StorageUri::Dora(DoraLocalUri(item_name)) = request.storage_uri {
            match self.storage.put(item_name, &data) {
                Ok(()) => {
                    let mut resp = GenericResponse {
                        request_id: request::RequestId(session_id.to_owned()),
                        result: request::ResponseState::Success,
                        signature: request::Signature(vec![]),
                        output_location: None,
                        data: None,
                    };
                    let temp_resp_bytes = resp.to_jcs().unwrap();
                    let mut sign_fsm = self.get_sign_fsm(
                        &temp_resp_bytes,
                        session_id.to_string(),
                        sign_input,
                        sign_output,
                    )?;
                    let final_state = match sign_fsm.run() {
                        Ok(state) => state,
                        Err(e) => return Err(ApiNodeError::SignatureError(e)),
                    };
                    let (signature, working_nodes) =
                        manage_signature_terminal_state(final_state, session_id, did_urls, logger)
                            .map_err(ApiNodeError::SignatureError)?;
                    resp.signature = request::Signature(signature.0);

                    Ok((resp, working_nodes))
                }
                Err(_) => {
                    let mut resp = GenericResponse {
                        request_id: request::RequestId(session_id.to_owned()),
                        result: request::ResponseState::Failure,
                        signature: request::Signature(vec![]),
                        output_location: None,
                        data: None,
                    };
                    let temp_resp_bytes = resp.to_jcs().unwrap();
                    let mut sign_fsm = self.get_sign_fsm(
                        &temp_resp_bytes,
                        session_id.to_string(),
                        sign_input,
                        sign_output,
                    )?;
                    let final_state = match sign_fsm.run() {
                        Ok(state) => state,
                        Err(e) => return Err(ApiNodeError::SignatureError(e)),
                    };
                    let (signature, working_nodes) =
                        manage_signature_terminal_state(final_state, session_id, did_urls, logger)
                            .map_err(ApiNodeError::SignatureError)?;
                    resp.signature = request::Signature(signature.0);

                    Ok((resp, working_nodes))
                }
            }
        } else {
            Err(ApiNodeError::StorageError(anyhow::Error::msg(
                "Storage not supported",
            )))
        }
    }

    fn handle_get_request(
        &self,
        request: GetRequest,
        sign_input: &Receiver<MessageWrapper<SignMessage>>,
        sign_output: &Sender<MessageWrapper<SignMessage>>,
        session_id: &str,
        logger: NodeSignatureLogger,
        did_urls: Vec<String>,
    ) -> Result<(GenericResponse, Vec<String>), ApiNodeError> {
        let data = match self.get_data(&request.input) {
            Ok(d) => d,
            Err(e) => {
                let mut resp = GenericResponse {
                    request_id: request::RequestId(session_id.to_owned()),
                    result: request::ResponseState::Failure,
                    signature: request::Signature(vec![]),
                    output_location: None,
                    data: None,
                };
                let temp_resp_bytes = resp.to_jcs().unwrap();
                let mut sign_fsm = self.get_sign_fsm(
                    &temp_resp_bytes,
                    session_id.to_string(),
                    sign_input,
                    sign_output,
                )?;
                let final_state = match sign_fsm.run() {
                    Ok(state) => state,
                    Err(e) => return Err(ApiNodeError::SignatureError(e)),
                };
                let (signature, working_nodes) =
                    manage_signature_terminal_state(final_state, session_id, did_urls, logger)
                        .map_err(ApiNodeError::SignatureError)?;
                resp.signature = request::Signature(signature.0);

                return Ok((resp, working_nodes));
            }
        };

        let data_utf8 = match std::str::from_utf8(&data) {
            Ok(text) => text.to_string(),
            Err(e) => return Err(ApiNodeError::ConversionError(e)),
        };

        let mut resp = GenericResponse {
            request_id: request::RequestId(session_id.to_owned()),
            result: request::ResponseState::Success,
            signature: request::Signature(vec![]),
            output_location: None,
            data: Some(data_utf8),
        };
        let temp_resp_bytes = resp.to_jcs().unwrap();
        let mut sign_fsm = self.get_sign_fsm(
            &temp_resp_bytes,
            session_id.to_string(),
            sign_input,
            sign_output,
        )?;
        let final_state = match sign_fsm.run() {
            Ok(state) => state,
            Err(e) => return Err(ApiNodeError::SignatureError(e)),
        };
        let (signature, working_nodes) =
            manage_signature_terminal_state(final_state, session_id, did_urls, logger)
                .map_err(ApiNodeError::SignatureError)?;
        resp.signature = request::Signature(signature.0);

        Ok((resp, working_nodes))
    }

    fn handle_delete_request(
        &self,
        request: DeleteRequest,
        logger: NodeSignatureLogger,
        did_urls: Vec<String>,
    ) -> Result<(GenericResponse, Vec<String>), ApiNodeError> {
        match self.storage.delete(request.message_id) {
            Ok(()) => (),
            Err(e) => return Err(ApiNodeError::StorageError(e)),
        };
        let response = DeleteResponse::Success;
        Ok((
            NodeMessage::DeleteResponse(response).try_into().unwrap(),
            vec![],
        ))
    }

    fn get_data(&self, location: &InputUri) -> Result<Vec<u8>, ApiNodeError> {
        let data = match location {
            InputUri::Iota(uri) => match uri {
                IotaMessageUri(index) => {
                    let rt = tokio::runtime::Runtime::new()?;
                    let message_id = MessageId::from_str(index)
                        .map_err(|e| ApiNodeError::InvalidMessageId(e.into()))?;
                    let message = rt.block_on(self.iota_client.get_message().data(&message_id))?;
                    let payload = match message.payload() {
                        Some(p) => p,
                        None => return Err(ApiNodeError::MissingPayload(message_id)),
                    };
                    let indexation_payload = match payload {
                        iota_client::bee_message::prelude::Payload::Indexation(i) => i,
                        _ => return Err(ApiNodeError::UnsupportedPayload),
                    };
                    indexation_payload.data().to_vec()
                }
            },
            InputUri::Local(uri) => match uri {
                DoraLocalUri(index) => self
                    .storage
                    .get(index.to_owned())
                    .map_err(ApiNodeError::StorageError)?,
            },
            InputUri::Literal(s) => s.as_bytes().to_vec(),
            InputUri::Url(u) => get_data_from_url(u)?,
        };
        Ok(data)
    }

    fn get_sign_fsm<'a>(
        &self,
        message: &[u8],
        session_id: String,
        sign_input: &'a Receiver<MessageWrapper<SignMessage>>,
        sign_output: &'a Sender<MessageWrapper<SignMessage>>,
    ) -> Result<FSM<'a>, ApiNodeError> {
        let sign_initial_state = sign::InitializingBuilder::try_from(self.dkg.clone())
            .map_err(ApiNodeError::SignatureError)?
            .with_message(message.into())
            .with_secret(self.secret.clone())
            .with_sender(self.signature_sender.clone())
            .with_sleep_time(self.signature_sleep_time)
            .with_id(session_id.clone())
            .build()
            .map_err(ApiNodeError::SignatureError)?;

        let fsm = StateMachine::new(
            Box::new(sign_initial_state),
            session_id.clone(),
            Feed::new(sign_input, session_id),
            sign_output,
            self.id,
            self.public_key.clone(),
        );
        Ok(fsm)
    }
}

fn get_data_from_url(url: &Url) -> Result<Vec<u8>, ApiNodeError> {
    let mut body = Vec::new();
    let _ = reqwest::blocking::get(url.as_str())
        .map_err(|e| ApiNodeError::HttpError(anyhow::Error::msg(format!("{}", e))))?
        .read_to_end(&mut body)?;
    Ok(body)
}

type FSM<'a> = StateMachine<'a, SignTypes, &'a Receiver<MessageWrapper<SignMessage>>>;

#[derive(Debug, EnumDisplay)]
pub enum ApiNodeError {
    AsyncRuntimeError(std::io::Error),
    InvalidMessageId(anyhow::Error),
    IotaError(iota_client::Error),
    MissingPayload(MessageId),
    UnsupportedPayload,
    StorageError(anyhow::Error),
    SignatureError(anyhow::Error),
    ConversionError(Utf8Error),
    LogError(anyhow::Error),
    HttpError(anyhow::Error),
}

impl std::error::Error for ApiNodeError {}

impl From<std::io::Error> for ApiNodeError {
    fn from(value: std::io::Error) -> Self {
        Self::AsyncRuntimeError(value)
    }
}

impl From<iota_client::Error> for ApiNodeError {
    fn from(value: iota_client::Error) -> Self {
        Self::IotaError(value)
    }
}

#[derive(Clone)]
pub struct NodeSignatureLogger {
    own_did_url: String,
    committee_index: String,
    network: String,
    keypair: Pair<Point>,
}

pub fn new_node_signature_logger(
    own_did_url: String,
    committee_did_url: String,
    network: String,
    keypair: Pair<Point>,
) -> NodeSignatureLogger {
    NodeSignatureLogger {
        own_did_url,
        committee_index: committee_did_url.split(':').last().unwrap().to_string(),
        network,
        keypair,
    }
}

impl NodeSignatureLogger {
    pub fn publish(&self, log: &mut NodeSignatureLog) -> anyhow::Result<()> {
        let network = match self.network.as_str() {
            "iota-main" => Network::Mainnet,
            "iota-dev" => Network::Devnet,
            _ => panic!("unsupported network"),
        };
        let publisher = Publisher::new(network)?;
        self.sign_log(log)?;

        let msg_id = tokio::runtime::Runtime::new()?
            .block_on(publisher.publish(&log.to_jcs()?, Some(self.committee_index.clone())))?;
        log::info!("Log published (msg_id: {})", msg_id);
        Ok(())
    }

    fn sign_log(&self, log: &mut NodeSignatureLog) -> anyhow::Result<()> {
        let eddsa = EdDSA::from(self.keypair.clone());
        log.add_sender(&self.own_did_url);
        log.add_signature(&eddsa.sign(&log.to_bytes()?)?);
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeSignatureLog {
    session_id: String,
    sender: String,
    absent_nodes: Vec<String>,
    bad_signers: Vec<String>,
    signature: Vec<u8>,
}

pub fn new_signature_log(
    session_id: String,
    processed_partial_owners: Vec<Point>,
    bad_signers: Vec<Point>,
    did_urls: Vec<String>,
) -> anyhow::Result<(NodeSignatureLog, Vec<String>)> {
    // find out who didn't send a partial signature
    let mut working_nodes = vec![];
    for owner in processed_partial_owners {
        working_nodes.push(public_to_did(&did_urls, owner)?);
    }
    let mut absent_nodes = did_urls.clone();
    for worker in working_nodes.clone() {
        absent_nodes.retain(|x| *x != worker);
    }

    // find out who was a bad signer
    let mut bad_signers_nodes = vec![];
    for owner in bad_signers {
        bad_signers_nodes.push(public_to_did(&did_urls, owner)?);
    }

    log::info!("Signature success. Nodes that didn't participate: {:?}. Nodes that didn't provide a correct signature: {:?}", absent_nodes, bad_signers_nodes);
    Ok((
        NodeSignatureLog {
            session_id,
            sender: "".to_string(),
            absent_nodes,
            bad_signers: bad_signers_nodes,
            signature: vec![],
        },
        working_nodes,
    ))
}

impl NodeSignatureLog {
    fn add_sender(&mut self, sender: &str) {
        self.sender = sender.to_string();
    }

    fn add_signature(&mut self, signature: &[u8]) {
        self.signature = signature.to_vec();
    }

    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        match bincode::serialize(self) {
            Ok(v) => Ok(v),
            Err(e) => {
                bail!(MarshallingError::Serialization(e))
            }
        }
    }
}

fn manage_signature_terminal_state(
    final_state: SignTerminalStates,
    session_id: &str,
    did_urls: Vec<String>,
    logger: NodeSignatureLogger,
) -> anyhow::Result<(Signature, Vec<String>)> {
    match final_state {
        SignTerminalStates::Completed(signature, processed_partial_owners, bad_signers) => {
            let (mut log, working_nodes) = new_signature_log(
                session_id.to_string(),
                processed_partial_owners,
                bad_signers,
                did_urls,
            )
            .map_err(ApiNodeError::LogError)?;
            logger.publish(&mut log).map_err(ApiNodeError::LogError)?;

            Ok((signature, working_nodes))
        }
        SignTerminalStates::Failed => {
            log::error!("Sign failed");
            Err(anyhow::Error::msg("Sign Failed"))
        }
    }
}
