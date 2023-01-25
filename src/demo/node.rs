use std::sync::mpsc::{Receiver, Sender};

use crate::api::routes::delete::{DeleteRequest, DeleteResponse};
use crate::api::routes::get::{GetError, GetRequest, GetResponse};
use crate::api::routes::save::{StoreError, StoreRequest, StoreResponse};
use crate::api::routes::NodeMessage;
use crate::did::{new_document, resolve_document};
use crate::dkg::{DistPublicKey, DkgMessage, DkgTerminalStates, Initializing};
use crate::net::broadcast::LocalBroadcast;
use crate::states::dkg::InitializingIota;
use crate::states::feed::{Feed, MessageWrapper};
use crate::states::fsm::{StateMachine, StateMachineTypes};
use crate::store::Storage;
use anyhow::bail;
use identity_iota::iota_core::{self, MessageId};
use iota_client::Client;
use kyber_rs::encoding::BinaryMarshaler;
use kyber_rs::group::edwards25519::{Scalar, SuiteEd25519};
use kyber_rs::share::dkg::rabin::DistKeyGenerator;

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
        let secret = self.keypair.private.clone();
        let public = self.keypair.public.clone();
        let dkg_initial_state = Initializing::new(self.keypair, did_url, num_participants);
        let mut dkg_fsm = StateMachine::new(
            Box::new(dkg_initial_state),
            Feed::new(self.dkg_input_channel, public.clone()),
            self.dkg_output_channel,
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

        let mut sign_fsm = StateMachine::new(
            Box::new(sign_initial_state),
            Feed::new(self.sign_input_channel, public.clone()),
            self.sign_output_channel,
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
        let dkg_initial_state =
            InitializingIota::new(self.keypair, own_did_url, did_urls, num_participants)?;
        let mut dkg_fsm = StateMachine::new(
            Box::new(dkg_initial_state),
            Feed::new(self.dkg_input_channel, public.clone()),
            self.dkg_output_channel,
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

        let sign_initial_state = sign::InitializingBuilder::try_from(dkg)?
            .with_message(document.to_bytes()?)
            .with_secret(secret)
            .with_sender(signature_sender)
            .with_sleep_time(signature_sleep_time)
            .build()?;

        let mut sign_fsm = StateMachine::new(
            Box::new(sign_initial_state),
            Feed::new(self.sign_input_channel, public.clone()),
            self.sign_output_channel,
            self.id,
            public,
        );

        let sign_terminal_state = sign_fsm.run()?;

        if let SignTerminalStates::Completed(signature, processed_partial_owners, bad_signers) =
            sign_terminal_state
        {
            // find out who didn't send a partial signature
            let mut working_nodes = vec![];
            for owner in processed_partial_owners {
                working_nodes.push(public_to_did(&did_urls, owner)?);
            }
            let mut absent_nodes = did_urls.clone();
            for worker in working_nodes {
                absent_nodes.retain(|x| *x != worker);
            }

            // find out who was a bad signer
            let mut bad_signers_nodes = vec![];
            for owner in bad_signers {
                bad_signers_nodes.push(public_to_did(&did_urls, owner)?);
            }
            log::info!("Signature success. Nodes that didn't participate: {:?}. Nodes that didn't provide a correct signature: {:?}", absent_nodes, bad_signers_nodes);

            // Publish signed DID
            let did_url = document.did_url();
            document.publish(&signature.to_vec())?;
            log::info!("Committee's DID has been published, DID URL: {}", did_url);

            let resolved_did = resolve_document(did_url.clone())?;

            if let Some(strg) = storage {
                strg.put(did_url, &resolved_did.to_bytes()?)?;
            }

            Ok((signature, dist_pub_key))
        } else {
            let did_url = document.did_url();
            log::info!("Could not sign committee's DID, DID URL: {}", did_url);
            Ok((Signature::from(vec![]), dist_pub_key))
        }
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
    storage: Storage,
    iota_client: Client,
    dkg: DistKeyGenerator<SuiteEd25519>,
    secret: Scalar,
    nodes_input: tokio::sync::broadcast::Sender<MessageWrapper<SignMessage>>,
    nodes_output: Sender<MessageWrapper<SignMessage>>,
    public_key: Point,
    id: usize,
}

impl ApiNode {
    pub fn handle_message(
        &self,
        message: NodeMessage,
    ) -> Result<Option<NodeMessage>, ApiNodeError> {
        match message {
            NodeMessage::StoreRequest(r) => Ok(Some(self.handle_store_request(r)?)),
            NodeMessage::GetRequest(r) => Ok(Some(self.handle_get_request(r)?)),
            NodeMessage::DeleteRequest(r) => Ok(Some(self.handle_delete_request(r)?)),
            _ => todo!(),
        }
    }

    fn handle_store_request(&self, request: StoreRequest) -> Result<NodeMessage, ApiNodeError> {
        let rt = tokio::runtime::Runtime::new()?;
        let raw_message_id: &[u8; 32] = request.message_id.as_bytes().try_into()?;
        let message_id = MessageId::from(*raw_message_id);
        let message = rt.block_on(self.iota_client.get_message().data(&message_id))?;
        let payload = match message.payload() {
            Some(p) => p,
            None => return Err(ApiNodeError::MissingPayload(message_id)),
        };
        let indexation_payload = match payload {
            iota_client::bee_message::prelude::Payload::Indexation(i) => i,
            _ => return Err(ApiNodeError::UnsupportedPayload),
        };
        match self
            .storage
            .put(request.message_id, indexation_payload.data())
        {
            Ok(()) => Ok(NodeMessage::StoreResponse(StoreResponse::Success(
                "done".to_owned(),
            ))),
            Err(e) => Ok(NodeMessage::StoreResponse(StoreResponse::Failure(
                StoreError::StorageError(e.to_string()),
            ))),
        }
    }

    fn handle_get_request(&self, request: GetRequest) -> Result<NodeMessage, ApiNodeError> {
        let data = match self.storage.get(request.message_id) {
            Ok(d) => d,
            Err(e) => return Err(ApiNodeError::StorageError(e)),
        };

        let mut sign_fsm = self.get_sign_fsm(&data)?;
        let final_state = match sign_fsm.run() {
            Ok(state) => state,
            Err(e) => return Err(ApiNodeError::SignatureError(e)),
        };

        match final_state {
            SignTerminalStates::Completed(signature, ..) => {
                let response = GetResponse::Success {
                    signature: signature.to_vec(),
                    data,
                };

                Ok(NodeMessage::GetResponse(response))
            }
            SignTerminalStates::Failed => {
                log::error!("Sign failed");
                Ok(NodeMessage::GetResponse(GetResponse::Failure(
                    GetError::Message("Sign failed".to_owned()),
                )))
            }
        }
    }

    fn handle_delete_request(&self, reqeust: DeleteRequest) -> Result<NodeMessage, ApiNodeError> {
        match self.storage.delete(reqeust.message_id) {
            Ok(()) => (),
            Err(e) => return Err(ApiNodeError::StorageError(e)),
        };
        let response = DeleteResponse::Success;
        Ok(NodeMessage::DeleteResponse(response))
    }

    fn get_sign_fsm(&self, message: &[u8]) -> Result<FSM, ApiNodeError> {
        let sign_initial_state = sign::InitializingBuilder::try_from(self.dkg.clone())
            .map_err(ApiNodeError::SignatureError)?
            .with_message(message.into())
            .with_secret(self.secret.clone())
            .build()
            .map_err(ApiNodeError::SignatureError)?;

        Ok(StateMachine::new(
            Box::new(sign_initial_state),
            Feed::new(self.nodes_input.subscribe(), self.public_key.clone()),
            self.nodes_output.clone(),
            self.id,
            self.public_key.clone(),
        ))
    }
}

type FSM = StateMachine<SignTypes, tokio::sync::broadcast::Receiver<MessageWrapper<SignMessage>>>;

pub enum ApiNodeError {
    AsyncRuntimeError(std::io::Error),
    InvalidMessageId(std::array::TryFromSliceError),
    IotaError(iota_client::Error),
    MissingPayload(MessageId),
    UnsupportedPayload,
    StorageError(anyhow::Error),
    SignatureError(anyhow::Error),
}

impl From<std::io::Error> for ApiNodeError {
    fn from(value: std::io::Error) -> Self {
        Self::AsyncRuntimeError(value)
    }
}

impl From<std::array::TryFromSliceError> for ApiNodeError {
    fn from(value: std::array::TryFromSliceError) -> Self {
        Self::InvalidMessageId(value)
    }
}

impl From<iota_client::Error> for ApiNodeError {
    fn from(value: iota_client::Error) -> Self {
        Self::IotaError(value)
    }
}
