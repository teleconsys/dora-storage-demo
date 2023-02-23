use std::{
    io::Read,
    str::{FromStr, Utf8Error},
    sync::mpsc::{Receiver, Sender},
};

use enum_display::EnumDisplay;
use identity_iota::{core::ToJson, iota_core::MessageId};
use iota_client::Client;
use kyber_rs::{
    group::edwards25519::{Point, Scalar, SuiteEd25519},
    share::dkg::rabin::DistKeyGenerator,
};

use crate::{
    logging::{new_signature_log, signature_log_target, NodeSignatureLogger},
    states::{
        feed::{Feed, MessageWrapper},
        fsm::StateMachine,
        sign::{self, SignMessage, SignTerminalStates, SignTypes, Signature},
    },
    store::Storage,
};

use super::{
    messages::{self, CommitteeLog, InputUri, IotaMessageUri, StorageLocalUri, StorageUri},
    GenericRequest, NodeMessage,
};
use url::Url;

pub struct ApiParams {
    pub iota_client: Client,
    pub dkg: DistKeyGenerator<SuiteEd25519>,
    pub secret: Scalar,
    pub public_key: Point,
    pub id: usize,
    pub(crate) signature_sender: Sender<MessageWrapper<SignMessage>>,
    pub(crate) signature_sleep_time: u64,
}

pub struct HandlerParams {
    pub signature_logger: NodeSignatureLogger,
    pub committee_did: String,
    pub dids: Vec<String>,
    pub node_url: Option<String>,
}

pub struct ApiNode {
    pub storage: Storage,
    pub api_params: ApiParams,
}

impl ApiNode {
    pub fn handle_message(
        &self,
        message: NodeMessage,
        nodes_input: &Receiver<MessageWrapper<SignMessage>>,
        nodes_output: &Sender<MessageWrapper<SignMessage>>,
        session_id: &str,
        handler_params: HandlerParams,
    ) -> Result<Option<(CommitteeLog, Vec<String>)>, ApiNodeError> {
        match message {
            NodeMessage::GenericRequest(r) => Ok(Some(self.handle_request(
                r,
                session_id,
                nodes_input,
                nodes_output,
                handler_params,
            )?)),
            m => {
                log::warn!("skipping unsupported request: {:?}", m);
                Ok(None)
            }
        }
    }

    fn handle_request(
        &self,
        request: GenericRequest,
        session_id: &str,
        sign_input: &Receiver<MessageWrapper<SignMessage>>,
        sign_output: &Sender<MessageWrapper<SignMessage>>,
        handler_params: HandlerParams,
    ) -> Result<(CommitteeLog, Vec<String>), ApiNodeError> {
        let mut committee_log = CommitteeLog {
            committee_did: handler_params.committee_did.clone(),
            request_id: messages::RequestId(session_id.to_owned()),
            ..Default::default()
        };

        let data = match self.get_data(&request.input_uri) {
            Ok(d) => d,
            Err(_e) => {
                return self.sign_request_logs(
                    committee_log,
                    session_id.to_owned(),
                    sign_input,
                    sign_output,
                    handler_params,
                );
            }
        };
        match request.storage_uri {
            // in this case it is a store request
            StorageUri::Storage(StorageLocalUri(item_name)) => {
                match self.storage.put(item_name, &data) {
                    Ok(()) => {
                        committee_log.result = messages::ResponseState::Success;
                        self.sign_request_logs(
                            committee_log,
                            session_id.to_owned(),
                            sign_input,
                            sign_output,
                            handler_params,
                        )
                    }

                    Err(_) => self.sign_request_logs(
                        committee_log,
                        session_id.to_owned(),
                        sign_input,
                        sign_output,
                        handler_params,
                    ),
                }
            }
            // in this case it is a get request
            StorageUri::None => {
                let data = match self.get_data(&request.input_uri) {
                    Ok(d) => d,
                    Err(_e) => {
                        return self.sign_request_logs(
                            committee_log,
                            session_id.to_owned(),
                            sign_input,
                            sign_output,
                            handler_params,
                        )
                    }
                };

                let data_utf8 = match std::str::from_utf8(&data) {
                    Ok(text) => text.to_string(),
                    Err(e) => return Err(ApiNodeError::ConversionError(e)),
                };

                committee_log.result = messages::ResponseState::Success;
                committee_log.data = Some(data_utf8);

                self.sign_request_logs(
                    committee_log,
                    session_id.to_owned(),
                    sign_input,
                    sign_output,
                    handler_params,
                )
            }
        }
    }

    fn sign_request_logs(
        &self,
        mut committee_log: CommitteeLog,
        session_id: String,
        sign_input: &Receiver<MessageWrapper<SignMessage>>,
        sign_output: &Sender<MessageWrapper<SignMessage>>,
        handler_params: HandlerParams,
    ) -> Result<(CommitteeLog, Vec<String>), ApiNodeError> {
        let temp_resp_bytes = committee_log.to_jcs().unwrap();
        let mut sign_fsm = self.get_sign_fsm(
            &temp_resp_bytes,
            session_id.clone(),
            sign_input,
            sign_output,
        )?;
        let final_state = match sign_fsm.run() {
            Ok(state) => state,
            Err(e) => return Err(ApiNodeError::SignatureError(e)),
        };
        let (signature, working_nodes) = manage_signature_terminal_state(
            final_state,
            &session_id,
            handler_params.dids,
            handler_params.signature_logger,
            handler_params.node_url,
        )
        .map_err(ApiNodeError::SignatureError)?;
        committee_log.signature_hex = Some(hex::encode(signature.0));

        Ok((committee_log, working_nodes))
    }

    fn get_data(&self, location: &InputUri) -> Result<Vec<u8>, ApiNodeError> {
        let data = match location {
            InputUri::Iota(uri) => match uri {
                IotaMessageUri(index) => {
                    let rt = tokio::runtime::Runtime::new()?;
                    let message_id = MessageId::from_str(index)
                        .map_err(|e| ApiNodeError::InvalidMessageId(e.into()))?;
                    let message =
                        rt.block_on(self.api_params.iota_client.get_message().data(&message_id))?;
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
                StorageLocalUri(index) => self
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
    ) -> Result<Fsm<'a>, ApiNodeError> {
        let sign_initial_state = sign::InitializingBuilder::try_from(self.api_params.dkg.clone())
            .map_err(ApiNodeError::SignatureError)?
            .with_message(message.into())
            .with_secret(self.api_params.secret.clone())
            .with_sender(self.api_params.signature_sender.clone())
            .with_sleep_time(self.api_params.signature_sleep_time)
            .with_id(session_id.clone())
            .build()
            .map_err(ApiNodeError::SignatureError)?;

        let fsm = StateMachine::new(
            Box::new(sign_initial_state),
            session_id.clone(),
            Feed::new(sign_input, session_id),
            sign_output,
            self.api_params.id,
            self.api_params.public_key.clone(),
        );
        Ok(fsm)
    }
}

fn get_data_from_url(url: &Url) -> Result<Vec<u8>, ApiNodeError> {
    let mut body = Vec::new();
    let _ = reqwest::blocking::get(url.as_str())
        .map_err(|e| ApiNodeError::HttpError(anyhow::Error::msg(format!("{e}"))))?
        .read_to_end(&mut body)?;
    Ok(body)
}

type Fsm<'a> = StateMachine<'a, SignTypes, &'a Receiver<MessageWrapper<SignMessage>>>;

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

fn manage_signature_terminal_state(
    final_state: SignTerminalStates,
    session_id: &str,
    dids: Vec<String>,
    logger: NodeSignatureLogger,
    node_url: Option<String>,
) -> anyhow::Result<(Signature, Vec<String>)> {
    match final_state {
        SignTerminalStates::Completed(signature, processed_partial_owners, bad_signers) => {
            let (mut log, working_nodes) = new_signature_log(
                session_id.to_string(),
                processed_partial_owners,
                bad_signers,
                dids,
                node_url.clone(),
            )
            .map_err(ApiNodeError::LogError)?;
            logger
                .publish(&mut log, node_url)
                .map_err(ApiNodeError::LogError)?;

            Ok((signature, working_nodes))
        }
        SignTerminalStates::Failed => {
            log::error!(
                target: &signature_log_target(session_id),
                "signature failed"
            );
            Err(anyhow::Error::msg("Sign Failed"))
        }
    }
}
