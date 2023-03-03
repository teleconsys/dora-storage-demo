use std::{
    io::Read,
    str::{FromStr, Utf8Error},
};

use enum_display::EnumDisplay;
use identity_iota::core::ToJson;
use iota_client::{
    block::{payload::Payload, BlockId},
    Client,
};
use kyber_rs::{
    group::edwards25519::{Point, Scalar, SuiteEd25519},
    share::dkg::rabin::DistKeyGenerator,
};
use thiserror::Error;

use crate::{
    logging::{new_signature_log, signature_log_target, NodeSignatureLogger},
    net::channel::{Receiver, Sender},
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
    pub client: Client,
    pub dkg: DistKeyGenerator<SuiteEd25519>,
    pub secret: Scalar,
    pub public_key: Point,
    pub id: usize,
    pub(crate) signature_sender: std::sync::mpsc::Sender<MessageWrapper<SignMessage>>,
    pub(crate) signature_sleep_time: u64,
}

pub struct HandlerParams {
    pub signature_logger: NodeSignatureLogger,
    pub committee_did: String,
    pub dids: Vec<String>,
    pub node_url: String,
}

pub struct ApiNode {
    pub storage: Storage,
    pub api_params: ApiParams,
}

impl ApiNode {
    pub fn handle_message(
        &self,
        message: NodeMessage,
        nodes_input: impl Receiver<MessageWrapper<SignMessage>>,
        nodes_output: impl Sender<MessageWrapper<SignMessage>>,
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
        sign_input: impl Receiver<MessageWrapper<SignMessage>>,
        sign_output: impl Sender<MessageWrapper<SignMessage>>,
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
        sign_input: impl Receiver<MessageWrapper<SignMessage>>,
        sign_output: impl Sender<MessageWrapper<SignMessage>>,
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
                IotaMessageUri(id) => {
                    let rt = tokio::runtime::Runtime::new()?;
                    let block_id = BlockId::from_str(id)
                        .map_err(|e| ApiNodeError::InvalidMessageId(e.into()))?;
                    let block = rt.block_on(self.api_params.client.get_block(&block_id))?;
                    let payload = match block.payload() {
                        Some(p) => p,
                        None => return Err(ApiNodeError::MissingPayload(block_id)),
                    };
                    let tagged_data = match payload {
                        Payload::TaggedData(td) => td,
                        _ => return Err(ApiNodeError::UnsupportedPayload),
                    };
                    tagged_data.data().to_vec()
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

    fn get_sign_fsm<
        'a,
        R: Receiver<MessageWrapper<SignMessage>>,
        S: Sender<MessageWrapper<SignMessage>>,
    >(
        &self,
        message: &[u8],
        session_id: String,
        sign_input: R,
        sign_output: S,
    ) -> Result<Fsm<'a, R, S>, ApiNodeError> {
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

type Fsm<'a, R, S> = StateMachine<SignTypes, R, S>;

#[derive(Debug, Error)]
pub enum ApiNodeError {
    #[error("async runtime error")]
    AsyncRuntimeError(#[from] std::io::Error),
    #[error("message id is not valid")]
    InvalidMessageId(#[source] anyhow::Error),
    #[error("iota client error")]
    IotaError(#[from] iota_client::Error),
    #[error("missing payload {0}")]
    MissingPayload(BlockId),
    #[error("payload is not supported")]
    UnsupportedPayload,
    #[error("storage error")]
    StorageError(#[source] anyhow::Error),
    #[error("signature error")]
    SignatureError(#[source] anyhow::Error),
    #[error("data is not a valid utf8 string")]
    ConversionError(#[from] Utf8Error),
    #[error("dlt logging failed")]
    LogError(#[source] anyhow::Error),
    #[error("http connection error")]
    HttpError(#[source] anyhow::Error),
}


fn manage_signature_terminal_state(
    final_state: SignTerminalStates,
    session_id: &str,
    dids: Vec<String>,
    logger: NodeSignatureLogger,
    node_url: String,
) -> anyhow::Result<(Signature, Vec<String>)> {
    match final_state {
        SignTerminalStates::Completed(signature, processed_partial_owners, bad_signers) => {
            let (mut log, working_nodes) = new_signature_log(
                session_id.to_string(),
                processed_partial_owners,
                bad_signers,
                dids,
                node_url,
            )
            .map_err(ApiNodeError::LogError)?;
            logger.publish(&mut log).map_err(ApiNodeError::LogError)?;

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
