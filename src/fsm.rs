use std::{fmt::Display, sync::Arc, time::Duration};

use anyhow::Error;
use async_trait::async_trait;
use colored::Colorize;
use futures::lock::Mutex;
use kyber_rs::group::edwards25519::Point;
use thiserror::Error;

use crate::feed::Feed;

pub type BoxedState<M> = Box<dyn State<M>>;

pub enum DeliveryStatus<M> {
    Delivered,
    Unexpected(M),
    Error(Error),
}

pub enum Transition<M> {
    Same,
    Next(BoxedState<M>),
    Terminal,
}

pub trait State<M>: Display + Send {
    fn initialize(&self) -> Vec<M>;
    fn deliver(&mut self, message: M) -> DeliveryStatus<M>;
    fn advance(&self) -> Result<Transition<M>, Error>;
}

pub struct StateMachine<M, R: Receiver<M>> {
    id: usize,
    state: BoxedState<M>,
    message_output: Box<dyn Sender<M>>,
    message_input: Feed<M, R>,
}

impl<M: Display, R: Receiver<M>> StateMachine<M, R> {
    fn log_target(&self) -> String {
        format!("fsm:node_{}", self.id)
    }
    pub fn new(
        initial_state: BoxedState<M>,
        input_channel: Feed<M, R>,
        output_channel: Box<dyn Sender<M>>,
        id: usize,
    ) -> StateMachine<M, R> {
        Self {
            id,
            state: initial_state,
            message_output: output_channel,
            message_input: input_channel,
        }
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        'states: loop {
            let messages = self.state.initialize();
            for message in messages {
                self.message_output.send(message).await;
            }

            self.message_input.refresh();
            log::info!(
                target: &self.log_target(),
                "Initializing state {}",
                self.state.to_string().cyan()
            );
            loop {
                let transition = self
                    .state
                    .advance()
                    .map_err(|e| Error::msg(format!("[{}] Failed transition: {}", self.id, e)))?;
                match transition {
                    Transition::Same => {
                        match self.message_input.next().await {
                            Ok(next_message) => match self.state.deliver(next_message) {
                                DeliveryStatus::Delivered => {}
                                DeliveryStatus::Unexpected(m) => {
                                    log::warn!(
                                        target: &self.log_target(),
                                        "Delaying unexpected message: {}", m
                                    );
                                    self.message_input.delay(m);
                                }
                                DeliveryStatus::Error(e) => {
                                    return Err(Error::msg(format!(
                                        "[{}][{}] {}",
                                        self.id, self.state, e
                                    )));
                                }
                            },
                            Err(e) => {
                                log::trace!(
                                    target: &self.log_target(),
                                    "Could not get new message due to: {}", e)
                            }
                        };
                    }
                    Transition::Next(next_state) => {
                        log::trace!(
                            target: &self.log_target(),
                            "Transitioning state: {} => {}", self.state.to_string(), next_state.to_string()
                        );
                        self.state = next_state;
                        break;
                    }
                    Transition::Terminal => {
                        log::info!(
                            target: &self.log_target(),
                            "Completed"
                        );
                        break 'states;
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
pub trait Sender<M>: Send {
    async fn send(&mut self, msg: M);
}

#[async_trait]
pub trait Receiver<M>: Send {
    async fn receive(&mut self) -> Result<M, ReceiverError>;
}

#[derive(Error, Debug)]
pub enum ReceiverError {
    #[error("No new messages")]
    NoNewMessages,
    #[error("Something has gone wrong while receiving: {error}")]
    FailedToReceive { error: Error },
}

pub struct MessageWrapper<M> {
    pub sender: Point,
    pub message: M,
}

pub struct IoBus<M> {
    messages: Arc<Mutex<Vec<MessageWrapper<M>>>>,
    read_index: usize,
    own_key: Point,
}

impl<M> IoBus<M> {
    pub fn new(messages: Arc<Mutex<Vec<MessageWrapper<M>>>>, key: Point) -> IoBus<M> {
        Self {
            messages,
            read_index: 0,
            own_key: key,
        }
    }
}

#[async_trait]
impl<M: Send> Sender<M> for IoBus<M> {
    async fn send(&mut self, msg: M) {
        self.messages.lock().await.push(MessageWrapper {
            sender: self.own_key.clone(),
            message: msg,
        });
    }
}

#[async_trait]
impl<M: Send> Receiver<M> for IoBus<M>
where
    M: ToOwned<Owned = M>,
    M: Send,
{
    async fn receive(&mut self) -> Result<M, ReceiverError> {
        let m = self.messages.lock().await;
        if let Some(msg) = m.get(self.read_index) {
            self.read_index += 1;
            if msg.sender == self.own_key {
                log::trace!("Skipping own message");
                return Err(ReceiverError::NoNewMessages);
            }
            return Ok(msg.message.to_owned());
        }
        drop(m);
        async_std::task::sleep(Duration::from_millis(1)).await;
        Err(ReceiverError::NoNewMessages)
    }
}
