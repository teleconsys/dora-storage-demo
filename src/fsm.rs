use std::{fmt::Display, sync::Arc, time::Duration};

use anyhow::Error;
use async_trait::async_trait;
use colored::Colorize;
use futures::lock::Mutex;
use kyber_rs::group::edwards25519::Point;
use thiserror::Error;

use crate::feed::Feed;

pub type BoxedState<T> = Box<dyn State<T>>;

pub enum DeliveryStatus<M> {
    Delivered,
    Unexpected(M),
    Error(Error),
}

pub enum Transition<T: StateMachineTypes> {
    Same,
    Next(BoxedState<T>),
    Terminal(T::TerminalStates),
}

pub trait State<T: StateMachineTypes>: Display + Send {
    fn initialize(&self) -> Vec<T::Message>;
    fn deliver(&mut self, message: T::Message) -> DeliveryStatus<T::Message>;
    fn advance(&self) -> Result<Transition<T>, Error>;
}

pub trait StateMachineTypes {
    type Message: Display;
    type Receiver: Receiver<Self::Message>;
    type TerminalStates;
}

pub struct StateMachine<T: StateMachineTypes> {
    id: usize,
    state: BoxedState<T>,
    message_output: Box<dyn Sender<T::Message>>,
    message_input: Feed<T::Message, T::Receiver>,
}

impl<T: StateMachineTypes> StateMachine<T> {
    fn log_target(&self) -> String {
        format!("fsm:node_{}", self.id)
    }
    pub fn new(
        initial_state: BoxedState<T>,
        input_channel: Feed<T::Message, T::Receiver>,
        output_channel: Box<dyn Sender<T::Message>>,
        id: usize,
    ) -> StateMachine<T> {
        Self {
            id,
            state: initial_state,
            message_output: output_channel,
            message_input: input_channel,
        }
    }

    pub async fn run(&mut self) -> Result<T::TerminalStates, Error> {
        'states: loop {
            let messages: Vec<T::Message> = self.state.initialize();
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
                let transition: Transition<T> = self
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
                                // log::trace!(
                                //     target: &self.log_target(),
                                //     "Could not get new message due to: {}", e)
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
                    Transition::Terminal(final_state) => {
                        log::info!(
                            target: &self.log_target(),
                            "Completed"
                        );
                        return Ok(final_state);
                    }
                }
            }
        }
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
