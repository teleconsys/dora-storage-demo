use std::{fmt::Display, sync::mpsc::Sender};

use anyhow::Error;
use colored::Colorize;
use kyber_rs::group::edwards25519::Point;
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    net::channel::Receiver,
    states::feed::{Feed, MessageWrapper},
};

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
    fn advance(&mut self) -> Result<Transition<T>, Error>;
}

pub trait StateMachineTypes {
    type Message: Display + Send + Sync + 'static + Serialize + DeserializeOwned;
    type TerminalStates;
}

pub struct StateMachine<'a, T: StateMachineTypes, R: Receiver<MessageWrapper<T::Message>>> {
    id: usize,
    session_id: String,
    key: Point,
    state: BoxedState<T>,
    message_output: &'a Sender<MessageWrapper<T::Message>>,
    message_input: Feed<T::Message, R>,
}

impl<'a, T: StateMachineTypes, R: Receiver<MessageWrapper<T::Message>>> StateMachine<'a, T, R> {
    fn log_target(&self) -> String {
        format!("fsm:{}", self.session_id.chars().take(10).collect::<String>().yellow())
    }
    pub fn new<F: Into<Feed<T::Message, R>>>(
        initial_state: BoxedState<T>,
        session_id: String,
        input_channel: F,
        output_channel: &'a Sender<MessageWrapper<T::Message>>,
        id: usize,
        key: Point,
    ) -> StateMachine<'a, T, R> {
        Self {
            id,
            session_id,
            key,
            state: initial_state,
            message_output: output_channel,
            message_input: input_channel.into(),
        }
    }

    pub fn run(&mut self) -> Result<T::TerminalStates, Error> {
        loop {
            let messages: Vec<T::Message> = self.state.initialize();
            for message in messages {
                self.message_output.send(MessageWrapper {
                    session_id: self.session_id.clone(),
                    message,
                })?;
            }

            self.message_input.refresh();
            log::trace!(
                target: &self.log_target(),
                "initializing state {}",
                self.state.to_string().cyan()
            );
            loop {
                let transition: Transition<T> = self
                    .state
                    .advance()
                    .map_err(|e| Error::msg(format!("[{}] failed transition: {}", self.session_id.chars().take(10).collect::<String>(), e)))?;
                match transition {
                    Transition::Same => {
                        match self.message_input.next() {
                            Ok(next_message) => match self.state.deliver(next_message) {
                                DeliveryStatus::Delivered => {}
                                DeliveryStatus::Unexpected(m) => {
                                    log::warn!(
                                        target: &self.log_target(),
                                        "delaying unexpected message: {}", m
                                    );
                                    self.message_input.delay(m);
                                }
                                DeliveryStatus::Error(e) => {
                                    return Err(Error::msg(format!(
                                        "[{}][{}] {}",
                                        self.session_id.chars().take(10).collect::<String>(), self.state, e
                                    )));
                                }
                            },
                            Err(_e) => {
                                // log::trace!(
                                //     target: &self.log_target(),
                                //     "Could not get new message due to: {}", e)
                            }
                        };
                    }
                    Transition::Next(next_state) => {
                        log::trace!(
                            target: &self.log_target(),
                            "transitioning state: {} => {}", self.state.to_string(), next_state.to_string()
                        );
                        self.state = next_state;
                        break;
                    }
                    Transition::Terminal(final_state) => {
                        log::trace!(
                            target: &self.log_target(),
                            "completed"
                        );
                        return Ok(final_state);
                    }
                }
            }
        }
    }
}
