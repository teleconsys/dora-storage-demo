use std::{
    fmt::{Debug, Display},
    sync::Arc,
    time::Duration,
};

use anyhow::Error;
use async_trait::async_trait;
use futures::lock::Mutex;

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

pub struct StateMachine<M> {
    id: usize,
    state: BoxedState<M>,
    message_output: Box<dyn Sender<M>>,
    message_input: Box<dyn Receiver<M>>,
}

impl<M> StateMachine<M> {
    pub fn new(
        initial_state: BoxedState<M>,
        input_channel: Box<dyn Receiver<M>>,
        output_channel: Box<dyn Sender<M>>,
        id: usize,
    ) -> StateMachine<M> {
        Self {
            id,
            state: initial_state,
            message_output: output_channel,
            message_input: input_channel,
        }
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        'states: loop {
            println!("[{}] Initializing state [{}]", self.id, self.state);
            let messages = self.state.initialize();
            for message in messages {
                self.message_output.send(message).await;
            }

            println!("[{}] Processing messages...", self.id);
            loop {
                let transition = self.state.advance()?;
                match transition {
                    Transition::Same => {
                        match self.message_input.receive().await {
                            Ok(next_message) => match self.state.deliver(next_message) {
                                DeliveryStatus::Delivered => {}
                                DeliveryStatus::Unexpected(_) => {
                                    panic!("No mechaninsm to handle unexpected messages");
                                }
                                DeliveryStatus::Error(e) => {
                                    return Err(Error::msg(format!(
                                        "[{}][{}] {}",
                                        self.id, self.state, e
                                    )))
                                }
                            },
                            Err(e) => println!("[{}] {}", self.id, e),
                        };
                    }
                    Transition::Next(next_state) => {
                        println!(
                            "[{}] Transitioning from [{}] to state [{}]",
                            self.id, self.state, next_state
                        );
                        self.state = next_state;
                        break;
                    }
                    Transition::Terminal => break 'states,
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
    async fn receive(&mut self) -> Result<M, Error>;
}

pub struct IoBus<M> {
    messages: Arc<Mutex<Vec<M>>>,
    read_index: usize,
}

impl<M> IoBus<M> {
    pub fn new(messages: Arc<Mutex<Vec<M>>>) -> IoBus<M> {
        Self {
            messages,
            read_index: 0,
        }
    }
}

#[async_trait]
impl<M: Send> Sender<M> for IoBus<M> {
    async fn send(&mut self, msg: M) {
        self.messages.lock().await.push(msg);
    }
}

#[async_trait]
impl<M: Send> Receiver<M> for IoBus<M>
where
    M: ToOwned<Owned = M>,
    M: Send,
{
    async fn receive(&mut self) -> Result<M, Error> {
        let m = self.messages.lock().await;
        if let Some(msg) = m.get(self.read_index) {
            self.read_index += 1;
            return Ok(msg.to_owned());
        }
        drop(m);
        async_std::task::sleep(Duration::from_millis(1)).await;
        Err(Error::msg("No new messages"))
        // println!("no messages...");
        // Ok(self.receive().await?)
    }
}
