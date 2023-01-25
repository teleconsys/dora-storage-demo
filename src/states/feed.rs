use kyber_rs::group::edwards25519::Point;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt::{Debug, Display};
use thiserror::Error;

use crate::net::channel::Receiver;

/// [Feed] combines polling from a queue of messages and a channel. Message can be delayed
/// and later placed in the queue.
#[derive(Debug)]
pub struct Feed<T: Display + Serialize, R: Receiver<MessageWrapper<T>>> {
    /// Messages from [queue] will be delivered first.
    queue: VecDeque<T>,

    /// Channel to receive message to deliver..
    receiver: R,

    filter_key: Point,

    /// Any message drawn from [Feed] can be delayed and later placed in the [queue].
    delayed: Vec<T>,
}

impl<T: Display + Serialize, R: Receiver<MessageWrapper<T>>> Feed<T, R> {
    pub(crate) fn new(feed: R, key: Point) -> Self {
        Self {
            queue: VecDeque::new(),
            receiver: feed,
            delayed: Vec::new(),
            filter_key: key,
        }
    }

    /// Draw the next message either from [queue] or [feed].
    pub(crate) fn next(&mut self) -> Result<T, FeedError> {
        if !self.queue.is_empty() {
            return self
                .queue
                .pop_front()
                .ok_or_else(|| panic!("Popping a message from a non-empty queue must not fail"));
        }

        let wrapped_message = self.receiver.recv().map_err(|e| match e {
            RecvError => FeedError::ChannelClosed,
        })?;
        if wrapped_message.sender == self.filter_key {
            return Err(FeedError::NoNewMessages);
        }
        Ok(wrapped_message.message)
    }

    pub(crate) fn delay(&mut self, message: T) {
        self.delayed.push(message);
    }

    /// Place [delayed] messages in the [queue].
    pub(crate) fn refresh(&mut self) {
        self.delayed
            .drain(..)
            .rev()
            .for_each(|message| self.queue.push_front(message));
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageWrapper<T: Display + Serialize> {
    pub sender: Point,
    pub message: T,
}

impl<T: Display + Serialize> Display for MessageWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "Broadcasting from {}: {}",
            &self.sender.to_string()[..6],
            self.message
        ))
    }
}

#[derive(Error, Debug)]
pub enum FeedError {
    #[error("Channel has been closed prematurely; more messages are expected")]
    ChannelClosed,
    #[error("No new messages")]
    NoNewMessages,
}
