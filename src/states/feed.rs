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

    filter_id: String,

    /// Any message drawn from [Feed] can be delayed and later placed in the [queue].
    delayed: Vec<T>,
}

impl<T: Display + Serialize, R: Receiver<MessageWrapper<T>>> Feed<T, R> {
    pub(crate) fn new(feed: R, filter_id: String) -> Self {
        Self {
            queue: VecDeque::new(),
            receiver: feed,
            delayed: Vec::new(),
            filter_id,
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

        let wrapped_message = self.receiver.recv().map_err(|e| {
            let _recv_error = e;
            FeedError::ChannelClosed
        })?;
        if wrapped_message.session_id != self.filter_id {
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
    pub session_id: String,
    pub message: T,
}

impl<T: Display + Serialize> Display for MessageWrapper<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "broadcasting session_id {}: {}",
            &self.session_id.chars().take(10).collect::<String>(),
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
