use std::collections::VecDeque;
use std::fmt::Debug;
use thiserror::Error;

use crate::fsm::{Receiver, ReceiverError};

/// [Feed] combines polling from a queue of messages and a channel. Message can be delayed
/// and later placed in the queue.
#[derive(Debug)]
pub struct Feed<M, R: Receiver<M>> {
    /// Messages from [queue] will be delivered first.
    queue: VecDeque<M>,

    /// Channel to receive message to deliver..
    feed: R,

    /// Any message drawn from [Feed] can be delayed and later placed in the [queue].
    delayed: Vec<M>,
}

impl<T, R: Receiver<T>> Feed<T, R> {
    pub(crate) fn new(feed: R) -> Self {
        Self {
            queue: VecDeque::new(),
            feed,
            delayed: Vec::new(),
        }
    }

    /// Draw the next message either from [queue] or [feed].
    pub(crate) async fn next(&mut self) -> Result<T, FeedError> {
        if !self.queue.is_empty() {
            return self
                .queue
                .pop_front()
                .ok_or_else(|| panic!("Popping a message from a non-empty queue must not fail"));
        }

        self.feed.receive().await.map_err(|e| match e {
            ReceiverError::FailedToReceive { error: _ } => FeedError::ChannelClosed,
            ReceiverError::NoNewMessages => FeedError::NoNewMessages,
        })
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

#[derive(Error, Debug)]
pub enum FeedError {
    #[error("Channel has been closed prematurely; more messages are expected")]
    ChannelClosed,
    #[error("No new messages")]
    NoNewMessages,
}
