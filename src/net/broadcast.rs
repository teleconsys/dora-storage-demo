use std::{
    fmt::Display,
    sync::mpsc::{Receiver, Sender},
    thread::{self, JoinHandle},
};

pub struct LocalBroadcast<T: Send> {
    receiver: Receiver<T>,
    senders: Vec<Sender<T>>,
    global_sender: Sender<T>,
}

impl<T: Display + Clone + Send + 'static> LocalBroadcast<T> {
    pub fn new() -> Self {
        let (global_sender, receiver) = std::sync::mpsc::channel();
        Self {
            receiver,
            senders: Vec::new(),
            global_sender,
        }
    }

    pub fn get_broadcast_sender(&self) -> Sender<T> {
        self.global_sender.clone()
    }

    pub fn add_sender_of_receiving_channel(&mut self, sender: Sender<T>) {
        self.senders.push(sender);
    }

    pub fn start(self) -> JoinHandle<()> {
        thread::spawn(move || {
            for message in self.receiver {
                println!("Received broadcast message: {message}");
                self.senders
                    .iter()
                    .map(|tx| tx.send(message.clone()))
                    .for_each(|res| {
                        if let Err(e) = res {
                            log::warn!("{}", e)
                        }
                    });
            }
        })
    }
}
