use std::{
    str,
    sync::{mpsc::channel, Arc, Mutex},
};

use anyhow::Result;
use iota_client::{
    bee_message::prelude::{Message, Payload},
    Client, MqttEvent, Topic,
};

use super::client::iota_client;

pub struct Listener(Client);

pub fn new_listener(network: &str) -> Result<Listener> {
    Ok(Listener(iota_client(network)?))
}

impl Listener {
    pub async fn start(&mut self, index: String) -> Result<()> {
        self.listen_index(index).await?;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.0.subscriber().disconnect().await?;
        Ok(())
    }

    async fn listen_index(&mut self, index: String) -> Result<()> {
        let (tx, rx) = channel();
        let tx = Arc::new(Mutex::new(tx));

        let mut event_rx = self.0.mqtt_event_receiver();
        tokio::spawn(async move {
            while event_rx.changed().await.is_ok() {
                let event = event_rx.borrow();
                if *event == MqttEvent::Disconnected {
                    println!("mqtt disconnected");
                    std::process::exit(1);
                }
            }
        });
        self.0
            .subscriber()
            .with_topics(vec![Topic::new(
                "messages/indexation/".to_owned() + index.as_str(),
            )?])
            .subscribe(move |event| {
                let message: Message = serde_json::from_str(&event.payload).unwrap();
                if let Payload::Indexation(payload) = message.payload().as_ref().unwrap() {
                    println!("{}", str::from_utf8(payload.data()).unwrap());
                }
                tx.lock().unwrap().send(()).unwrap();
            })
            .await?;

        loop {
            rx.recv()?;
        }
    }
}

pub struct Publisher(Client);

pub fn new_publisher(network: &str) -> Result<Publisher> {
    Ok(Publisher(iota_client(network)?))
}

impl Publisher {
    pub async fn publish(&self, data: &[u8], index: Option<String>) -> Result<String> {
        // Build message with optional index
        let client_message_builder = match index {
            Some(idx) => self.0.message().with_data(data.to_vec()).with_index(idx),
            None => self.0.message().with_data(data.to_vec()),
        };
        let response = client_message_builder.finish().await?;

        Ok(response.id().0.to_string())
    }
}
