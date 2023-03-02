use std::{
    str,
    sync::{
        mpsc::{channel, Receiver},
        Arc, Mutex,
    },
};

use anyhow::Result;
use iota_client::{
    block::{payload::Payload, BlockId},
    Client, MqttEvent, MqttPayload, Topic,
};

pub struct Listener(Client);

impl Listener {
    pub fn new(node_url: &str) -> Result<Self> {
        Ok(Listener(Client::builder().with_node(node_url)?.finish()?))
    }

    pub async fn start(&mut self, tag: String) -> Result<Receiver<(Vec<u8>, BlockId)>> {
        self.listen_tag(tag).await
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.0.subscriber().disconnect().await?;
        Ok(())
    }

    async fn listen_tag(&mut self, tag: String) -> Result<Receiver<(Vec<u8>, BlockId)>> {
        let (tx, rx) = channel();
        let tx = Arc::new(Mutex::new(tx));

        let mut event_rx = self.0.mqtt_event_receiver();
        tokio::spawn(async move {
            while event_rx.changed().await.is_ok() {
                let event = event_rx.borrow();
                if *event == MqttEvent::Disconnected {
                    //println!("mqtt disconnected");
                    std::process::exit(1);
                }
            }
        });
        self.0
            .subscriber()
            .with_topics(vec![Topic::try_from("blocks/tagged-data".to_string())?])
            .subscribe(move |event| {
                if let MqttPayload::Block(b) = event.payload.clone() {
                    if let Payload::TaggedData(payload) = b.payload().unwrap() {
                        if tag.as_bytes() == payload.tag() {
                            tx.lock()
                                .unwrap()
                                .send((Vec::from(payload.data()), b.id()))
                                .unwrap()
                        }
                    };
                }
            })
            .await?;
        Ok(rx)
    }
}

pub struct Publisher(pub Client);

impl Publisher {
    pub fn new(node_url: &str) -> Result<Self> {
        Ok(Publisher(Client::builder().with_node(node_url)?.finish()?))
    }

    pub async fn publish(&self, data: &[u8], tag: Option<String>) -> Result<String> {
        let client_message_builder = match tag {
            Some(tag) => self
                .0
                .block()
                .with_tag(tag.into_bytes())
                .with_data(data.to_vec()),
            None => self.0.block().with_data(data.to_vec()),
        };

        let response = client_message_builder.finish().await?;
        Ok(response.id().to_string())
    }
}
