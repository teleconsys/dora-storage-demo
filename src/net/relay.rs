use anyhow::{Error, Result};
use iota_client::block::BlockId;
use std::{
    fmt::Display,
    io::{self, Read, Write},
    marker::PhantomData,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use serde::{de::DeserializeOwned, Serialize};

use crate::dlt::iota::{Listener, Publisher};

use super::{
    channel::{Receiver, Sender},
    host::Host,
};

pub struct ListenRelay<T, S: Sender<T>> {
    output: S,
    host: Host,
    is_closed: Arc<AtomicBool>,
    _phantom_data: PhantomData<T>,
}

impl<T: DeserializeOwned + Display, S: Sender<T>> ListenRelay<T, S> {
    pub fn new(host: Host, output: S, is_closed: Arc<AtomicBool>) -> Self {
        Self {
            output,
            host,
            is_closed,
            _phantom_data: PhantomData,
        }
    }

    pub fn listen(&self) -> Result<()> {
        let listener = match TcpListener::bind(SocketAddr::from(self.host.clone())) {
            Ok(v) => v,
            Err(e) => {
                log::error!("could not listen on port {}: {}", self.host.port(), e);
                return Err(e.into());
            }
        };

        log::info!("listeninig at {}", listener.local_addr()?);
        listener.set_nonblocking(true)?;
        for stream in listener.incoming() {
            if self.is_closed.load(Ordering::SeqCst) {
                return Ok(());
            }
            match stream {
                Ok(stream) => self.handle_stream(stream)?,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    log::error!("could not get incoming stream: {}", e);
                    return Err(e.into());
                }
            }
        }

        Ok(())
    }

    fn handle_stream(&self, mut stream: TcpStream) -> Result<()> {
        log::trace!("receiving message from {}", &stream.peer_addr()?);
        let mut buf = vec![];
        stream.read_to_end(&mut buf)?;
        let message = serde_json::from_slice(&buf)?;
        log::trace!("message received");
        let res = self.output.send(message);
        if let Err(e) = res {
            log::error!("could not relay message: {}", e);
        }
        Ok(())
    }
}

pub struct IotaListenRelay<T, S: Sender<T>> {
    output: S,
    is_closed: Arc<AtomicBool>,
    tags: Vec<String>,
    node_url: String,
    _phantom_data: PhantomData<T>,
}

impl<T: DeserializeOwned + Display, S: Sender<T> + 'static> IotaListenRelay<T, S> {
    pub fn new(output: S, is_closed: Arc<AtomicBool>, tags: Vec<String>, node_url: String) -> Self {
        Self {
            output,
            is_closed,
            tags,
            node_url,
            _phantom_data: PhantomData,
        }
    }

    pub fn listen(&self) -> Result<()> {
        let mut listener = Listener::new(&self.node_url)?;
        let receivers: Vec<std::sync::mpsc::Receiver<(Vec<u8>, BlockId)>> = self
            .tags
            .iter()
            .map(|i| tokio::runtime::Runtime::new()?.block_on(listener.start(i.to_string())))
            .collect::<Result<Vec<_>>>()?;

        let mut handles = Vec::new();
        for receiver in receivers {
            let output = self.output.clone();

            // TODO MANAGE THE ID
            let h = thread::spawn(move || {
                for (data, _id) in receiver {
                    if let Ok(message) = serde_json::from_slice(&data) {
                        log::trace!("message received");
                        let res = output.send(message);
                        if let Err(e) = res {
                            log::error!("could not relay message: {}", e);
                        }
                    }
                }
            });
            handles.push(h)
        }

        Ok(())
    }
}

pub struct BroadcastRelay<T, R: Receiver<T>> {
    input: R,
    destinations: Vec<SocketAddr>,
    _phantom: PhantomData<T>,
}

impl<T: Serialize, R: Receiver<T>> BroadcastRelay<T, R> {
    pub fn new(input: R, destinations: Vec<SocketAddr>) -> Self {
        Self {
            input,
            destinations,
            _phantom: PhantomData,
        }
    }

    pub fn broadcast(&mut self) -> Result<()> {
        std::thread::sleep(Duration::from_secs(3));

        loop {
            let message = self
                .input
                .recv()
                .map_err(|e| Error::msg(format!("{:?}", e)))?;
            log::trace!(
                "relaying message: {:?}",
                serde_json::to_string(&message).unwrap()
            );
            let serialized = serde_json::to_string(&message)?;

            for destination in &self.destinations {
                log::trace!("sending to peer {}", destination);
                match TcpStream::connect(destination) {
                    Ok(mut socket) => {
                        log::trace!("relaying message to {}", socket.peer_addr()?);
                        socket.write_all(serialized.as_bytes())?;
                    }
                    Err(e) => {
                        log::error!("could not connect to destination {}: {}", destination, e);
                    }
                }
            }
        }
    }
}

pub struct IotaBroadcastRelay<T, R: Receiver<T>> {
    input: R,
    tag: String,
    publisher: Publisher,
    _phantom: PhantomData<T>,
}

impl<T: Serialize, R: Receiver<T>> IotaBroadcastRelay<T, R> {
    pub fn new(tag: String, input: R, node_url: String) -> Result<Self> {
        let publisher = Publisher::new(&node_url)?;
        Ok(IotaBroadcastRelay {
            input,
            tag,
            publisher,
            _phantom: PhantomData,
        })
    }

    pub fn broadcast(&mut self) -> Result<()> {
        std::thread::sleep(Duration::from_secs(3));

        loop {
            let message = self
                .input
                .recv()
                .map_err(|e| Error::msg(format!("{e:?}")))?;
            // log::trace!(
            // "Relaying message: {:?}",
            // serde_json::to_string(&message).unwrap()
            // );
            let serialized = serde_json::to_string(&message)?;

            let tag = self.tag.clone();
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(self.publisher.publish(serialized.as_bytes(), Some(tag)))?;
        }
    }
}
