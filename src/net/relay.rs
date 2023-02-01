use anyhow::{Error, Result};
use identity_iota::iota_core::Network;
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
                log::error!("Could not listen on port {}: {}", self.host.port(), e);
                return Err(e.into());
            }
        };

        log::info!("Listeninig at {}", listener.local_addr()?);
        listener.set_nonblocking(true)?;
        for stream in listener.incoming() {
            if self.is_closed.load(Ordering::SeqCst) {
                return Ok(());
            }
            match stream {
                Ok(stream) => self.handle_stream(stream)?,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => {
                    log::error!("Could not get incoming stream: {}", e);
                    return Err(e.into());
                }
            }
        }

        Ok(())
    }

    fn handle_stream(&self, mut stream: TcpStream) -> Result<()> {
        log::info!("Receiving message from {}", &stream.peer_addr()?);
        let mut buf = vec![];
        stream.read_to_end(&mut buf)?;
        let message = serde_json::from_slice(&buf)?;
        log::trace!("Message received");
        let res = self.output.send(message);
        if let Err(e) = res {
            log::error!("Could not relay message: {}", e);
        }
        Ok(())
    }
}

pub struct IotaListenRelay<T, S: Sender<T>> {
    output: S,
    is_closed: Arc<AtomicBool>,
    indexes: Vec<String>,
    network: Network,
    _phantom_data: PhantomData<T>,
}

impl<T: DeserializeOwned + Display, S: Sender<T> + 'static> IotaListenRelay<T, S> {
    pub fn new(
        output: S,
        is_closed: Arc<AtomicBool>,
        indexes: Vec<String>,
        network: String,
    ) -> Self {
        let net = match network.as_str() {
            "iota-main" => Network::Mainnet,
            "iota-dev" => Network::Devnet,
            _ => panic!("unsupported network"),
        };
        Self {
            output,
            is_closed,
            indexes,
            _phantom_data: PhantomData,
            network: net,
        }
    }

    pub fn listen(&self) -> Result<()> {
        let mut listener = Listener::new(self.network.clone())?;
        let receivers: Vec<std::sync::mpsc::Receiver<(Vec<u8>, Vec<u8>)>> = self
            .indexes
            .iter()
            .map(|i| tokio::runtime::Runtime::new()?.block_on(listener.start(i.to_string())))
            .collect::<Result<Vec<_>>>()?;

        let mut handles = Vec::new();
        for receiver in receivers {
            let output = self.output.clone();

            // TODO MANAGE THE ID 
            let h = thread::spawn(move || {
                for (data, id) in receiver {
                    if let Ok(message) = serde_json::from_slice(&data) {
                        log::trace!("Message received");
                        let res = output.send(message);
                        if let Err(e) = res {
                            log::error!("Could not relay message: {}", e);
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
                "Relaying message: {:?}",
                serde_json::to_string(&message).unwrap()
            );
            let serialized = serde_json::to_string(&message)?;

            for destination in &self.destinations {
                log::trace!("Sending to peer {}", destination);
                match TcpStream::connect(destination) {
                    Ok(mut socket) => {
                        log::trace!("Relaying message to {}", socket.peer_addr()?);
                        socket.write_all(serialized.as_bytes())?;
                    }
                    Err(e) => {
                        log::error!("Could not connect to destination {}: {}", destination, e);
                    }
                }
            }
        }
    }
}

pub struct IotaBroadcastRelay<T, R: Receiver<T>> {
    input: R,
    index: String,
    publisher: Publisher,
    network: Network,
    _phantom: PhantomData<T>,
}

impl<T: Serialize, R: Receiver<T>> IotaBroadcastRelay<T, R> {
    pub fn new(index: String, input: R, network: String) -> Result<Self> {
        let net = match network.as_str() {
            "iota-main" => Network::Mainnet,
            "iota-dev" => Network::Devnet,
            _ => panic!("unsupported network"),
        };
        let publisher = Publisher::new(net.clone())?;
        Ok(IotaBroadcastRelay {
            input,
            index,
            publisher,
            network: net,
            _phantom: PhantomData,
        })
    }

    pub fn broadcast(&mut self) -> Result<()> {
        std::thread::sleep(Duration::from_secs(3));

        loop {
            let message = self
                .input
                .recv()
                .map_err(|e| Error::msg(format!("{:?}", e)))?;
            // log::trace!(
            // "Relaying message: {:?}",
            // serde_json::to_string(&message).unwrap()
            // );
            let serialized = serde_json::to_string(&message)?;

            let network = self.network.clone();
            let index = self.index.clone();
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(self.publisher.publish(serialized.as_bytes(), Some(index)))?;
        }
    }
}
