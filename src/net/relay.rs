use anyhow::{Error, Result};
use std::{
    fmt::{Debug, Display},
    io::{self, Read, Write},
    marker::PhantomData,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use serde::{de::DeserializeOwned, Serialize};

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
        let listener = match TcpListener::bind(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            self.host.port(),
            0,
            0,
        )) {
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
            log::info!(
                "Relaying message: {:?}",
                serde_json::to_string(&message).unwrap()
            );
            let serialized = serde_json::to_string(&message)?;

            for destination in &self.destinations {
                log::trace!("Sending to peer {}", destination);
                match TcpStream::connect(destination) {
                    Ok(mut socket) => {
                        log::info!("Relaying message to {}", socket.peer_addr()?);
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
