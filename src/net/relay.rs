use anyhow::Result;
use std::{
    fmt::Display,
    io::{self, Read, Write},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender},
        Arc,
    },
    time::Duration,
};

use serde::{de::DeserializeOwned, Serialize};

pub struct ListenRelay<T> {
    output: Sender<T>,
    port: u16,
    is_closed: Arc<AtomicBool>,
}

impl<T: DeserializeOwned + Display> ListenRelay<T> {
    pub fn new(port: u16, output: Sender<T>, is_closed: Arc<AtomicBool>) -> Self {
        Self {
            output,
            port,
            is_closed,
        }
    }

    pub fn listen(&self) -> Result<()> {
        let listener =
            match TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, self.port, 0, 0)) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("Could not listen on port {}: {}", self.port, e);
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
        log::trace!("Message received: {}", &message);
        let res = self.output.send(message);
        if let Err(e) = res {
            log::error!("Could not relay message: {}", e);
        }
        Ok(())
    }
}

pub struct BroadcastRelay<T> {
    input: Receiver<T>,
    destinations: Vec<SocketAddr>,
}

impl<T: Serialize + Display> BroadcastRelay<T> {
    pub fn new(input: Receiver<T>, destinations: Vec<SocketAddr>) -> Self {
        Self {
            input,
            destinations,
        }
    }

    pub fn broadcast(&self) -> Result<()> {
        std::thread::sleep(Duration::from_secs(3));

        for message in &self.input {
            log::info!("Relaying message: {}", message);
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

        Ok(())
    }
}
