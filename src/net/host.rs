use std::{
    fmt::Display,
    io::{self, ErrorKind},
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
};

use anyhow::Error;

#[derive(Debug, Clone)]
pub struct Host(SocketAddr);

impl Host {
    pub fn with_port(&self, port: u16) -> Self {
        let mut socket_address = SocketAddr::from(self);
        socket_address.set_port(port);
        socket_address.into()
    }

    pub fn port(&self) -> u16 {
        self.0.port()
    }
}

impl FromStr for Host {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Host(s.to_socket_addrs()?.next().ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, Error::msg("Missing socket"))
        })?))
    }
}

impl From<SocketAddr> for Host {
    fn from(value: SocketAddr) -> Self {
        Self(value)
    }
}

impl From<Host> for SocketAddr {
    fn from(value: Host) -> Self {
        value.0
    }
}

impl From<&Host> for SocketAddr {
    fn from(value: &Host) -> Self {
        value.0
    }
}

impl Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<SocketAddr> for Host {
    fn as_ref(&self) -> &SocketAddr {
        &self.0
    }
}
