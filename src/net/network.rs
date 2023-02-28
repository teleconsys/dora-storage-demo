use std::str::FromStr;

use identity_iota::iota_core::Network as IotaNetwork;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Network {
    IotaNetwork(IotaNetwork),
}

impl From<IotaNetwork> for Network {
    fn from(net: IotaNetwork) -> Self {
        Self::IotaNetwork(net)
    }
}

impl FromStr for Network {
    type Err = NetworkError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        match parts[0] {
            "iota" => Ok(Self::IotaNetwork(
                IotaNetwork::try_from_name(parts[1].to_owned())
                    .map_err(|_| NetworkError::NetworkParsing)?,
            )),
            _ => Err(NetworkError::NetworkParsing),
        }
    }
}

impl TryInto<IotaNetwork> for Network {
    type Error = NetworkError;

    fn try_into(self) -> Result<IotaNetwork, Self::Error> {
        if let Network::IotaNetwork(net) = self {
            Ok(net)
        } else {
            Err(Self::Error::IotaNetworkParsing)
        }
    }
}

impl ToString for Network {
    fn to_string(&self) -> String {
        match self {
            Network::IotaNetwork(IotaNetwork::Mainnet) => "main".to_owned(),
            Network::IotaNetwork(IotaNetwork::Devnet) => "dev".to_owned(),
            _ => "".to_owned(),
        }
    }
}

pub enum NetworkError {
    NetworkParsing,
    IotaNetworkParsing,
}
