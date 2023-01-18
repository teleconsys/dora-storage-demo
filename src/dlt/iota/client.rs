use anyhow::Result;
use identity_iota::{
    client::{ClientBuilder, DIDMessageEncoding},
    iota_core::Network,
    prelude::Client as IdentityClient,
};
use iota_client::Client;

pub(crate) fn iota_client(network_name: &str) -> Result<Client> {
    let client_builder = Client::builder()
        .with_network(network_name)
        .with_node(&default_network_node(network_name))?;

    let r = tokio::runtime::Runtime::new()?;
    Ok(r.block_on(client_builder.finish())?)
}

pub(crate) fn identity_client(network_name: &str) -> Result<IdentityClient> {
    let client_builder = ClientBuilder::new()
        .network(Network::try_from_name(network_name.to_owned())?)
        .encoding(DIDMessageEncoding::Json)
        .primary_node(&default_network_node(network_name), None, None)?;

    let r = tokio::runtime::Runtime::new()?;
    Ok(r.block_on(client_builder.build())?)
}

fn default_network_node(network: &str) -> String {
    match network {
        "main" => "https://chrysalis-nodes.iota.cafe".to_string(),
        "dev" => "https://api.lb-0.h.chrysalis-devnet.iota.cafe".to_string(),
        _ => panic!("invalid iota network"),
    }
}
