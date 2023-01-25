use std::sync::mpsc::{Receiver, Sender};

use crate::did::{new_document, resolve_document};
use crate::dkg::{DistPublicKey, DkgMessage, DkgTerminalStates, Initializing};
use crate::net::broadcast::LocalBroadcast;
use crate::states::dkg::InitializingIota;
use crate::states::feed::{Feed, MessageWrapper};
use crate::states::fsm::StateMachine;
use crate::store::Storage;
use anyhow::{bail, Ok, Result};
use kyber_rs::encoding::BinaryMarshaler;

use crate::states::sign::{self, SignMessage, SignTerminalStates, Signature};
use kyber_rs::{group::edwards25519::Point, util::key::Pair};

pub struct Node {
    keypair: Pair<Point>,
    dkg_input_channel: Receiver<MessageWrapper<DkgMessage>>,
    sign_input_channel: Receiver<MessageWrapper<SignMessage>>,
    dkg_output_channel: Sender<MessageWrapper<DkgMessage>>,
    sign_output_channel: Sender<MessageWrapper<SignMessage>>,
    id: usize,
}

impl Node {
    pub fn new(
        keypair: Pair<Point>,
        dkg_input_channel: Receiver<MessageWrapper<DkgMessage>>,
        dkg_output_channel: Sender<MessageWrapper<DkgMessage>>,
        sign_input_channel: Receiver<MessageWrapper<SignMessage>>,
        sign_output_channel: Sender<MessageWrapper<SignMessage>>,
        id: usize,
    ) -> Self {
        Self {
            keypair,
            dkg_input_channel,
            sign_input_channel,
            dkg_output_channel,
            sign_output_channel,
            id,
        }
    }

    pub fn new_local(
        keypair: Pair<Point>,
        index: usize,
        dkg_broadcast: &mut LocalBroadcast<MessageWrapper<DkgMessage>>,
        sign_broadcast: &mut LocalBroadcast<MessageWrapper<SignMessage>>,
    ) -> Node {
        let (dkg_input_sender, dkg_input_receiver) = std::sync::mpsc::channel();
        dkg_broadcast.add_sender_of_receiving_channel(dkg_input_sender);

        let (sign_input_sender, sign_input_receiver) = std::sync::mpsc::channel();
        sign_broadcast.add_sender_of_receiving_channel(sign_input_sender);

        Node::new(
            keypair,
            dkg_input_receiver,
            dkg_broadcast.get_broadcast_sender(),
            sign_input_receiver,
            sign_broadcast.get_broadcast_sender(),
            index,
        )
    }

    pub fn run(
        self,
        storage: Option<Storage>,
        did_network: Option<String>,
        did_url: Option<String>,
        num_participants: usize,
        signature_sender: Sender<MessageWrapper<SignMessage>>,
        signature_sleep_time: u64,
    ) -> Result<(Signature, DistPublicKey), anyhow::Error> {
        let secret = self.keypair.private.clone();
        let public = self.keypair.public.clone();
        let dkg_initial_state = Initializing::new(self.keypair, did_url, num_participants);
        let mut dkg_fsm = StateMachine::new(
            Box::new(dkg_initial_state),
            Feed::new(self.dkg_input_channel, public.clone()),
            self.dkg_output_channel,
            self.id,
            public.clone(),
        );
        let dkg_terminal_state = dkg_fsm.run()?;
        let DkgTerminalStates::Completed { dkg, did_urls } = dkg_terminal_state;
        let dist_pub_key = dkg.dist_key_share()?.public();

        let mut nodes_dids = None;
        let mut network = "iota-dev".to_owned();
        if let Some(net) = did_network.clone() {
            network = net;
            nodes_dids = Some(did_urls);
        }

        // Create unsigned DID
        let document = new_document(
            &dist_pub_key.marshal_binary()?,
            &network,
            Some(20),
            nodes_dids,
        )?;

        let sign_initial_state = sign::InitializingBuilder::try_from(dkg)?
            .with_message(document.to_bytes()?)
            .with_secret(secret)
            .with_sender(signature_sender)
            .with_sleep_time(signature_sleep_time)
            .build()?;

        let mut sign_fsm = StateMachine::new(
            Box::new(sign_initial_state),
            Feed::new(self.sign_input_channel, public.clone()),
            self.sign_output_channel,
            self.id,
            public,
        );

        let sign_terminal_state = sign_fsm.run()?;

        if let SignTerminalStates::Completed(signature, _processed_partial_owners, _bad_signers) =
            sign_terminal_state
        {
            if did_network.is_some() {
                // Publish signed DID
                let did_url = document.did_url();
                document.publish(&signature.to_vec())?;
                log::info!("Committee's DID has been published, DID URL: {}", did_url);

                let resolved_did = resolve_document(did_url.clone())?;

                if let Some(strg) = storage {
                    strg.put(did_url, &resolved_did.to_bytes()?)?;
                }
            }
            Ok((signature, dist_pub_key))
        } else {
            let did_url = document.did_url();
            log::info!("Could not sign committee's DID, DID URL: {}", did_url);
            Ok((Signature::from(vec![]), dist_pub_key))
        }
    }

    pub fn run_iota(
        self,
        storage: Option<Storage>,
        did_network: String,
        own_did_url: String,
        did_urls: Vec<String>,
        num_participants: usize,
        time_resolution: usize,
        signature_sender: Sender<MessageWrapper<SignMessage>>,
        signature_sleep_time: u64,
    ) -> Result<(Signature, DistPublicKey), anyhow::Error> {
        let secret = self.keypair.private.clone();
        let public = self.keypair.public.clone();
        let dkg_initial_state =
            InitializingIota::new(self.keypair, own_did_url, did_urls, num_participants)?;
        let mut dkg_fsm = StateMachine::new(
            Box::new(dkg_initial_state),
            Feed::new(self.dkg_input_channel, public.clone()),
            self.dkg_output_channel,
            self.id,
            public.clone(),
        );
        let dkg_terminal_state = dkg_fsm.run()?;
        let DkgTerminalStates::Completed { dkg, did_urls } = dkg_terminal_state;
        let dist_pub_key = dkg.dist_key_share()?.public();

        // Create unsigned DID
        let document = new_document(
            &dist_pub_key.marshal_binary()?,
            &did_network,
            Some(time_resolution as u32),
            Some(did_urls.clone()),
        )?;

        let sign_initial_state = sign::InitializingBuilder::try_from(dkg)?
            .with_message(document.to_bytes()?)
            .with_secret(secret)
            .with_sender(signature_sender)
            .with_sleep_time(signature_sleep_time)
            .build()?;

        let mut sign_fsm = StateMachine::new(
            Box::new(sign_initial_state),
            Feed::new(self.sign_input_channel, public.clone()),
            self.sign_output_channel,
            self.id,
            public,
        );

        let sign_terminal_state = sign_fsm.run()?;

        if let SignTerminalStates::Completed(signature, processed_partial_owners, bad_signers) =
            sign_terminal_state
        {
            // find out who didn't send a partial signature
            let mut working_nodes = vec![];
            for owner in processed_partial_owners {
                working_nodes.push(public_to_did(&did_urls, owner)?);
            }
            let mut absent_nodes = did_urls.clone();
            for worker in working_nodes {
                absent_nodes.retain(|x| *x != worker);
            }

            // find out who was a bad signer
            let mut bad_signers_nodes = vec![];
            for owner in bad_signers {
                bad_signers_nodes.push(public_to_did(&did_urls, owner)?);
            }
            log::info!("Signature success. Nodes that didn't participate: {:?}. Nodes that didn't provide a correct signature: {:?}", absent_nodes, bad_signers_nodes);

            // Publish signed DID
            let did_url = document.did_url();
            document.publish(&signature.to_vec())?;
            log::info!("Committee's DID has been published, DID URL: {}", did_url);

            let resolved_did = resolve_document(did_url.clone())?;

            if let Some(strg) = storage {
                strg.put(did_url, &resolved_did.to_bytes()?)?;
            }

            Ok((signature, dist_pub_key))
        } else {
            let did_url = document.did_url();
            log::info!("Could not sign committee's DID, DID URL: {}", did_url);
            Ok((Signature::from(vec![]), dist_pub_key))
        }
    }
}

fn public_to_did(did_urls: &[String], public_key: Point) -> Result<String> {
    for did_url in did_urls.iter() {
        if resolve_document(did_url.to_string())?.public_key()? == public_key {
            return Ok(did_url.to_string());
        }
    }
    bail!("could not find the offending DID")
}
