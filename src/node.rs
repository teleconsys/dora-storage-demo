use std::sync::mpsc::{Receiver, Sender};

use crate::broadcast::LocalBroadcast;
use crate::did::{new_document, resolve_document};
use crate::dkg::{DistPublicKey, DkgMessage, DkgTerminalStates, Initializing};
use crate::feed::{Feed, MessageWrapper};
use crate::fsm::StateMachine;
use crate::store::Storage;
use anyhow::{Ok, Result};
use kyber_rs::encoding::BinaryMarshaler;
use kyber_rs::group::edwards25519::Curve;
use kyber_rs::sign::eddsa::EdDSA;

use crate::sign::{self, SignMessage, SignTerminalStates, Signature};
use kyber_rs::{group::edwards25519::Point, util::key::Pair};

pub struct Node {
    keypair: EdDSA<Curve>,
    dkg_input_channel: Receiver<MessageWrapper<DkgMessage>>,
    sign_input_channel: Receiver<MessageWrapper<SignMessage>>,
    dkg_output_channel: Sender<MessageWrapper<DkgMessage>>,
    sign_output_channel: Sender<MessageWrapper<SignMessage>>,
    id: usize,
}

impl Node {
    pub fn new(
        keypair: EdDSA<Curve>,
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
        keypair: EdDSA<Curve>,
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
        storage: Storage,
        did_network: Option<String>,
        num_participants: usize,
    ) -> Result<(Signature, DistPublicKey), anyhow::Error> {
        let secret = self.keypair.secret.clone();
        let public = self.keypair.public.clone();
        let dkg_initial_state = Initializing::new(self.keypair, num_participants);
        let mut dkg_fsm = StateMachine::new(
            Box::new(dkg_initial_state),
            Feed::new(self.dkg_input_channel, public.clone()),
            self.dkg_output_channel,
            self.id,
            public.clone(),
        );
        let dkg_terminal_state = dkg_fsm.run()?;
        let DkgTerminalStates::Completed { dkg } = dkg_terminal_state;
        let dist_pub_key = dkg.dist_key_share()?.public();

        let mut network = "iota-dev".to_owned();
        if let Some(net) = did_network.clone() {
            network = net;
        }
        // Create unsigned DID
        let document = new_document(&dist_pub_key.marshal_binary()?, &network, Some(20))?;

        let sign_initial_state = sign::InitializingBuilder::try_from(dkg)?
            .with_message(document.to_bytes()?)
            .with_secret(secret)
            .build()?;

        let mut sign_fsm = StateMachine::new(
            Box::new(sign_initial_state),
            Feed::new(self.sign_input_channel, public.clone()),
            self.sign_output_channel,
            self.id,
            public,
        );

        let sign_terminal_state = sign_fsm.run()?;

        let SignTerminalStates::Completed(signature) = sign_terminal_state;

        if let Some(_) = did_network {
            // Publish signed DID
            let did_url = document.did_url();
            document.publish(&signature.to_vec())?;
            log::info!("Committee's DID has been published, DID URL: {}", did_url);

            let resolved_did = resolve_document(did_url)?;
        }

        Ok((signature, dist_pub_key))
    }
}
