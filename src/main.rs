
use std::{num::ParseIntError, sync::{Mutex, Arc}, str::FromStr};

use chrono::Utc;
use ethers_core::types::transaction::eip712::Eip712;
use ethers_derive_eip712::*;
use prost::Message;
use serde::{Deserialize, Serialize};
use ethers_core::{
    k256::ecdsa::SigningKey,
    types::{transaction::eip712::Eip712Error, Signature},
};
use ethers::signers::{Signer, Wallet};

use ethers_contract::EthAbiType;
use async_graphql::SimpleObject;
use waku::{WakuNodeHandle, Running, WakuPubSubTopic, WakuContentTopic, WakuMessage};
use url::ParseError;


#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    #[error("The subgraph is in a failed state")]
    IndexingError,
    #[error("Query response is unexpected: {0}")]
    ParseResponseError(String),
    #[error("Query response is empty: {0}")]
    PrometheusError(#[from] prometheus_http_query::Error),
    #[error("Unknown error: {0}")]
    Other(anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum WakuHandlingError {
    #[error(transparent)]
    ParseUrlError(#[from] ParseError),
    #[error("Subscription error to the content topic. {}", .0)]
    ContentTopicsError(String),
    #[error("Unable to retrieve peers list. {}", .0)]
    RetrievePeersError(String),
    #[error("Unable to publish message to peer: {}", .0)]
    PublishMessage(String),
    #[error("Unable to validate a message from peer: {}", .0)]
    InvalidMessage(String),
    #[error(transparent)]
    ParsePortError(#[from] ParseIntError),
    #[error("Unable to create  node: {}", .0)]
    CreateNodeError(String),
    #[error("Unable to stop  node: {}", .0)]
    StopNodeError(String),
    #[error("Unable to get peer println!rmation: {}", .0)]
    PeerInfoError(String),
    #[error(transparent)]
    QueryResponseError(#[from] QueryError),
    #[error("Unknown error: {0}")]
    Other(anyhow::Error),
}

impl WakuHandlingError {
    pub fn type_string(&self) -> &str {
        match self {
            WakuHandlingError::ParseUrlError(_) => "ParseUrlError",
            WakuHandlingError::ContentTopicsError(_) => "ContentTopicsError",
            WakuHandlingError::RetrievePeersError(_) => "RetrievePeersError",
            WakuHandlingError::PublishMessage(_) => "PublishMessage",
            WakuHandlingError::InvalidMessage(_) => "InvalidMessage",
            WakuHandlingError::ParsePortError(_) => "ParsePortError",
            WakuHandlingError::CreateNodeError(_) => "CreateNodeError",
            WakuHandlingError::StopNodeError(_) => "StopNodeError",
            WakuHandlingError::PeerInfoError(_) => "PeerInfoError",
            WakuHandlingError::QueryResponseError(_) => "QueryResponseError",
            WakuHandlingError::Other(_) => "Other",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkBlockError {
    #[error("Unsupported network: {0}")]
    UnsupportedNetwork(String),
    #[error("Failed to query syncing status of the network: {0}")]
    FailedStatus(String),
    #[error("Cannot get network's block println!rmation: {0}")]
    Other(anyhow::Error),
}


#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("Radio payload failed to satisfy the defined Eip712 typing")]
    Payload,
    #[error("Could not sign payload")]
    Signing,
    #[error("Could not encode message")]
    Encoding,
    #[error("Could not decode message")]
    Decoding,
    #[error("Could not pass message validity checks: {0}")]
    InvalidFields(anyhow::Error),
    #[error("Could not build message with Network and BlockPointer: {0}")]
    Network(NetworkBlockError),
    #[error("Could not derive fields from the existing message: {0}")]
    FieldDerivations(QueryError),
    #[error("{0}")]
    TypeCast(String),
}

//TODO: add required functions for RadioPayload, such as
// Build, new, validations, ...; may need to be async trait for valid checks
pub trait RadioPayload:
    Message
    + ethers::types::transaction::eip712::Eip712<Error = Eip712Error>
    + Default
    + Clone
    + 'static
    + Serialize
    + async_graphql::OutputType
{
    // type ExternalValidation;
    // async fn validity_check(&self, gc: GraphcastMessage<Self>, input: Self::ExternalValidation) -> Result<&Self, MessageError>;

    fn valid_outer(&self, outer: &GraphcastMessage<Self>) -> Result<&Self, MessageError>;
}


#[derive(Eip712, EthAbiType, Clone, Message, Serialize, Deserialize, PartialEq, SimpleObject)]
#[eip712(
    name = "UpgradeIntentMessage",
    version = "0",
    chain_id = 1,
    verifying_contract = "0xc944e90c64b2c07662a292be6244bdf05cda44a7"
)]
pub struct UpgradeIntentMessage {
    /// current subgraph deployment hash
    #[prost(string, tag = "1")]
    pub deployment: String,
    /// subgraph id shared by both versions of the subgraph deployment
    #[prost(string, tag = "2")]
    pub subgraph_id: String,
    // new version of the subgraph has a new deployment hash
    #[prost(string, tag = "3")]
    pub new_hash: String,
    /// nonce cached to check against the next incoming message
    #[prost(uint64, tag = "4")]
    pub nonce: u64,
    /// Graph account sender - expect the sender to be subgraph owner
    #[prost(string, tag = "5")]
    pub graph_account: String,
}

impl RadioPayload for UpgradeIntentMessage {
    /// Check duplicated fields: payload message has duplicated fields with GraphcastMessage, the values must be the same
    fn valid_outer(&self, outer: &GraphcastMessage<Self>) -> Result<&Self, MessageError> {
        if self.nonce == outer.nonce && self.graph_account == outer.graph_account {
            Ok(self)
        } else {
            Err(MessageError::InvalidFields(anyhow::anyhow!(
                "Radio message wrapped by inconsistent GraphcastMessage: {:#?} <- {:#?}",
                &self,
                &outer,
            )))
        }
    }
}
/// GraphcastMessage type casts over radio payload
#[derive(Clone, Message, Serialize, Deserialize, SimpleObject)]
pub struct GraphcastMessage<T: RadioPayload> {
    /// Graph identifier for the entity the radio is communicating about
    #[prost(string, tag = "1")]
    pub identifier: String,
    /// nonce cached to check against the next incoming message
    #[prost(uint64, tag = "3")]
    pub nonce: u64,
    /// Graph account sender
    #[prost(string, tag = "4")]
    pub graph_account: String,
    /// content to share about the identified entity
    #[prost(message, required, tag = "2")]
    pub payload: T,
    /// signature over radio payload
    #[prost(string, tag = "5")]
    pub signature: String,
}

impl<T: RadioPayload> GraphcastMessage<T> {
    /// Create a graphcast message
    pub fn new(
        identifier: String,
        nonce: u64,
        graph_account: String,
        payload: T,
        signature: String,
    ) -> Result<Self, MessageError> {
        Ok(GraphcastMessage {
            identifier,
            nonce,
            graph_account,
            payload,
            signature,
        })
    }

    /// Signs the radio payload and construct graphcast message
    pub async fn build(
        wallet: &Wallet<SigningKey>,
        identifier: String,
        graph_account: String,
        nonce: u64,
        payload: T,
    ) -> Result<Self, MessageError> {
        let sig = wallet
            .sign_typed_data(&payload)
            .await
            .map_err(|_| MessageError::Signing)?;

        GraphcastMessage::new(identifier, nonce, graph_account, payload, sig.to_string())
    }

    /// Send Graphcast message to the Waku relay network
    pub fn send_to_waku(
        &self,
        node_handle: &WakuNodeHandle<Running>,
        pubsub_topic: WakuPubSubTopic,
        content_topic: WakuContentTopic,
    ) -> Result<String, WakuHandlingError> {
        let mut buff = Vec::new();
        Message::encode(self, &mut buff).expect("Could not encode :(");

        let waku_message = WakuMessage::new(
            buff,
            content_topic,
            2,
            Utc::now().timestamp() as usize,
            vec![],
            true,
        );
        println!( "Sending message");

        node_handle
            .relay_publish_message(&waku_message, Some(pubsub_topic.clone()), None)
            .map_err(|e| {
                println!(
                    "Failed to relay publish the message"
                );
                WakuHandlingError::PublishMessage(e)
            })
    }

    /// Recover sender address from Graphcast message radio payload
    /// Recover sender address from Graphcast message radio payload
    pub fn recover_sender_address(&self) -> Result<String, MessageError> {
        // Log the decoded message
        println!("Decoded message: {:?}", self);

        let signed_data = match self.payload.encode_eip712() {
            Ok(data) => {
                // Log the encoded message
                println!("Encoded EIP-712 message: {:?}", data);
                data
            },
            Err(e) => {
                println!("Error encoding message for EIP-712: {}", e);
                return Err(MessageError::InvalidFields(e.into()));
            }
        };

        match Signature::from_str(&self.signature) {
            Ok(sig) => {
                match sig.recover(signed_data) {
                    Ok(addr) => {
                        // Log the recovered address
                        println!("Recovered address: {}", addr);
                        Ok(format!("{:?}", addr))
                    },
                    Err(e) => {
                        println!("Failed to recover address: {}", e);
                        Err(MessageError::InvalidFields(e.into()))
                    },
                }
            },
            Err(e) => {
                println!("Failed to parse signature: {}", e);
                Err(MessageError::InvalidFields(e.into()))
            },
        }
    }

    pub fn decode(payload: &[u8]) -> Result<Self, WakuHandlingError> {
        <GraphcastMessage<T> as Message>::decode(payload).map_err(|e| {
            WakuHandlingError::InvalidMessage(format!(
                "Waku message not interpretated as a Graphcast message\nError occurred: {e:?}"
            ))
        })
    }
}


pub fn main() {

}