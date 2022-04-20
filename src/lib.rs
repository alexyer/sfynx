//! General-purpose onion routing packet construction and processor based on Sphinx.
#![feature(explicit_generic_args_with_impl_trait)]

use core::fmt::Debug;
use cryptraits::convert::Len;

pub mod crypto;
pub mod header;
pub mod packet;

pub type SfynxVersion = u8;

const VERSION: u8 = 1;
const HASH: &[u8] = b"alexyer.hash";
const ENCRYPTION: &[u8] = b"alexyer.encryption";

/// Sfynx address.
pub trait Address: Debug + Len + PartialEq {
    fn from_bytes(bytes: &[u8]) -> Self;
    fn to_vec(&self) -> Vec<u8>;
}

#[derive(Debug)]
pub enum SfynxError {
    WrongRoutingInfoLength,
    StreamCipherError(String),
    EmptyCircuit,
    KeyPairError(String),
    InvalidMac,
}

#[cfg(feature = "std")]
impl std::fmt::Display for SfynxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            SfynxError::WrongRoutingInfoLength => String::from("WrongRoutingInfoLength"),
            SfynxError::StreamCipherError(e) => format!("StreamCipherError({})", e),
            SfynxError::EmptyCircuit => String::from("EmptyCircuit"),
            SfynxError::KeyPairError(e) => format!("KeyPairError({})", e),
            SfynxError::InvalidMac => String::from("InvalidMac"),
        };

        f.write_str(&message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SfynxError {}

#[cfg(test)]
mod tests {
    use cryptimitives::{hash, hmac, key::x25519_ristretto, stream_cipher::chacha20};
    use cryptraits::{
        convert::Len,
        key::{Generate, SecretKey},
    };

    use crate::{packet::Packet, Address};

    #[derive(Debug, PartialEq, Clone)]
    struct TestAddress(String);

    impl Address for TestAddress {
        fn to_vec(&self) -> Vec<u8> {
            Vec::from(self.0.as_bytes())
        }

        fn from_bytes(bytes: &[u8]) -> Self {
            Self(String::from_utf8(bytes.to_vec()).unwrap())
        }
    }

    impl Len for TestAddress {
        const LEN: usize = 46;
    }

    #[test]
    fn test_e2e() {
        let max_relays = 4;
        let dest = TestAddress(String::from(
            "/ip6/2607:f8b0:4003:c01::6a/udp/5678#000000000",
        ));
        let routing_info = vec![
            TestAddress(String::from(
                "QmQV4LdB3jDKEZxB1EGoutUYyRSt8H8oW4B6DoBLB9z6b7",
            )),
            TestAddress(String::from(
                "/ip4/127.0.0.1/udp/1234#0000000000000000000000",
            )),
            TestAddress(String::from(
                "QmPxawpH7ymXENBZcbKpV3NTxMc4fs37gmREn8e9C2kgNe",
            )),
            TestAddress(String::from(
                "/ip4/120.120.0.2/tcp/1222#00000000000000000000",
            )),
        ];

        let mut circuit_keypairs = Vec::new();
        let mut circuit_pub_keys = Vec::new();

        for _ in 0..max_relays {
            let secret = x25519_ristretto::EphemeralSecretKey::generate();
            circuit_pub_keys.push(secret.to_public());
            circuit_keypairs.push(secret);
        }

        let session_key = x25519_ristretto::EphemeralSecretKey::generate();

        let mut payload = [0; 256];
        payload[..13].copy_from_slice(b"Hello, Sfynx!");

        let (_, mut new_packet) =
            Packet::<_, hmac::sha256::Hmac, chacha20::StreamCipher, _, hash::sha256::Hash>::new(
                session_key,
                circuit_pub_keys,
                &routing_info,
                dest.clone(),
                max_relays,
                &payload,
            )
            .unwrap();

        for (keypair, _) in circuit_keypairs
            .iter()
            .zip(routing_info.into_iter().skip(1))
        {
            assert_eq!(new_packet.payload.len(), 256);

            assert_ne!(
                &new_packet.payload, &payload,
                "Payload was not successfully ENCRYPTED"
            );

            let (_, _, packet) = new_packet.peel(keypair).unwrap();
            new_packet = packet;
        }

        let (_, _, final_packet) = new_packet.peel(circuit_keypairs.last().unwrap()).unwrap();

        assert!(final_packet.is_last());
        assert_eq!(final_packet.payload, payload);
    }
}
