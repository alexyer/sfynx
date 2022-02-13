//! Sphinx packet.

use std::{fmt::Debug, marker::PhantomData};

use cryptraits::{
    convert::{Len, ToVec},
    hash::Hash,
    hmac::Hmac,
    key::{Blind, KeyPair, SecretKey},
    key_exchange::DiffieHellman,
    stream_cipher::StreamCipher,
};

use crate::{
    crypto::{generate_cipher_stream, generate_shared_secrets, xor},
    header::Header,
    Address, SfynxError, SfynxVersion, VERSION,
};

/// Sphinx packet.
pub struct Packet<A, HMAC, SC, K, H>
where
    A: Address,
    HMAC: Hmac,
    SC: StreamCipher,
    K: KeyPair + DiffieHellman + Blind,
    H: Hash,
{
    /// Sphinx packet version.
    pub version: SfynxVersion,

    /// Encrypted packet header.
    pub header: Header<A, HMAC, SC, K, H>,

    /// Encrypted payload.
    pub payload: Vec<u8>,
    _hash: PhantomData<H>,
}

impl<A, HMAC, SC, K, H> Debug for Packet<A, HMAC, SC, K, H>
where
    A: Address,
    HMAC: Hmac,
    SC: StreamCipher,
    K: KeyPair + DiffieHellman + Blind,
    H: Hash,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Packet")
            .field("version", &self.version)
            .field("header", &self.header)
            .field("payload", &self.payload)
            .finish()
    }
}

impl<A, HMAC, SC, K, H> Packet<A, HMAC, SC, K, H>
where
    A: Address,
    HMAC: Hmac + Len,
    SC: StreamCipher,
    K: KeyPair + DiffieHellman<PK = <K::SK as SecretKey>::PK> + Blind,
    <K as DiffieHellman>::SSK: ToVec,
    <<K as KeyPair>::SK as SecretKey>::PK: ToVec + Blind,
    <K as KeyPair>::SK: ToVec,
    H: Hash,
{
    /// Creates a new packet to be forwarded to the first relay in the
    /// secure circuit. It takes an ephemeral session key, the destination
    /// information (address and payload) and relay information (public keys and
    /// addresses) and constructs a cryptographically secure onion packet. The packet
    /// is then encoded and sent over the wire to the first relay. This is the entry
    /// point function for an initiator to construct a onion circuit.
    pub fn new(
        session_key: K,
        circuit_pub_keys: Vec<<K as DiffieHellman>::PK>,
        routing_info: &[A],
        max_relays: usize,
        dest: A,
        payload: &[u8],
    ) -> Result<Self, SfynxError> {
        if circuit_pub_keys.is_empty() {
            return Err(SfynxError::EmptyCircuit);
        }

        let shared_secrets =
            generate_shared_secrets::<K, H>(&circuit_pub_keys, session_key.clone())?;

        let header = Header::<A, HMAC, SC, K, H>::new(
            max_relays,
            routing_info,
            &shared_secrets,
            dest,
            session_key.clone(),
        )?;

        let payload = Self::encrypt_payload(payload, &shared_secrets)?;

        Ok(Self {
            version: VERSION,
            header,
            payload,
            _hash: Default::default(),
        })
    }

    /// Encrypts packet payload in multiple layers using the shared secrets derived
    /// from the relayers' public keys. the payload will be "peeled" as the packet
    /// traversed the circuit
    fn encrypt_payload(
        payload: &[u8],
        shared_secrets: &[<K as DiffieHellman>::SSK],
    ) -> Result<Vec<u8>, SfynxError> {
        let mut encrypted_payload = Vec::from(payload);

        for secret in shared_secrets.into_iter().rev() {
            let cipher =
                generate_cipher_stream::<SC>(&secret.to_vec(), &vec![0; 12], payload.len())
                    .or_else(|e| Err(SfynxError::StreamCipherError(format!("{:?}", e))))?;
            xor(&mut encrypted_payload, &cipher);
        }

        Ok(encrypted_payload)
    }

    fn decrypt_payload(&self, secret: &<K as DiffieHellman>::SSK) -> Result<Vec<u8>, SfynxError> {
        let mut decrypted_payload = self.payload.clone();

        let cipher =
            generate_cipher_stream::<SC>(&secret.to_vec(), &vec![0; 12], decrypted_payload.len())
                .or_else(|e| Err(SfynxError::StreamCipherError(format!("{:?}", e))))?;
        xor(&mut decrypted_payload, &cipher);

        Ok(decrypted_payload)
    }

    /// Decrypt upper layer and get underlying payload from the package.
    pub fn peel(&self, session_key: K) -> Result<(A, Self), SfynxError> {
        let shared_secret = session_key.diffie_hellman(&self.header.public_key);
        let (next_addr, header) = self.header.peel(&shared_secret)?;

        let payload = self.decrypt_payload(&shared_secret)?;

        Ok((
            next_addr,
            Self {
                version: VERSION,
                header,
                payload,
                _hash: Default::default(),
            },
        ))
    }

    pub fn is_last(&self) -> bool {
        self.header.routing_info_mac.iter().all(|i| *i == 0)
    }
}
