//! Sphinx packet.

use std::{fmt::Debug, marker::PhantomData};

use cryptraits::{
    convert::{FromBytes, Len, ToVec},
    hash::Hash,
    hmac::Hmac,
    key::{Blind, SecretKey},
    key_exchange::DiffieHellman,
    stream_cipher::StreamCipher,
};

use crate::{
    crypto::{generate_cipher_stream, generate_shared_secrets, xor},
    header::Header,
    Address, SfynxError, SfynxVersion, VERSION,
};

/// Sphinx packet.
pub struct Packet<A, HMAC, SC, ESK, H>
where
    A: Address,
    HMAC: Hmac,
    SC: StreamCipher,
    ESK: SecretKey + DiffieHellman + Blind,
    H: Hash,
{
    /// Sphinx packet version.
    pub version: SfynxVersion,

    /// Encrypted packet header.
    pub header: Header<A, HMAC, SC, ESK, H>,

    /// Encrypted payload.
    pub payload: Vec<u8>,
    _hash: PhantomData<H>,
}

impl<A, HMAC, SC, ESK, H> Debug for Packet<A, HMAC, SC, ESK, H>
where
    A: Address,
    HMAC: Hmac,
    SC: StreamCipher,
    ESK: SecretKey + DiffieHellman + Blind,
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

impl<A, HMAC, SC, ESK, H> Packet<A, HMAC, SC, ESK, H>
where
    A: Address,
    HMAC: Hmac + Len,
    SC: StreamCipher,
    ESK: SecretKey + DiffieHellman<PK = <ESK as SecretKey>::PK> + Blind + ToVec,
    <ESK as SecretKey>::PK: Blind + ToVec + FromBytes,
    <ESK as DiffieHellman>::SSK: ToVec,
    H: Hash,
{
    /// Creates a new packet to be forwarded to the first relay in the
    /// secure circuit. It takes an ephemeral session key, the destination
    /// information (address and payload) and relay information (public keys and
    /// addresses) and constructs a cryptographically secure onion packet. The packet
    /// is then encoded and sent over the wire to the first relay. This is the entry
    /// point function for an initiator to construct a onion circuit.
    pub fn new(
        session_key: ESK,
        circuit_pub_keys: Vec<<ESK as DiffieHellman>::PK>,
        routing_info: &[A],
        dest: impl Address,
        max_relays: usize,
        payload: &[u8],
    ) -> Result<(Vec<<ESK as DiffieHellman>::SSK>, Self), SfynxError> {
        let shared_secrets =
            generate_shared_secrets::<ESK, H>(&circuit_pub_keys, session_key.clone())?;

        Self::with_shared_secrets(
            session_key,
            circuit_pub_keys,
            routing_info,
            dest,
            max_relays,
            payload,
            &shared_secrets,
        )
    }

    pub fn with_shared_secrets(
        session_key: ESK,
        circuit_pub_keys: Vec<<ESK as DiffieHellman>::PK>,
        routing_info: &[A],
        dest: impl Address,
        max_relays: usize,
        payload: &[u8],
        shared_secrets: &[<ESK as DiffieHellman>::SSK],
    ) -> Result<(Vec<<ESK as DiffieHellman>::SSK>, Self), SfynxError> {
        if circuit_pub_keys.is_empty() {
            return Err(SfynxError::EmptyCircuit);
        }

        let (_, header) = Header::<A, HMAC, SC, ESK, H>::with_shared_secrets(
            max_relays,
            routing_info,
            dest,
            session_key,
            shared_secrets,
        )?;

        let payload = Self::encrypt_payload(payload, shared_secrets)?;

        Ok((
            shared_secrets.to_vec(),
            Self {
                version: VERSION,
                header,
                payload,
                _hash: Default::default(),
            },
        ))
    }

    pub fn from_bytes(
        header_bytes: impl AsRef<[u8]>,
        payload_bytes: impl AsRef<[u8]>,
        max_relays: usize,
    ) -> Result<Self, SfynxError> {
        let header = Header::from_bytes(header_bytes, max_relays)?;
        let payload = Vec::from(payload_bytes.as_ref());

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
        shared_secrets: &[<ESK as DiffieHellman>::SSK],
    ) -> Result<Vec<u8>, SfynxError> {
        let mut encrypted_payload = Vec::from(payload);

        for secret in shared_secrets.iter().rev() {
            Self::wrap(&mut encrypted_payload, secret)?;
        }

        Ok(encrypted_payload)
    }

    /// Decrypt payload in-place with provided `secret` key.
    ///
    /// # Safety
    /// Unsafe because it ignores header integrity.
    /// Should be used with caution.
    pub unsafe fn decrypt_payload(
        &self,
        payload: &mut [u8],
        secret: &<ESK as DiffieHellman>::SSK,
    ) -> Result<(), SfynxError> {
        let cipher = generate_cipher_stream::<SC>(&secret.to_vec(), &[0; 12], payload.len())
            .map_err(|e| SfynxError::StreamCipherError(format!("{:?}", e)))?;
        xor(payload, &cipher);

        Ok(())
    }

    /// Wrap payload in an onion encryption layer in-place.
    pub fn wrap(
        payload: &mut [u8],
        secret: &<ESK as DiffieHellman>::SSK,
    ) -> Result<(), SfynxError> {
        let cipher = generate_cipher_stream::<SC>(&secret.to_vec(), &[0; 12], payload.len())
            .map_err(|e| SfynxError::StreamCipherError(format!("{:?}", e)))?;
        xor(payload, &cipher);

        Ok(())
    }

    /// Decrypt upper layer and get underlying payload from the package.
    pub fn peel(
        &self,
        session_key: ESK,
    ) -> Result<(<ESK as DiffieHellman>::SSK, A, Self), SfynxError> {
        let shared_secret = session_key.diffie_hellman(&self.header.public_key);
        let (next_addr, header) = self.header.peel(&shared_secret)?;

        let mut payload = self.payload.clone();
        unsafe { self.decrypt_payload(&mut payload, &shared_secret)? };

        Ok((
            shared_secret,
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
