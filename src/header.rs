use std::{fmt::Debug, marker::PhantomData};

use cryptraits::{
    convert::{FromBytes, Len, ToVec},
    hash::Hash,
    hmac::Hmac,
    key::{Blind, SecretKey},
    key_exchange::DiffieHellman,
    stream_cipher::StreamCipher,
};
use zeroize::Zeroize;

use crate::{
    crypto::{
        compute_blinding_factor, compute_mac, generate_cipher_stream, generate_encryption_key,
        generate_padding, generate_shared_secrets, xor,
    },
    Address, SfynxError, ENCRYPTION, HASH,
};

#[derive(Clone, Zeroize)]
pub struct Header<A, H, SC, ESK, HASH>
where
    A: Address,
    H: Hmac,
    SC: StreamCipher,
    ESK: SecretKey + DiffieHellman,
    HASH: Hash,
{
    /// Maximum number of hops per circuit.
    max_relays: u8,

    /// Routing table for the header.
    pub routing_info: Vec<u8>,

    /// HMAC of routing_info.
    pub routing_info_mac: Vec<u8>,

    pub public_key: <ESK as SecretKey>::PK,

    #[zeroize(skip)]
    _a: PhantomData<A>,

    #[zeroize(skip)]
    _h: PhantomData<H>,

    #[zeroize(skip)]
    _sc: PhantomData<SC>,

    #[zeroize(skip)]
    _hash: PhantomData<HASH>,
}

impl<A, H, SC, ESK, HASH> Debug for Header<A, H, SC, ESK, HASH>
where
    A: Address,
    H: Hmac,
    SC: StreamCipher,
    ESK: SecretKey + DiffieHellman,
    HASH: Hash,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Header")
            .field("routing_info", &self.routing_info)
            .field("routing_info_mac", &self.routing_info_mac)
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl<A, H, SC, ESK, HASH> Drop for Header<A, H, SC, ESK, HASH>
where
    A: Address,
    H: Hmac,
    SC: StreamCipher,
    ESK: SecretKey + DiffieHellman,
    HASH: Hash,
{
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<A, H, SC, ESK, HASH> Header<A, H, SC, ESK, HASH>
where
    A: Address,
    H: Hmac + Len,
    SC: StreamCipher,
    ESK: SecretKey + DiffieHellman<PK = <ESK as SecretKey>::PK> + Blind + ToVec,
    <ESK as DiffieHellman>::SSK: ToVec,
    <ESK as SecretKey>::PK: Blind + ToVec + FromBytes,
    HASH: Hash,
{
    #[allow(clippy::type_complexity)]
    pub fn new(
        max_relays: u8,
        routing_info: &[A],
        dest: impl Address,
        session_key: ESK,
        circuit_pub_keys: Vec<<ESK as DiffieHellman>::PK>,
    ) -> Result<
        (
            Vec<<ESK as DiffieHellman>::SSK>,
            Header<A, H, SC, ESK, HASH>,
        ),
        SfynxError,
    > {
        let shared_secrets =
            generate_shared_secrets::<ESK, HASH>(&circuit_pub_keys, session_key.clone())?;

        Self::with_shared_secrets(max_relays, routing_info, dest, session_key, &shared_secrets)
    }

    #[allow(clippy::type_complexity)]
    pub fn with_shared_secrets(
        max_relays: u8,
        routing_info: &[A],
        dest: impl Address,
        session_key: ESK,
        shared_secrets: &[<ESK as DiffieHellman>::SSK],
    ) -> Result<
        (
            Vec<<ESK as DiffieHellman>::SSK>,
            Header<A, H, SC, ESK, HASH>,
        ),
        SfynxError,
    > {
        Self::validate_header_input(max_relays, routing_info)?;

        let relay_data_size: usize = A::LEN + H::LEN;
        let routing_info_size: usize = max_relays as usize * relay_data_size;
        let stream_size = routing_info_size + relay_data_size;

        let padding =
            generate_padding::<H, SC>(A::LEN, max_relays.into(), shared_secrets, &[0; 12])
                .map_err(|e| SfynxError::StreamCipherError(format!("{e:?}")))?;

        let mut routing_info_bytes = vec![0; routing_info_size];

        routing_info_bytes[routing_info_size - padding.len()..].copy_from_slice(&padding);

        let mut dest = dest.to_vec();
        let mut routing_info_mac = vec![0; H::LEN];

        for (addr, shared_secret) in routing_info.iter().zip(shared_secrets).rev() {
            let enc_key = generate_encryption_key::<H>(&shared_secret.to_vec(), ENCRYPTION);
            let mac_key = generate_encryption_key::<H>(&shared_secret.to_vec(), HASH);

            if Some(addr) != routing_info.last() {
                routing_info_bytes.rotate_right(relay_data_size);
            }

            routing_info_bytes[..A::LEN].copy_from_slice(&dest);
            routing_info_bytes[A::LEN..relay_data_size].copy_from_slice(&routing_info_mac);

            let cipher = generate_cipher_stream::<SC>(&enc_key, &[0; 12], stream_size)
                .map_err(|e| SfynxError::StreamCipherError(format!("{e:?}")))?;

            xor(&mut routing_info_bytes, &cipher[..routing_info_size]);

            if Some(addr) == routing_info.last() {
                let len = routing_info_bytes.len() - padding.len();
                routing_info_bytes[len..].copy_from_slice(&padding);
            }

            routing_info_mac = compute_mac::<H>(&mac_key, &routing_info_bytes);

            dest = addr.to_vec();
        }

        Ok((
            shared_secrets.to_vec(),
            Header {
                max_relays,
                routing_info: routing_info_bytes.to_vec(),
                routing_info_mac,
                public_key: session_key.to_public(),
                _a: Default::default(),
                _h: Default::default(),
                _sc: Default::default(),
                _hash: Default::default(),
            },
        ))
    }

    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, SfynxError> {
        let max_relays = bytes.as_ref()[0] as usize;
        let bytes = &bytes.as_ref()[1..];

        let routing_info = Vec::from(&bytes[..max_relays * (A::LEN + H::LEN)]);
        let routing_info_mac = Vec::from(
            &bytes[max_relays * (A::LEN + H::LEN)..max_relays * (A::LEN + H::LEN) + H::LEN],
        );
        let public_key =
            <ESK as SecretKey>::PK::from_bytes(&bytes[max_relays * (A::LEN + H::LEN) + H::LEN..])
                .map_err(|e| SfynxError::KeyPairError(format!("{e:?}")))?;

        let max_relays = max_relays as u8;

        Ok(Self {
            max_relays,
            routing_info,
            routing_info_mac,
            public_key,
            _a: Default::default(),
            _h: Default::default(),
            _sc: Default::default(),
            _hash: Default::default(),
        })
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, SfynxError> {
        let mut bytes = Vec::new();
        bytes.extend(&[self.max_relays]);
        bytes.extend(&self.routing_info);
        bytes.extend(&self.routing_info_mac);
        bytes.extend(&self.public_key.to_vec());

        Ok(bytes)
    }

    /// Validate header input data. Panics if data is incorrect.
    fn validate_header_input(max_relays: u8, routing_info: &[A]) -> Result<(), SfynxError>
    where
        A: Address,
    {
        if routing_info.len() > max_relays as usize {
            Err(SfynxError::WrongRoutingInfoLength)
        } else {
            Ok(())
        }
    }

    /// Process header.
    pub fn peel(
        &self,
        shared_secret: &<ESK as DiffieHellman>::SSK,
    ) -> Result<(A, Self), SfynxError> {
        let relay_data_size: usize = A::LEN + H::LEN;
        let routing_info_size: usize = self.max_relays as usize * relay_data_size;
        let stream_size = routing_info_size + relay_data_size;

        let enc_key = generate_encryption_key::<H>(&shared_secret.to_vec(), ENCRYPTION);
        let mac_key = generate_encryption_key::<H>(&shared_secret.to_vec(), HASH);

        let routing_info_mac = compute_mac::<H>(&mac_key, &self.routing_info.to_vec());

        if self.routing_info_mac != routing_info_mac {
            return Err(SfynxError::InvalidMac);
        }

        let mut routing_info = self.routing_info.clone();
        routing_info.extend(vec![0; H::LEN + A::LEN]);

        let cipher = generate_cipher_stream::<SC>(&enc_key.to_vec(), &[0; 12], stream_size)
            .map_err(|e| SfynxError::StreamCipherError(format!("{e:?}")))?;

        xor(&mut routing_info[..stream_size], &cipher);

        let next_addr = A::from_bytes(&routing_info[..A::LEN]);
        let next_routing_info_mac = Vec::from(&routing_info[A::LEN..relay_data_size]);
        let next_routing_info = Vec::from(&routing_info[relay_data_size..]);

        let blinding_factor = compute_blinding_factor::<ESK, HASH>(&self.public_key, shared_secret);

        let new_public_key = self
            .public_key
            .to_blind(&blinding_factor)
            .map_err(|e| SfynxError::KeyPairError(format!("{e:?}")))?;

        let next_header = Self {
            max_relays: self.max_relays,
            routing_info: next_routing_info,
            routing_info_mac: next_routing_info_mac,
            public_key: new_public_key,
            _a: Default::default(),
            _h: Default::default(),
            _sc: Default::default(),
            _hash: Default::default(),
        };

        Ok((next_addr, next_header))
    }
}

#[cfg(test)]
mod tests {
    use cryptimitives::{hash::sha256, hmac, key::x25519_ristretto, stream_cipher::chacha20};
    use cryptraits::{
        convert::{Len, ToVec},
        key::{Generate, SecretKey},
    };

    use crate::{crypto::generate_shared_secrets, header::Header, Address};

    #[derive(Debug, PartialEq)]
    struct TestAddress(String);

    impl Address for TestAddress {
        fn from_bytes(bytes: &[u8]) -> Self {
            Self(String::from_utf8(bytes.to_vec()).unwrap())
        }

        fn to_vec(&self) -> Vec<u8> {
            Vec::from(self.0.as_bytes())
        }
    }

    impl Len for TestAddress {
        const LEN: usize = 46;
    }

    #[test]
    fn test_new_header() {
        let num_relays = 4;
        let dest = TestAddress(String::from(
            "QmZrXVN6xNkXYqFharGfjG6CjdE3X85werKm8AyMdqsQKS",
        ));

        let relay_addrs = vec![
            TestAddress(String::from(
                "/ip4/127.0.0.1/udp/1234#0000000000000000000000",
            )),
            TestAddress(String::from(
                "QmSFXZRzh6ZdpWXXQQ2mkYtx3ns39ZPtWgQJ7sSqStiHZH",
            )),
            TestAddress(String::from(
                "/ip6/2607:f8b0:4003:c00::6a/udp/5678#000000000",
            )),
            TestAddress(String::from(
                "/ip4/198.162.0.2/tcp/4321#00000000000000000000",
            )),
        ];

        let mut circuit_keypairs = Vec::new();

        for _ in 0..num_relays {
            circuit_keypairs.push(x25519_ristretto::EphemeralSecretKey::generate());
        }

        let session_key = x25519_ristretto::EphemeralSecretKey::generate();

        let shared_secrets =
            generate_shared_secrets::<x25519_ristretto::EphemeralSecretKey, sha256::Hash>(
                &circuit_keypairs
                    .iter()
                    .map(|k| k.to_public())
                    .collect::<Vec<x25519_ristretto::EphemeralPublicKey>>(),
                session_key.clone(),
            )
            .unwrap();

        let (_, header) = Header::<
            TestAddress,
            hmac::sha256::Hmac,
            chacha20::StreamCipher,
            x25519_ristretto::EphemeralSecretKey,
            sha256::Hash,
        >::with_shared_secrets(
            num_relays, &relay_addrs, dest, session_key, &shared_secrets
        )
        .unwrap();

        // checks if there are suffixed zeros in the padding
        let mut count = 0;

        for i in header.routing_info.iter().rev() {
            if *i != 0 {
                break;
            }

            count += 1;
        }

        assert!(
            count <= 2,
            "Header is revealing number of relays. Suffixed 0s count: {}",
            count
        );
    }

    #[test]
    fn test_return_shared_secrets() {
        let num_relays = 4;
        let dest = TestAddress(String::from(
            "QmZrXVN6xNkXYqFharGfjG6CjdE3X85werKm8AyMdqsQKS",
        ));

        let routing_info = vec![
            TestAddress(String::from(
                "/ip4/127.0.0.1/udp/1234#0000000000000000000000",
            )),
            TestAddress(String::from(
                "QmSFXZRzh6ZdpWXXQQ2mkYtx3ns39ZPtWgQJ7sSqStiHZH",
            )),
            TestAddress(String::from(
                "/ip6/2607:f8b0:4003:c00::6a/udp/5678#000000000",
            )),
            TestAddress(String::from(
                "/ip4/198.162.0.2/tcp/4321#00000000000000000000",
            )),
        ];

        let mut circuit_keypairs = Vec::new();

        for _ in 0..num_relays {
            circuit_keypairs.push(x25519_ristretto::EphemeralSecretKey::generate());
        }

        let session_key = x25519_ristretto::EphemeralSecretKey::generate();

        let shared_secrets =
            generate_shared_secrets::<x25519_ristretto::EphemeralSecretKey, sha256::Hash>(
                &circuit_keypairs
                    .iter()
                    .map(|k| k.to_public())
                    .collect::<Vec<x25519_ristretto::EphemeralPublicKey>>(),
                session_key.clone(),
            )
            .unwrap();

        let (secrets, _) = Header::<
            TestAddress,
            hmac::sha256::Hmac,
            chacha20::StreamCipher,
            x25519_ristretto::EphemeralSecretKey,
            sha256::Hash,
        >::with_shared_secrets(
            num_relays,
            &routing_info,
            dest,
            session_key,
            &shared_secrets,
        )
        .unwrap();

        assert_eq!(
            secrets.iter().map(|s| s.to_vec()).collect::<Vec<Vec<u8>>>(),
            shared_secrets
                .iter()
                .map(|s| s.to_vec())
                .collect::<Vec<Vec<u8>>>()
        );
    }

    #[test]
    fn test_header_from_bytes() {
        let num_relays = 4;
        let dest = TestAddress(String::from(
            "QmZrXVN6xNkXYqFharGfjG6CjdE3X85werKm8AyMdqsQKS",
        ));

        let routing_info = vec![
            TestAddress(String::from(
                "/ip4/127.0.0.1/udp/1234#0000000000000000000000",
            )),
            TestAddress(String::from(
                "QmSFXZRzh6ZdpWXXQQ2mkYtx3ns39ZPtWgQJ7sSqStiHZH",
            )),
            TestAddress(String::from(
                "/ip6/2607:f8b0:4003:c00::6a/udp/5678#000000000",
            )),
            TestAddress(String::from(
                "/ip4/198.162.0.2/tcp/4321#00000000000000000000",
            )),
        ];

        let mut circuit_keypairs = Vec::new();

        for _ in 0..num_relays {
            circuit_keypairs.push(x25519_ristretto::EphemeralSecretKey::generate());
        }

        let session_key = x25519_ristretto::EphemeralSecretKey::generate();

        let shared_secrets =
            generate_shared_secrets::<x25519_ristretto::EphemeralSecretKey, sha256::Hash>(
                &circuit_keypairs
                    .iter()
                    .map(|k| k.to_public())
                    .collect::<Vec<x25519_ristretto::EphemeralPublicKey>>(),
                session_key.clone(),
            )
            .unwrap();

        let (_, header) = Header::<
            TestAddress,
            hmac::sha256::Hmac,
            chacha20::StreamCipher,
            x25519_ristretto::EphemeralSecretKey,
            sha256::Hash,
        >::with_shared_secrets(
            num_relays,
            &routing_info,
            dest,
            session_key,
            &shared_secrets,
        )
        .unwrap();

        let bytes = header.to_vec().unwrap();
        let header_from_bytes = Header::<
            TestAddress,
            hmac::sha256::Hmac,
            chacha20::StreamCipher,
            x25519_ristretto::EphemeralSecretKey,
            sha256::Hash,
        >::from_bytes(&bytes)
        .unwrap();

        assert_eq!(header_from_bytes.routing_info, header.routing_info);
        assert_eq!(header_from_bytes.routing_info_mac, header.routing_info_mac);
        assert_eq!(header_from_bytes.public_key, header.public_key);
    }
}
