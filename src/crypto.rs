use cryptraits::{
    convert::{Len, ToVec},
    hash::Hash,
    hmac::Hmac,
    key::{Blind, SecretKey, SharedSecretKey},
    key_exchange::DiffieHellman,
    stream_cipher::StreamCipher,
};

use crate::{SfynxError, ENCRYPTION};

// Generate cipher stream of size numBytes.
pub(crate) fn generate_cipher_stream<SC>(
    key: &[u8],
    nonce: &[u8],
    num_bytes: usize,
) -> Result<Vec<u8>, SC::E>
where
    SC: StreamCipher,
{
    let mut cipher = SC::new_from_slices(key, nonce)?;

    let mut out = vec![0; num_bytes];
    cipher.apply_keystream(out.as_mut_slice())?;

    Ok(out)
}

/// Xor slices in-place.
pub(crate) fn xor(a: &mut [u8], b: &[u8]) {
    for (x, y) in a.iter_mut().zip(b) {
        *x ^= y;
    }
}

// Computes blinding factor used for blinding the cyclic group element at each
// hop. The blinding factor is computed by hashing the concatenation of the
// hop's public key and the secret key derived between the sender and the hop
pub(crate) fn compute_blinding_factor<ESK, H>(
    public: &<ESK as SecretKey>::PK,
    shared: &ESK::SSK,
) -> Vec<u8>
where
    ESK: SecretKey + DiffieHellman,
    H: Hash,
    <ESK as SecretKey>::PK: ToVec,
    ESK::SSK: ToVec,
{
    let mut hasher = H::new();

    hasher.update(&public.to_vec());
    hasher.update(&shared.to_vec());

    hasher.finalize()
}

pub(crate) fn generate_shared_secrets<ESK, H>(
    circuit_pub_keys: &[<ESK as DiffieHellman>::PK],
    mut session_key: ESK,
) -> Result<Vec<<ESK as DiffieHellman>::SSK>, SfynxError>
where
    ESK: SecretKey + DiffieHellman + Blind + ToVec,
    <ESK as SecretKey>::PK: ToVec,
    ESK::SSK: ToVec,
    H: Hash,
{
    if circuit_pub_keys.is_empty() {
        return Err(SfynxError::EmptyCircuit);
    }

    let mut shared_secrets: Vec<<ESK as DiffieHellman>::SSK> =
        Vec::with_capacity(circuit_pub_keys.len());

    for public in circuit_pub_keys {
        let shared_secret = session_key.diffie_hellman(public);
        let blinding_factor =
            compute_blinding_factor::<ESK, H>(&session_key.to_public(), &shared_secret);

        session_key
            .blind(&blinding_factor)
            .map_err(|e| SfynxError::KeyPairError(format!("{:?}", e)))?;

        shared_secrets.push(shared_secret);
    }

    Ok(shared_secrets)
}

pub(crate) fn generate_padding<H, SC>(
    addr_size: usize,
    max_relays: usize,
    shared_secrets: &[impl SharedSecretKey + ToVec],
    nonce: &[u8],
) -> Result<Vec<u8>, SC::E>
where
    H: Hmac + Len,
    SC: StreamCipher,
{
    let mut padding = Vec::new();

    let shared_secrets_num = shared_secrets.len();
    for key in shared_secrets.iter().take(shared_secrets_num - 1) {
        padding.extend(vec![0; addr_size + H::LEN]);
        let key = generate_encryption_key::<H>(&key.to_vec(), ENCRYPTION);
        let cipher = generate_cipher_stream::<SC>(
            &key,
            nonce,
            max_relays * (addr_size + H::LEN) + (addr_size + H::LEN),
        )?;

        let padding_len = padding.len();

        xor(&mut padding, &cipher[cipher.len() - padding_len..]);
    }

    Ok(padding)
}

pub(crate) fn generate_encryption_key<H>(key: &[u8], data: &[u8]) -> Vec<u8>
where
    H: Hmac,
{
    compute_mac::<H>(key, data)
}

pub(crate) fn compute_mac<H>(key: &[u8], data: &[u8]) -> Vec<u8>
where
    H: Hmac,
{
    let mut hmac = H::new_from_slice(key).expect("Correct MAC");
    hmac.update(data);

    hmac.finalize()
}
