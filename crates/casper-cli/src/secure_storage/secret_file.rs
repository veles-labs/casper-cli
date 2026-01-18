use std::error::Error;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::RootSecret;

const STORAGE_VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// Argon2id parameters chosen for interactive CLI usage:
/// ~64 MiB memory, 3 iterations, single lane.
const KDF_MEMORY_KIB: u32 = 64 * 1024;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;

/// Encrypted secret file layout.
#[derive(Serialize, Deserialize)]
pub(crate) struct EncryptedSecretFile {
    version: u8,
    kdf: KdfParams,
    nonce: String,
    ciphertext: String,
}

/// Plaintext secret file layout (used for unencrypted wallets).
#[derive(Serialize, Deserialize)]
pub(crate) struct PlainSecretFile {
    version: u8,
    secret: RootSecret,
}

#[derive(Serialize)]
struct PlainSecretFileRef<'a> {
    version: u8,
    secret: &'a RootSecret,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum SecretFile {
    Encrypted(EncryptedSecretFile),
    Plain(PlainSecretFile),
}

/// Parameters stored alongside the ciphertext for future migrations.
#[derive(Serialize, Deserialize)]
struct KdfParams {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Debug)]
struct StorageError(String);

impl StorageError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for StorageError {}

pub(crate) fn encode_plain_secret(secret: &RootSecret) -> Result<Vec<u8>, Box<dyn Error>> {
    let plain = PlainSecretFileRef {
        version: STORAGE_VERSION,
        secret,
    };
    Ok(serde_json::to_vec_pretty(&plain)?)
}

pub(crate) fn encode_encrypted_secret(
    secret: &RootSecret,
    wallet_name: &str,
    password: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let encrypted = encrypt_secret(wallet_name, secret, password)?;
    let secret_file = SecretFile::Encrypted(encrypted);
    Ok(serde_json::to_vec_pretty(&secret_file)?)
}

pub(crate) fn parse_secret_file(data: &str) -> Result<SecretFile, Box<dyn Error>> {
    Ok(serde_json::from_str(data)?)
}

pub(crate) fn decode_secret(
    secret_file: SecretFile,
    wallet_name: &str,
    password: Option<&[u8]>,
) -> Result<RootSecret, Box<dyn Error>> {
    match secret_file {
        SecretFile::Plain(plain) => {
            if plain.version != STORAGE_VERSION {
                return Err(StorageError::new("unsupported secret version").into());
            }
            Ok(plain.secret)
        }
        SecretFile::Encrypted(encrypted) => {
            let password = password.ok_or_else(|| StorageError::new("authentication required"))?;
            decrypt_secret(wallet_name, &encrypted, password)
        }
    }
}

fn derive_key(
    params: &KdfParams,
    salt: &[u8],
    password: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Box<dyn Error>> {
    // Store algorithm identifier in the file for future migrations.
    if params.algorithm != "argon2id" {
        return Err(StorageError::new("unsupported kdf algorithm").into());
    }
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|err| StorageError::new(err.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, &mut key[..])
        .map_err(|err| StorageError::new(err.to_string()))?;
    Ok(key)
}

fn encrypt_secret(
    wallet_name: &str,
    secret: &RootSecret,
    password: &[u8],
) -> Result<EncryptedSecretFile, Box<dyn Error>> {
    // Random per-file salt and nonce avoid key/nonce reuse.
    let mut salt = [0u8; SALT_LEN];
    rand_core::OsRng.fill_bytes(&mut salt);

    let kdf = KdfParams {
        algorithm: "argon2id".to_string(),
        memory_kib: KDF_MEMORY_KIB,
        iterations: KDF_ITERATIONS,
        parallelism: KDF_PARALLELISM,
        salt: hex::encode(salt),
    };

    let key = derive_key(&kdf, &salt, password)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|err| StorageError::new(err.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce: XNonce = nonce_bytes.into();
    let plaintext = Zeroizing::new(serde_json::to_vec(secret)?);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_ref(),
                aad: wallet_name.as_bytes(),
            },
        )
        .map_err(|err| StorageError::new(err.to_string()))?;

    Ok(EncryptedSecretFile {
        version: STORAGE_VERSION,
        kdf,
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

fn decrypt_secret(
    wallet_name: &str,
    encrypted: &EncryptedSecretFile,
    password: &[u8],
) -> Result<RootSecret, Box<dyn Error>> {
    if encrypted.version != STORAGE_VERSION {
        return Err(StorageError::new("unsupported secret version").into());
    }

    let salt = hex::decode(&encrypted.kdf.salt)?;
    if salt.len() != SALT_LEN {
        return Err(StorageError::new("invalid salt length").into());
    }
    let nonce = hex::decode(&encrypted.nonce)?;
    let nonce_bytes: [u8; NONCE_LEN] = nonce
        .as_slice()
        .try_into()
        .map_err(|_| StorageError::new("invalid nonce length"))?;

    let key = derive_key(&encrypted.kdf, &salt, password)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|err| StorageError::new(err.to_string()))?;

    let ciphertext = hex::decode(&encrypted.ciphertext)?;
    let nonce: XNonce = nonce_bytes.into();
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: wallet_name.as_bytes(),
            },
        )
        .map_err(|_| {
            StorageError::new(
                "failed to decrypt wallet secret; check the master password and wallet name",
            )
        })?;

    let secret = serde_json::from_slice(&plaintext)?;
    Ok(secret)
}
