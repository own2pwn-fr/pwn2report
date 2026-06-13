//! Age passphrase encryption for the sync bundle.
//!
//! A bundle is encrypted with age's scrypt (passphrase) recipient — the same
//! primitive the `age` CLI uses for `age -p`. The output is a self-describing
//! age file: no separate salt/nonce bookkeeping on our side. A wrong passphrase
//! on decrypt surfaces as [`AppError::Sync`] (never a panic).
//!
//! API verified against the installed `age` 0.11.3 source:
//! - `age::Encryptor::with_user_passphrase(SecretString) -> Encryptor`
//! - `Encryptor::wrap_output(W) -> io::Result<StreamWriter<W>>`, then
//!   `StreamWriter::write_all` + `StreamWriter::finish()`
//! - `age::Decryptor::new(R) -> Result<Decryptor, DecryptError>`,
//!   `Decryptor::decrypt(impl Iterator<Item=&dyn Identity>) -> StreamReader`
//! - `age::scrypt::Identity::new(SecretString)` as the decrypt identity
//! - secrecy 0.10: `SecretString::from(String)` (no `Secret::new`)

use std::io::{Read, Write};

use age::secrecy::SecretString;

use crate::error::{AppError, AppResult};

/// Encrypt `plaintext` under `passphrase`, returning the age ciphertext bytes.
/// In-memory convenience used by tests; production export streams via
/// [`encrypt_to_writer`] to bound peak memory.
#[cfg(test)]
pub fn encrypt(passphrase: &str, plaintext: &[u8]) -> AppResult<Vec<u8>> {
    let mut out = Vec::new();
    encrypt_to_writer(passphrase, plaintext, &mut out)?;
    Ok(out)
}

/// Age-encrypt `plaintext` under `passphrase`, streaming the ciphertext directly
/// into `dest` (any `Write`). This avoids materializing the whole ciphertext in
/// a `Vec` first: the export path wraps a `BufWriter<File>` so peak memory stays
/// bounded by ~one copy of the payload (the plaintext JSON) instead of holding
/// plaintext + ciphertext + the file buffer all at once.
pub fn encrypt_to_writer<W: Write>(passphrase: &str, plaintext: &[u8], dest: W) -> AppResult<()> {
    let secret = SecretString::from(passphrase.to_owned());
    let encryptor = age::Encryptor::with_user_passphrase(secret);

    let mut writer = encryptor
        .wrap_output(dest)
        .map_err(|e| AppError::Sync(format!("encryption setup failed: {e}")))?;
    writer
        .write_all(plaintext)
        .map_err(|e| AppError::Sync(format!("encryption write failed: {e}")))?;
    writer
        .finish()
        .map_err(|e| AppError::Sync(format!("encryption finalize failed: {e}")))?;
    Ok(())
}

/// Decrypt age `ciphertext` with `passphrase`. A wrong passphrase or a file that
/// is not a passphrase-encrypted age file surfaces as [`AppError::Sync`].
pub fn decrypt(passphrase: &str, ciphertext: &[u8]) -> AppResult<Vec<u8>> {
    let decryptor = age::Decryptor::new(ciphertext)
        .map_err(|e| AppError::Sync(format!("not a valid sync bundle: {e}")))?;

    // Guard: only passphrase (scrypt) bundles are produced by `export`. Reject
    // recipient-key files with a clear message rather than a confusing "wrong
    // passphrase".
    if !decryptor.is_scrypt() {
        return Err(AppError::Sync(
            "sync bundle is not passphrase-encrypted".into(),
        ));
    }

    let secret = SecretString::from(passphrase.to_owned());
    let identity = age::scrypt::Identity::new(secret);

    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        // A wrong passphrase shows up here (NoMatchingKeys / DecryptionFailed).
        .map_err(|_| AppError::Sync("wrong passphrase or corrupt sync bundle".into()))?;

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| AppError::Sync(format!("decryption read failed: {e}")))?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let pass = "correct horse battery staple";
        let msg = b"top secret sync bundle payload \x00\xff";
        let ct = encrypt(pass, msg).unwrap();
        // Ciphertext must not contain the plaintext verbatim.
        assert_ne!(ct, msg);
        let pt = decrypt(pass, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn wrong_passphrase_fails_cleanly() {
        let ct = encrypt("right-passphrase", b"hello world").unwrap();
        let err = decrypt("wrong-passphrase", &ct).unwrap_err();
        assert!(matches!(err, AppError::Sync(_)));
    }

    #[test]
    fn garbage_input_is_a_sync_error() {
        let err = decrypt("whatever", b"this is not an age file").unwrap_err();
        assert!(matches!(err, AppError::Sync(_)));
    }
}
