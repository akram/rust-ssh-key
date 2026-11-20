//! AES-CBC/AES-CTR/AES-GCM via system OpenSSL, for environments that
//! require all cryptographic operations to go through a FIPS-certifiable
//! OpenSSL build. One-shot only (whole-buffer), matching this crate's own
//! `Cipher::encrypt`/`decrypt` contract -- unlike SSH *packet* encryption,
//! OpenSSH private-key-file and PPK encryption never spans more than one
//! call, so there is no cross-call IV/counter state to carry here.
//!
//! This crate is `no_std` with no `alloc` dependency, so unlike the
//! `openssl::symm::{encrypt,decrypt,encrypt_aead,decrypt_aead}` convenience
//! functions (which allocate a `Vec`), everything here is processed through
//! a fixed-size stack scratch buffer, chunk by chunk.

use openssl::symm::{Cipher as OsslCipher, Crypter, Mode};

use crate::{Cipher, Error, Result, Tag};

/// Chunk size for `Crypter::update` calls; an arbitrary multiple of the AES
/// block size (16), small enough to live on the stack, large enough that a
/// typical key blob (at most a few KiB) needs only a handful of calls.
const CHUNK: usize = 256;

fn ossl_cbc_cipher(cipher: Cipher) -> Result<OsslCipher> {
    match cipher {
        Cipher::Aes128Cbc => Ok(OsslCipher::aes_128_cbc()),
        Cipher::Aes192Cbc => Ok(OsslCipher::aes_192_cbc()),
        Cipher::Aes256Cbc => Ok(OsslCipher::aes_256_cbc()),
        Cipher::Aes128Ctr => Ok(OsslCipher::aes_128_ctr()),
        Cipher::Aes192Ctr => Ok(OsslCipher::aes_192_ctr()),
        Cipher::Aes256Ctr => Ok(OsslCipher::aes_256_ctr()),
        _ => Err(Error::UnsupportedCipher(cipher)),
    }
}

fn ossl_gcm_cipher(cipher: Cipher) -> Result<OsslCipher> {
    match cipher {
        Cipher::Aes128Gcm => Ok(OsslCipher::aes_128_gcm()),
        Cipher::Aes256Gcm => Ok(OsslCipher::aes_256_gcm()),
        _ => Err(Error::UnsupportedCipher(cipher)),
    }
}

/// Feeds `buffer` through `crypter` in fixed-size chunks, overwriting it
/// in place with the result. Each chunk's `update()` call is expected to
/// emit exactly as many bytes as it was fed -- true for a no-padding block
/// transform fed block-aligned input, and for a stream/AEAD cipher fed any
/// input -- so a mismatch is treated as a hard error rather than buffered.
fn process_in_place(crypter: &mut Crypter, buffer: &mut [u8]) -> Result<()> {
    let mut scratch = [0u8; CHUNK + 32];
    let mut pos = 0;
    while pos < buffer.len() {
        let end = (pos + CHUNK).min(buffer.len());
        let n = crypter
            .update(&buffer[pos..end], &mut scratch)
            .map_err(|_| Error::Crypto)?;
        if n != end - pos {
            return Err(Error::Crypto);
        }
        buffer[pos..end].copy_from_slice(&scratch[..n]);
        pos = end;
    }
    let mut tail = [0u8; 32];
    let n = crypter.finalize(&mut tail).map_err(|_| Error::Crypto)?;
    if n != 0 {
        return Err(Error::Crypto);
    }
    Ok(())
}

pub(crate) fn decrypt_block(cipher: Cipher, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<()> {
    if buffer.len() % cipher.block_size() != 0 {
        return Err(Error::Length);
    }
    let mut crypter =
        Crypter::new(ossl_cbc_cipher(cipher)?, Mode::Decrypt, key, Some(iv)).map_err(|_| Error::Crypto)?;
    crypter.pad(false);
    process_in_place(&mut crypter, buffer)
}

pub(crate) fn encrypt_block(cipher: Cipher, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<()> {
    if buffer.len() % cipher.block_size() != 0 {
        return Err(Error::Length);
    }
    let mut crypter =
        Crypter::new(ossl_cbc_cipher(cipher)?, Mode::Encrypt, key, Some(iv)).map_err(|_| Error::Crypto)?;
    crypter.pad(false);
    process_in_place(&mut crypter, buffer)
}

pub(crate) fn decrypt_aead(
    cipher: Cipher,
    key: &[u8],
    iv: &[u8],
    buffer: &mut [u8],
    tag: Option<Tag>,
) -> Result<()> {
    let tag = tag.ok_or(Error::TagSize)?;
    let mut crypter =
        Crypter::new(ossl_gcm_cipher(cipher)?, Mode::Decrypt, key, Some(iv)).map_err(|_| Error::Crypto)?;
    crypter.aad_update(&[]).map_err(|_| Error::Crypto)?;
    let mut scratch = [0u8; CHUNK + 32];
    let mut pos = 0;
    while pos < buffer.len() {
        let end = (pos + CHUNK).min(buffer.len());
        let n = crypter
            .update(&buffer[pos..end], &mut scratch)
            .map_err(|_| Error::Crypto)?;
        if n != end - pos {
            return Err(Error::Crypto);
        }
        buffer[pos..end].copy_from_slice(&scratch[..n]);
        pos = end;
    }
    crypter.set_tag(&tag).map_err(|_| Error::Crypto)?;
    let mut tail = [0u8; 32];
    let n = crypter.finalize(&mut tail).map_err(|_| Error::Crypto)?;
    if n != 0 {
        return Err(Error::Crypto);
    }
    Ok(())
}

pub(crate) fn encrypt_aead(cipher: Cipher, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<Tag> {
    let mut crypter =
        Crypter::new(ossl_gcm_cipher(cipher)?, Mode::Encrypt, key, Some(iv)).map_err(|_| Error::Crypto)?;
    crypter.aad_update(&[]).map_err(|_| Error::Crypto)?;
    let mut scratch = [0u8; CHUNK + 32];
    let mut pos = 0;
    while pos < buffer.len() {
        let end = (pos + CHUNK).min(buffer.len());
        let n = crypter
            .update(&buffer[pos..end], &mut scratch)
            .map_err(|_| Error::Crypto)?;
        if n != end - pos {
            return Err(Error::Crypto);
        }
        buffer[pos..end].copy_from_slice(&scratch[..n]);
        pos = end;
    }
    let mut tail = [0u8; 32];
    let n = crypter.finalize(&mut tail).map_err(|_| Error::Crypto)?;
    if n != 0 {
        return Err(Error::Crypto);
    }
    let mut tag_buf = [0u8; 16];
    crypter.get_tag(&mut tag_buf).map_err(|_| Error::Crypto)?;
    Ok(Tag::from(tag_buf))
}
