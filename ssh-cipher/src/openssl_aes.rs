//! AES-CBC/AES-CTR/AES-GCM via system OpenSSL, for environments that
//! require all cryptographic operations to go through a FIPS-certifiable
//! OpenSSL build. One-shot only (whole-buffer), matching this crate's own
//! `Cipher::encrypt`/`decrypt` contract -- unlike SSH *packet* encryption,
//! OpenSSH private-key-file and PPK encryption never spans more than one
//! call, so there is no cross-call IV/counter state to carry here.

use openssl::symm::{Cipher as OsslCipher, Crypter, Mode};

use crate::{Cipher, Error, Result, Tag};

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

/// One-shot, no-padding block transform; `buffer.len()` must already be a
/// multiple of the block size (this crate's own RustCrypto path shares the
/// same precondition -- see `decrypt_with_block_cipher`'s doc comment).
fn crypt_no_pad(cipher: OsslCipher, mode: Mode, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<()> {
    let mut crypter = Crypter::new(cipher, mode, key, Some(iv)).map_err(|_| Error::Crypto)?;
    crypter.pad(false);
    let mut out = vec![0u8; buffer.len() + 16];
    let n = crypter.update(buffer, &mut out).map_err(|_| Error::Crypto)?;
    let n2 = crypter.finalize(&mut out[n..]).map_err(|_| Error::Crypto)?;
    if n + n2 != buffer.len() {
        return Err(Error::Crypto);
    }
    buffer.copy_from_slice(&out[..n + n2]);
    Ok(())
}

pub(crate) fn decrypt_block(cipher: Cipher, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<()> {
    if buffer.len() % cipher.block_size() != 0 {
        return Err(Error::Length);
    }
    crypt_no_pad(ossl_cbc_cipher(cipher)?, Mode::Decrypt, key, iv, buffer)
}

pub(crate) fn encrypt_block(cipher: Cipher, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<()> {
    if buffer.len() % cipher.block_size() != 0 {
        return Err(Error::Length);
    }
    crypt_no_pad(ossl_cbc_cipher(cipher)?, Mode::Encrypt, key, iv, buffer)
}

pub(crate) fn decrypt_aead(
    cipher: Cipher,
    key: &[u8],
    iv: &[u8],
    buffer: &mut [u8],
    tag: Option<Tag>,
) -> Result<()> {
    let tag = tag.ok_or(Error::TagSize)?;
    let plaintext = openssl::symm::decrypt_aead(ossl_gcm_cipher(cipher)?, key, Some(iv), &[], buffer, &tag)
        .map_err(|_| Error::Crypto)?;
    if plaintext.len() != buffer.len() {
        return Err(Error::Crypto);
    }
    buffer.copy_from_slice(&plaintext);
    Ok(())
}

pub(crate) fn encrypt_aead(cipher: Cipher, key: &[u8], iv: &[u8], buffer: &mut [u8]) -> Result<Tag> {
    let mut tag_buf = [0u8; 16];
    let ciphertext = openssl::symm::encrypt_aead(
        ossl_gcm_cipher(cipher)?,
        key,
        Some(iv),
        &[],
        buffer,
        &mut tag_buf,
    )
    .map_err(|_| Error::Crypto)?;
    if ciphertext.len() != buffer.len() {
        return Err(Error::Crypto);
    }
    buffer.copy_from_slice(&ciphertext);
    Ok(Tag::from(tag_buf))
}
