use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub type R<T> = Result<T, String>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn hash(bytes: &[u8]) -> String {
    crate::security::hex(&Sha256::digest(bytes))
}

pub fn key(master: &[u8; 32], context: &str) -> [u8; 32] {
    let mut derived = [0; 32];
    Hkdf::<Sha256>::new(None, master).expand(context.as_bytes(), &mut derived).unwrap();
    derived
}

pub fn seal(key: &[u8; 32], plaintext: &[u8], context: &str, file: bool) -> R<Envelope> {
    let random = crate::security::random().map_err(|error| error.to_string())?;
    let nonce = &random[..12];
    let payload = Payload { msg: plaintext, aad: context.as_bytes() };
    let (algorithm, ciphertext) = if file {
        ("ChaCha20-Poly1305", ChaCha20Poly1305::new(key.into()).encrypt(nonce.into(), payload))
    } else {
        ("AES-256-GCM", Aes256Gcm::new(key.into()).encrypt(Nonce::from_slice(nonce), payload))
    };
    Ok(Envelope {
        algorithm: algorithm.into(),
        nonce: B64.encode(nonce),
        ciphertext: B64.encode(ciphertext.map_err(|_| "Enkripsi gagal")?),
    })
}

pub fn open(key: &[u8; 32], envelope: &Envelope, context: &str) -> R<Vec<u8>> {
    let nonce = B64.decode(&envelope.nonce).map_err(|_| "Nonce tidak valid")?;
    if nonce.len() != 12 { return Err("Panjang nonce tidak valid".into()); }
    let bytes = B64.decode(&envelope.ciphertext).map_err(|_| "Ciphertext tidak valid")?;
    let payload = Payload { msg: &bytes, aad: context.as_bytes() };
    match envelope.algorithm.as_str() {
        "AES-256-GCM" => Aes256Gcm::new(key.into()).decrypt(Nonce::from_slice(&nonce), payload),
        "ChaCha20-Poly1305" => ChaCha20Poly1305::new(key.into()).decrypt(nonce.as_slice().into(), payload),
        _ => return Err("Algoritma tidak didukung".into()),
    }.map_err(|_| "Verifikasi autentikasi gagal: kunci salah atau data berubah.".into())
}

fn vigenere(bytes: &[u8], key: &[u8; 32], decrypt: bool) -> Vec<u8> {
    let mut index = 0;
    bytes.iter().map(|&byte| {
        let base = if byte.is_ascii_uppercase() { b'A' } else if byte.is_ascii_lowercase() { b'a' } else { return byte };
        let shift = key[index % key.len()] % 26;
        index += 1;
        base + if decrypt { (byte - base + 26 - shift) % 26 } else { (byte - base + shift) % 26 }
    }).collect()
}

pub fn message_seal(master: &[u8; 32], text: &str, context: &str) -> R<Envelope> {
    let vigenere_key = Zeroizing::new(key(master, &format!("{context}:vigenere")));
    let aes_key = Zeroizing::new(key(master, &format!("{context}:aes")));
    let shifted = Zeroizing::new(vigenere(text.as_bytes(), &vigenere_key, false));
    seal(&aes_key, &shifted, context, false)
}

pub fn message_open(master: &[u8; 32], envelope: &Envelope, context: &str) -> R<String> {
    let vigenere_key = Zeroizing::new(key(master, &format!("{context}:vigenere")));
    let aes_key = Zeroizing::new(key(master, &format!("{context}:aes")));
    let shifted = Zeroizing::new(open(&aes_key, envelope, context)?);
    String::from_utf8(vigenere(&shifted, &vigenere_key, true)).map_err(|_| "Teks tidak valid".into())
}
