use super::intake::Intake;
use crate::crypto::{self, Envelope, R};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

fn context(evidence: &str) -> String {
    format!("ruang-bukti:{evidence}:note")
}

pub(super) fn reference(master: &[u8; 32], evidence: &str) -> Value {
    let context = context(evidence);
    let key = Zeroizing::new(crypto::key(master, &format!("{context}:vigenere")));
    json!({"key_hex": crate::security::hex(&*key), "context": format!("{context}:vigenere")})
}

pub(super) fn test_key(master: &[u8; 32], note: &Envelope, evidence: &str, input: &str) -> R<Value> {
    let input = input.trim();
    if input.len() != 64 || !input.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Kunci Vigenère harus berisi tepat 64 karakter hex (0–9, a–f).".into());
    }
    let mut supplied = Zeroizing::new([0u8; 32]);
    for (i, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        supplied[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
            .map_err(|_| "Format kunci hex tidak valid.")?;
    }
    let context = context(evidence);
    let expected = Zeroizing::new(crypto::key(master, &format!("{context}:vigenere")));
    let aes_key = Zeroizing::new(crypto::key(master, &format!("{context}:aes")));
    // AES authentication is checked with the server's AES key, never the manual key.
    let shifted = Zeroizing::new(crypto::open(&aes_key, note, &context)?);
    let original = Zeroizing::new(crypto::vigenere(&shifted, &expected, true));
    let candidate = Zeroizing::new(crypto::vigenere(&shifted, &supplied, true));
    let matches = *candidate == *original;
    let exact_key_match = bool::from(expected.as_slice().ct_eq(supplied.as_slice()));
    let decoded = std::str::from_utf8(&candidate).map_err(|_| "Hasil bukan UTF-8.")?;
    let display = if matches {
        if let Some(i) = Intake::decode(decoded) {
            format!("Kategori: {}\nAsal: {}\nPerolehan: {}\nCatatan: {}\nHasil pemeriksaan: {}",
                i.category, i.origin, i.acquisition, i.notes, i.exam_note.as_deref().unwrap_or("—"))
        } else { decoded.to_owned() }
    } else { decoded.chars().take(4000).collect() };
    Ok(json!({"exact_key_match":exact_key_match,"matches":matches,"plaintext":display,
        "truncated": !matches && decoded.chars().count() > 4000, "aes_authenticated":true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_key_uses_the_stored_envelope_without_modifying_it() {
        let master = [9; 32];
        let id = "CASE-A:BB-001";
        let source = "Catatan penerimaan barang bukti untuk pengujian Vigenere manual.";
        let envelope = super::super::text::seal_note(&master, source, id).unwrap();
        let before = serde_json::to_value(&envelope).unwrap();
        let reference = reference(&master, id);
        let right = reference["key_hex"].as_str().unwrap();
        let result = test_key(&master, &envelope, id, right).unwrap();
        assert_eq!(result["plaintext"], source);
        assert_eq!(result["matches"], true);
        assert_eq!(result["exact_key_match"], true);
        let mut wrong = crypto::key(&master, &format!("{}:vigenere", context(id)));
        wrong[0] = wrong[0].wrapping_add(1);
        let result = test_key(&master, &envelope, id, &crate::security::hex(&wrong)).unwrap();
        assert_eq!(result["matches"], false);
        assert_eq!(result["exact_key_match"], false);
        assert_eq!(result["aes_authenticated"], true);
        assert_eq!(serde_json::to_value(&envelope).unwrap(), before);
        assert!(test_key(&master, &envelope, id, "wrong").is_err());
        assert!(test_key(&master, &envelope, id, &"z".repeat(64)).is_err());
        assert!(test_key(&master, &envelope, "CASE-B:BB-001", right).is_err());
    }

    #[test]
    fn equivalent_shifts_are_not_misrepresented_as_identical_keys() {
        let master = [9; 32];
        let id = "CASE-A:BB-001";
        let envelope = super::super::text::seal_note(&master, "Catatan uji", id).unwrap();
        let mut equivalent = crypto::key(&master, &format!("{}:vigenere", context(id)));
        let byte = equivalent.iter_mut().find(|b| **b <= 229).unwrap();
        *byte += 26;
        let result = test_key(&master, &envelope, id, &crate::security::hex(&equivalent)).unwrap();
        assert_eq!(result["exact_key_match"], false);
        assert_eq!(result["matches"], true);
    }
}
