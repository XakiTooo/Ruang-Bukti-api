use crate::crypto::{self, Envelope, R};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum StoredFile {
    Object { r2_key: String },
    Inline(Envelope),
}

pub(crate) trait ObjectStore {
    fn put(&self, bytes: &[u8]) -> R<String>;
    fn get(&self, key: &str) -> R<Vec<u8>>;
    fn delete(&self, key: &str) -> R<()>;
}

impl StoredFile {
    pub(super) fn algorithm(&self) -> &str {
        match self {
            Self::Inline(file) => &file.algorithm,
            Self::Object { .. } => "ChaCha20-Poly1305",
        }
    }

    pub(super) fn verify(
        &self,
        objects: Option<&dyn ObjectStore>,
        master: &[u8; 32],
        context: &str,
        original_hash: &str,
    ) -> R<bool> {
        let file = match self {
            Self::Inline(file) => return Ok(verify_file(master, file, context, original_hash).unwrap_or(false)),
            Self::Object { r2_key } => {
                let bytes = objects.ok_or("Penyimpanan objek belum tersedia.")?.get(r2_key)?;
                let Ok(file) = serde_json::from_slice::<Envelope>(&bytes) else { return Ok(false) };
                file
            }
        };
        Ok(verify_file(master, &file, context, original_hash).unwrap_or(false))
    }
}

pub fn seal_file(master: &[u8; 32], bytes: &[u8], evidence_id: &str) -> R<Envelope> {
    let context = format!("ruang-bukti:{evidence_id}:file");
    let mut key = crypto::key(master, &context);
    let result = crypto::seal(&key, bytes, &context, true);
    key.zeroize();
    result
}

pub fn verify_file(
    master: &[u8; 32], file: &Envelope, evidence_id: &str, original_hash: &str,
) -> R<bool> {
    let context = format!("ruang-bukti:{evidence_id}:file");
    let mut key = crypto::key(master, &context);
    let result = crypto::open(&key, file, &context);
    key.zeroize();
    let mut bytes = result?;
    let matches = crypto::hash(&bytes) == original_hash;
    bytes.zeroize();
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DemoObject(Vec<u8>);

    impl ObjectStore for DemoObject {
        fn put(&self, _: &[u8]) -> R<String> { unreachable!() }
        fn get(&self, _: &str) -> R<Vec<u8>> { Ok(self.0.clone()) }
        fn delete(&self, _: &str) -> R<()> { unreachable!() }
    }

    #[test]
    fn verifies_legacy_file_and_private_object_with_same_context() {
        let master = [7; 32];
        let context = "SIM-BB/001:BB-002";
        let bytes = b"bukti simulasi";
        let original_hash = crypto::hash(bytes);
        let envelope = seal_file(&master, bytes, context).unwrap();
        let object = DemoObject(serde_json::to_vec(&envelope).unwrap());
        let legacy = StoredFile::Inline(envelope);
        let reference = StoredFile::Object { r2_key: "ruang-bukti/demo".into() };

        assert!(legacy.verify(None, &master, context, &original_hash).unwrap());
        assert!(reference.verify(Some(&object), &master, context, &original_hash).unwrap());
        assert!(!reference.verify(Some(&object), &master, "SIM-BB/002:BB-002", &original_hash).unwrap());
        assert!(reference.verify(None, &master, context, &original_hash).is_err());
    }
}
