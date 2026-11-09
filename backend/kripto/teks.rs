use crate::crypto::{self, Envelope, R};

pub fn seal_note(master: &[u8; 32], text: &str, evidence_id: &str) -> R<Envelope> {
    crypto::message_seal(master, text, &format!("ruang-bukti:{evidence_id}:note"))
}

pub fn open_note(master: &[u8; 32], note: &Envelope, evidence_id: &str) -> R<String> {
    crypto::message_open(master, note, &format!("ruang-bukti:{evidence_id}:note"))
}
