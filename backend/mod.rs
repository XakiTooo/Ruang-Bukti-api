mod files;
#[path = "kripto/teks.rs"]
mod text;
mod supabase;
mod auth;
mod audit;
mod cases;
mod evidence;
mod intake;
mod session;
mod transactions;
pub mod cloud;

use crate::{crypto::R, security};
use self::{audit::{Event, verify_events}, cases::CaseInfo, evidence::Evidence, files::ObjectStore};
use serde_json::{json, Value};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub struct EvidenceService {
    master: Zeroizing<[u8; 32]>,
    evidence: Vec<Evidence>,
    events: Vec<Event>,
    role: &'static str,
    store: Option<supabase::SupabaseStore>,
    objects: Option<Box<dyn ObjectStore>>,
    signed_in: bool,
    signed_in_user: String,
    revision: u64,
    cases: Vec<CaseInfo>,
    selected_case: String,
    local_archives: HashMap<String, (Vec<Evidence>, Vec<Event>)>,
}

impl EvidenceService {
    fn username(&self) -> &str {
        if self.store.is_some() || !self.signed_in_user.is_empty() { return &self.signed_in_user; }
        match self.role {
            "Petugas penerima" => "petugas_bukti",
            "Penyidik" => "penyidik",
            _ => "pengawas",
        }
    }

    fn last_recipient(&self, id: &str) -> Option<&str> {
        self.events.iter().rev().find(|event| event.evidence == id &&
            matches!(event.action.as_str(), "Serah terima diajukan" | "Pengembalian diajukan"))
            .and_then(|event| event.recipient.as_deref())
    }

    fn owner(&self, id: &str) -> Option<&str> {
        self.events.iter().rev().find(|event| event.evidence == id &&
            matches!(event.action.as_str(), "Bukti diterima" | "Bukti diterima penyidik" | "Bukti dikembalikan ke petugas"))
            .and_then(|event| event.actor_username.as_deref())
    }

    pub fn new() -> R<Self> {
        let mut service = Self {
            master: Zeroizing::new(security::random().map_err(|e| e.to_string())?),
            evidence: Vec::new(),
            events: Vec::new(),
            role: "Petugas penerima",
            store: None,
            objects: None,
            signed_in: false,
            signed_in_user: String::new(),
            revision: 0,
            cases: vec![CaseInfo::demo()],
            selected_case: CaseInfo::demo().id,
            local_archives: HashMap::new(),
        };
        service.receive("catatan-router-demo.txt", "Diserahkan oleh Raka. Catatan router simulasi, 5 November 2026.", b"SIMULASI: Android-2F terlihat pada daftar perangkat router pukul 19.25 WIB.")?;
        Ok(service)
    }

    fn configured(objects: Box<dyn ObjectStore>) -> R<Self> {
        let Some((store, master)) = supabase::SupabaseStore::from_env()? else {
            return Err("Konfigurasi Supabase belum tersedia.".into());
        };
        Ok(Self {
            master: Zeroizing::new(master),
            evidence: Vec::new(),
            events: Vec::new(),
            role: "Petugas penerima",
            store: Some(store),
            objects: Some(objects),
            signed_in: false,
            signed_in_user: String::new(),
            revision: 0,
            cases: Vec::new(),
            selected_case: String::new(),
            local_archives: HashMap::new(),
        })
    }

    fn reload(&mut self) -> R<()> {
        if let Some(store) = &self.store {
            let saved = store.read(&self.selected_case)?;
            if saved.revision != saved.events.len() as u64 || !verify_events(&saved.events) {
                return Err("Rantai riwayat di Supabase tidak cocok.".into());
            }
            self.revision = saved.revision;
            self.evidence = saved.evidence;
            self.events = saved.events;
        }
        Ok(())
    }

    fn summary(&self) -> Value {
        let evidence: Vec<_> = self.evidence.iter().map(|item| json!({
            "id":item.id, "name":item.name, "custodian":item.custodian, "size":item.size,
            "original_hash":item.original_hash,"pending":item.pending,
            "recipient": if item.pending { self.last_recipient(&item.id) } else { None },
            "owner": self.owner(&item.id)
        })).collect();
        json!({"role":self.role,"username":self.username(),"evidence":evidence,"events":self.events,"online":self.store.is_some(),"cases":self.cases,"selected_case":self.selected_case})
    }

    pub fn call(&mut self, action: &str, data: &Value) -> R<Value> {
        if let Some(result) = self.check_session(action, data)? {
            return Ok(result);
        }
        if action == "inbox" {
            if let Some(store) = &self.store { return store.inbox(self.username()); }
            let mut entries = Vec::new();
            for (case, evidence, events) in std::iter::once((&self.selected_case, &self.evidence, &self.events))
                .chain(self.local_archives.iter().map(|(case, (evidence, events))| (case, evidence, events))) {
                for item in evidence.iter().filter(|item| item.pending) {
                    if events.iter().rev().find(|event| event.evidence == item.id &&
                        matches!(event.action.as_str(), "Serah terima diajukan" | "Pengembalian diajukan"))
                        .and_then(|event| event.recipient.as_deref()) == Some(self.username()) {
                        entries.push(json!({"case_id":case,"id":item.id,"name":item.name}));
                    }
                }
            }
            return Ok(json!(entries));
        }
        if action == "list" {
            if let Some(store) = &self.store { self.cases = store.cases()?; }
            if !self.selected_case.is_empty() { self.reload()?; }
            return Ok(self.summary());
        }
        if action == "open_case" {
            let id = data["id"].as_str().unwrap_or("");
            return self.open_case(id);
        }
        if action == "create_case" { return self.create_case(data); }
        if self.selected_case.is_empty() && matches!(action, "receive" | "offer" | "accept" | "verify" | "inspect") {
            return Err("Buka kasus dari arsip terlebih dahulu.".into());
        }

        self.apply_evidence_command(action, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    #[test]
    fn failed_handoff_is_audited_without_changing_custody() {
        let mut service = EvidenceService::new().unwrap();
        let id = json!({"id":"BB-001"});
        service.call("offer", &id).unwrap();
        let files::StoredFile::Inline(file) = &mut service.evidence[0].file else { panic!("demo file") };
        file.ciphertext = "rusak".into();
        service.call("role", &json!({"role":"Penyidik"})).unwrap();
        let result = service.call("accept", &id).unwrap();
        assert_eq!(result["accepted"], false);
        assert_eq!(result["snapshot"]["evidence"][0]["owner"], "petugas_bukti");
        assert_eq!(result["snapshot"]["evidence"][0]["pending"], true);
        assert_eq!(service.events.last().unwrap().action, "Hash file berbeda");
        assert!(service.verify_audit());
    }

    #[test]
    fn evidence_is_encrypted_and_handoff_is_auditable() {
        let mut service = EvidenceService::new().unwrap();
        service.receive("uji.txt", "Keterangan sumber contoh", b"isi bukti contoh").unwrap();
        let item = &service.evidence[1];
        assert_eq!(item.file.algorithm(), "ChaCha20-Poly1305");
        assert_eq!(item.original_hash, crypto::hash(b"isi bukti contoh"));
        assert!(!item.note.ciphertext.contains("Keterangan sumber contoh"));
        assert_eq!(service.call("inspect", &json!({"id":"BB-002"})).unwrap()["source"], "Keterangan sumber contoh");
        let id = json!({"id":"BB-002"});
        let offered = service.call("offer", &id).unwrap();
        assert_eq!(offered["evidence"][1]["pending"], true);
        assert_eq!(offered["evidence"][1]["custodian"], "Petugas penerima");
        assert!(service.call("accept", &id).is_err());
        service.call("role", &json!({"role":"Penyidik cadangan"})).unwrap();
        assert_eq!(service.role, "Penyidik");
        assert!(service.call("accept", &id).unwrap_err().contains("akun lain"));
        service.call("role", &json!({"role":"Penyidik"})).unwrap();
        assert_eq!(service.call("inbox", &json!({})).unwrap()[0]["id"], "BB-002");
        let accepted = service.call("accept", &id).unwrap();
        assert_eq!(accepted["evidence"][1]["custodian"], "Penyidik");
        assert_eq!(accepted["evidence"][1]["pending"], false);
        assert!(service.receive("baru.txt", "Sumber", b"isi").is_err());
        let checked = service.call("verify", &json!({"id":"BB-002"})).unwrap();
        assert_eq!(checked["file_ok"], true);
        assert_eq!(checked["audit_ok"], true);
        service.call("offer", &id).unwrap();
        service.call("role", &json!({"role":"Petugas penerima"})).unwrap();
        assert_eq!(service.call("accept", &id).unwrap()["evidence"][1]["owner"], "petugas_bukti");
        service.events[0].hash = "modified".into();
        assert!(!service.verify_audit());
    }
}
