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
pub mod registration;

use crate::{crypto::R, security};
use self::{audit::{Event, verify_events}, cases::CaseInfo, evidence::Evidence, files::ObjectStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use zeroize::Zeroizing;

#[derive(Clone, Deserialize, Serialize)]
pub struct RecipientAccount {
    pub username: String,
    pub role: String,
}

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
    pub(super) recipients: Vec<RecipientAccount>,
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

    fn last_officer(&self, id: &str) -> Option<&str> {
        self.events.iter().rev().find(|event| event.evidence == id &&
            matches!(event.action.as_str(), "Bukti diterima" | "Bukti dikembalikan ke petugas"))
            .and_then(|event| event.actor_username.as_deref())
    }

    pub(super) fn default_investigator(&self) -> Option<String> {
        let investigators: Vec<&str> = self.recipients.iter()
            .filter(|item| item.role == "Penyidik")
            .map(|item| item.username.as_str())
            .collect();
        if investigators.len() == 1 {
            return Some(investigators[0].to_owned());
        }
        if self.store.is_none() {
            return Some("penyidik".into());
        }
        investigators.first().map(|u| (*u).to_owned())
    }

    pub(super) fn resolve_recipient(&self, evidence_id: &str, requested: &str) -> R<String> {
        let target_role = if self.role == "Petugas penerima" { "Penyidik" } else { "Petugas penerima" };
        if !requested.is_empty() {
            if !(3..=40).contains(&requested.len()) || !requested.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
            }) {
                return Err("Nama pengguna penerima tidak valid.".into());
            }
            if requested == self.username() {
                return Err("Penerima serah terima harus akun berbeda.".into());
            }
            if !self.recipients.is_empty() && !self.recipients.iter().any(|r| r.username == requested && r.role == target_role) {
                return Err("Akun tujuan serah terima tidak sesuai peran atau belum terdaftar.".into());
            }
            return Ok(requested.to_owned());
        }

        let current_case = self.cases.iter().find(|case| case.id == self.selected_case);
        if self.role == "Petugas penerima" {
            if let Some(inv) = current_case.and_then(|case| case.investigator.as_deref()).filter(|u| !u.is_empty()) {
                if self.recipients.is_empty() || self.recipients.iter().any(|r| r.username == inv && r.role == "Penyidik") {
                    return Ok(inv.to_owned());
                }
            }
            if let Some(prev_inv) = self.events.iter().rev()
                .find(|event| event.actor == "Penyidik" && event.actor_username.is_some())
                .and_then(|event| event.actor_username.as_deref())
            {
                if self.recipients.is_empty() || self.recipients.iter().any(|r| r.username == prev_inv && r.role == "Penyidik") {
                    return Ok(prev_inv.to_owned());
                }
            }
            let matching: Vec<&str> = self.recipients.iter()
                .filter(|r| r.role == "Penyidik")
                .map(|r| r.username.as_str())
                .collect();
            if matching.len() == 1 { return Ok(matching[0].to_owned()); }
            if self.store.is_none() { return Ok("penyidik".into()); }
            if matching.len() > 1 { return Err("Pilih akun penyidik tujuan serah terima.".into()); }
            return Err("Belum ada akun Penyidik terdaftar untuk menerima serah terima.".into());
        }

        if let Some(officer) = self.last_officer(evidence_id) {
            if self.recipients.is_empty() || self.recipients.iter().any(|r| r.username == officer && r.role == "Petugas penerima") {
                return Ok(officer.to_owned());
            }
        }
        if let Some(officer) = current_case.and_then(|case| case.officer.as_deref()).filter(|u| !u.is_empty()) {
            if self.recipients.is_empty() || self.recipients.iter().any(|r| r.username == officer && r.role == "Petugas penerima") {
                return Ok(officer.to_owned());
            }
        }
        let matching: Vec<&str> = self.recipients.iter()
            .filter(|r| r.role == "Petugas penerima")
            .map(|r| r.username.as_str())
            .collect();
        if matching.len() == 1 { return Ok(matching[0].to_owned()); }
        if self.store.is_none() { return Ok("petugas_bukti".into()); }
        if matching.len() > 1 { return Err("Pilih akun petugas tujuan pengembalian.".into()); }
        Err("Belum ada akun Petugas penerima terdaftar untuk menerima pengembalian.".into())
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
            recipients: vec![
                RecipientAccount { username: "petugas_bukti".into(), role: "Petugas penerima".into() },
                RecipientAccount { username: "penyidik".into(), role: "Penyidik".into() },
                RecipientAccount { username: "penyidik_cadangan".into(), role: "Penyidik".into() },
            ],
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
            recipients: Vec::new(),
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
            "owner": self.owner(&item.id),
            "return_to": self.last_officer(&item.id)
        })).collect();
        json!({
            "role":self.role, "username":self.username(), "evidence":evidence, "events":self.events,
            "online":self.store.is_some(), "cases":self.cases, "selected_case":self.selected_case,
            "recipients":self.recipients
        })
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
            if let Some(store) = &self.store {
                self.cases = store.cases()?;
                self.recipients = store.recipients().unwrap_or_default();
            }
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

    #[test]
    fn custom_accounts_and_case_assignment_work_across_handoff_and_return() {
        let mut service = EvidenceService::new().unwrap();
        service.recipients = vec![
            RecipientAccount { username: "petugas_baru".into(), role: "Petugas penerima".into() },
            RecipientAccount { username: "penyidik_satu".into(), role: "Penyidik".into() },
            RecipientAccount { username: "penyidik_dua".into(), role: "Penyidik".into() },
        ];
        service.role = "Petugas penerima";
        service.signed_in_user = "petugas_baru".into();
        let created = service.call("create_case", &json!({
            "title": "Kasus Akun Baru",
            "location": "Lab Forensik",
            "incident_time": "9 November 2026",
            "investigator": "penyidik_satu"
        })).unwrap();
        assert_eq!(created["cases"].as_array().unwrap().last().unwrap()["investigator"], "penyidik_satu");
        service.receive("bukti-baru.txt", "Asal baru", b"data baru").unwrap();
        let id = json!({"id": "BB-001"});
        let offered = service.call("offer", &id).unwrap();
        assert_eq!(offered["evidence"][0]["recipient"], "penyidik_satu");

        service.role = "Penyidik";
        service.signed_in_user = "penyidik_dua".into();
        assert!(service.call("accept", &id).unwrap_err().contains("akun lain"));

        service.signed_in_user = "penyidik_satu".into();
        assert_eq!(service.call("inbox", &json!({})).unwrap()[0]["id"], "BB-001");
        let accepted = service.call("accept", &id).unwrap();
        assert_eq!(accepted["evidence"][0]["owner"], "penyidik_satu");

        let returned = service.call("offer", &id).unwrap();
        assert_eq!(returned["evidence"][0]["recipient"], "petugas_baru");

        service.role = "Petugas penerima";
        service.signed_in_user = "petugas_baru".into();
        let final_state = service.call("accept", &id).unwrap();
        assert_eq!(final_state["evidence"][0]["owner"], "petugas_baru");
        assert!(service.verify_audit());
    }
}
