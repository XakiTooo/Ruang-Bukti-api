use super::EvidenceService;
use crate::crypto::R;
use serde_json::{json, Value};

impl EvidenceService {
    pub(super) fn check_session(&mut self, action: &str, data: &Value) -> R<Option<Value>> {
        if action == "status" {
            return Ok(Some(json!({"login_required": self.store.is_some()})));
        }
        if self.store.is_some() && !self.signed_in {
            return Err("Masuk untuk membuka arsip.".into());
        }
        if action == "role" {
            if self.store.is_some() { return Err("Peran ditentukan oleh akun.".into()); }
            let (role, username) = match data["role"].as_str().unwrap_or("") {
                "Petugas penerima" => ("Petugas penerima", "petugas_bukti"),
                "Penyidik" => ("Penyidik", "penyidik"),
                "Penyidik cadangan" => ("Penyidik", "penyidik_cadangan"),
                "Pengawas" => ("Pengawas", "pengawas"),
                _ => return Err("Pilih peran demo yang tersedia.".into()),
            };
            self.role = role;
            self.signed_in_user = username.into();
            return Ok(Some(self.summary()));
        }
        Ok(None)
    }
}
