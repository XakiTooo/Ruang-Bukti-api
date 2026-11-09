use super::EvidenceService;
use crate::{crypto::R, security};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct CaseInfo {
    pub(super) id: String,
    pub(super) title: String,
    pub(super) location: String,
    pub(super) incident_time: String,
}

impl CaseInfo {
    pub(super) fn demo() -> Self {
        Self {
            id: "SIM-BB/001".into(),
            title: "Penggunaan jaringan Wi-Fi".into(),
            location: "Rumah Raka (simulasi)".into(),
            incident_time: "5 November 2026".into(),
        }
    }
}

impl EvidenceService {
    pub(super) fn create_case(&mut self, data: &Value) -> R<Value> {
        if self.role != "Petugas penerima" { return Err("Pencatatan kasus dilakukan petugas penerima.".into()); }
        let field = |name: &str| data[name].as_str().unwrap_or("").trim().to_owned();
        let title = field("title");
        let location = field("location");
        let incident_time = field("incident_time");
        if title.is_empty() || title.len() > 240 || location.len() > 240 || incident_time.len() > 80 {
            return Err("Isi judul kasus. Ringkas lokasi dan waktu kejadian.".into());
        }
        let random = security::random().map_err(|error| error.to_string())?;
        let case = CaseInfo { id: format!("SIM-BB/{}", security::hex(&random[..6]).to_uppercase()), title, location, incident_time };
        if let Some(store) = &self.store { store.create_case(&case)?; }
        let id = case.id.clone();
        self.cases.push(case);
        self.open_case(&id)
    }

    pub(super) fn open_case(&mut self, id: &str) -> R<Value> {
        if !self.cases.iter().any(|case| case.id == id) {
            return Err("Kasus tidak ditemukan.".into());
        }
        if self.selected_case == id { self.reload()?; return Ok(self.summary()); }
        let previous = std::mem::replace(&mut self.selected_case, id.to_owned());
        if self.store.is_some() {
            if let Err(error) = self.reload() {
                self.selected_case = previous;
                return Err(error);
            }
        } else {
            let archive = (std::mem::take(&mut self.evidence), std::mem::take(&mut self.events));
            self.local_archives.insert(previous, archive);
            (self.evidence, self.events) = self.local_archives.remove(id).unwrap_or_default();
        }
        Ok(self.summary())
    }
}
