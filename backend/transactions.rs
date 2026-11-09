use super::EvidenceService;
use super::files::StoredFile;
use crate::crypto::R;
use serde_json::Value;

impl EvidenceService {
    pub(super) fn apply_evidence_command(&mut self, action: &str, data: &Value) -> R<Value> {
        if self.store.is_none() || !matches!(action, "receive" | "offer" | "accept" | "verify" | "examine") {
            return self.apply(action, data);
        }
        let evidence_len = self.evidence.len();
        let events_len = self.events.len();
        let changed = if matches!(action, "offer" | "accept" | "examine") {
            self.evidence.iter().position(|item| Some(item.id.as_str()) == data["id"].as_str())
        } else { None };
        let previous_state = changed.map(|index| (
            self.evidence[index].custodian.clone(),
            self.evidence[index].pending,
            self.evidence[index].note.clone(),
        ));
        let result = self.apply(action, data)?;
        let mut uploaded = None;
        if action == "receive" {
            if let Some(objects) = self.objects.as_deref() {
                let item = self.evidence.last_mut().unwrap();
                let StoredFile::Inline(envelope) = &item.file else { unreachable!() };
                let bytes = serde_json::to_vec(envelope).expect("envelope contains only strings");
                match objects.put(&bytes) {
                    Ok(key) => {
                        item.file = StoredFile::Object { r2_key: key.clone() };
                        uploaded = Some(key);
                    }
                    Err(error) => {
                        self.evidence.truncate(evidence_len);
                        self.events.truncate(events_len);
                        return Err(error);
                    }
                }
            }
        }
        let event = self.events.last().ok_or("Catatan audit tidak tersedia.")?;
        let evidence = if action == "receive" {
            self.evidence.last()
        } else if matches!(action, "offer" | "examine") {
            changed.and_then(|idx| self.evidence.get(idx))
        } else {
            None
        };
        let change = if action == "accept" && result["accepted"] == false { "verify" } else { action };
        let committed = self.store.as_ref().unwrap().commit(&self.selected_case, self.revision, change, evidence, event);
        if matches!(committed, Ok(true)) {
            self.revision += 1;
            return Ok(result);
        }
        self.evidence.truncate(evidence_len);
        self.events.truncate(events_len);
        if let (Some(index), Some((custodian, pending, note))) = (changed, previous_state) {
            self.evidence[index].custodian = custodian;
            self.evidence[index].pending = pending;
            self.evidence[index].note = note;
        }
        match committed {
            Ok(false) => {
                if let (Some(objects), Some(key)) = (self.objects.as_deref(), uploaded) {
                    let _ = objects.delete(&key);
                }
                Err("Data berubah. Klik Muat ulang sebelum mengulangi tindakan.".into())
            }
            Err(error) => Err(format!("{error} Muat ulang untuk melihat apakah perubahan tersimpan.")),
            Ok(true) => unreachable!(),
        }
    }
}
