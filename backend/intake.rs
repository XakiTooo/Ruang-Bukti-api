use crate::crypto::R;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PREFIX: &str = "ruang-bukti:intake:v1\n";

#[derive(Deserialize, Serialize)]
pub(super) struct Intake {
    category: String,
    origin: String,
    acquisition: String,
    notes: String,
}

impl Intake {
    pub(super) fn encode(data: &Value) -> R<String> {
        let mut intake: Self = serde_json::from_value(data.clone())
            .map_err(|_| "Lengkapi informasi penerimaan.")?;
        intake.origin = intake.origin.trim().to_owned();
        intake.notes = intake.notes.trim().to_owned();
        if !matches!(intake.category.as_str(), "Dokumen" | "Gambar" | "Audio" | "Video" | "Log" | "Lainnya")
            || !matches!(intake.acquisition.as_str(), "Diserahkan langsung" | "Diterima melalui kanal digital" | "Hasil pemeriksaan perangkat" | "Lainnya")
            || intake.origin.is_empty()
            || intake.origin.len() > 400
            || intake.notes.len() > 1000
        {
            return Err("Periksa kategori, asal, cara perolehan, dan catatan bukti.".into());
        }
        let serialized = serde_json::to_string(&intake).map_err(|_| "Catatan penerimaan tidak valid.")?;
        Ok(format!("{PREFIX}{serialized}"))
    }

    pub(super) fn decode(note: &str) -> Option<Self> {
        serde_json::from_str(note.strip_prefix(PREFIX)?).ok()
    }
}
