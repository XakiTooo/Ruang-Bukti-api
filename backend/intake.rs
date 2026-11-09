use crate::crypto::R;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PREFIX: &str = "ruang-bukti:intake:v1\n";

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Intake {
    pub(super) category: String,
    pub(super) origin: String,
    pub(super) acquisition: String,
    pub(super) notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) stego_png: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) exam_note: Option<String>,
}

impl Intake {
    pub(super) fn from_plain(source: &str) -> Self {
        Self::decode(source).unwrap_or_else(|| Self {
            category: "Lainnya".into(),
            origin: source.to_owned(),
            acquisition: "Diserahkan langsung".into(),
            notes: String::new(),
            stego_png: None,
            exam_note: None,
        })
    }

    pub(super) fn to_encoded(&self) -> R<String> {
        let serialized = serde_json::to_string(self).map_err(|_| "Catatan penerimaan tidak valid.")?;
        Ok(format!("{PREFIX}{serialized}"))
    }

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
