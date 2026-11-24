use super::{EvidenceService, files, intake::Intake, pdf, stego, text};
use super::files::StoredFile;
use crate::crypto::{self, Envelope, R};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroize;

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Evidence {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) note: Envelope,
    pub(super) file: StoredFile,
    pub(super) original_hash: String,
    pub(super) custodian: String,
    pub(super) pending: bool,
    pub(super) size: usize,
}

impl EvidenceService {
    pub(super) fn receive(&mut self, name: &str, source: &str, bytes: &[u8]) -> R<()> {
        if self.role != "Petugas penerima" {
            return Err("Hanya petugas penerima yang bisa mencatat bukti masuk.".into());
        }
        if name.trim().is_empty() || name.len() > 255 || source.trim().is_empty()
            || source.len() > 2_000 || bytes.is_empty() || bytes.len() > 2 * 1024 * 1024
        {
            return Err("Lengkapi nama dan asal bukti. Ukuran file harus 1 byte sampai 2 MiB.".into());
        }
        if self.evidence.len() >= 12 {
            return Err("Demo mendukung maksimal 12 bukti dalam satu sesi.".into());
        }
        let id = format!("BB-{:03}", self.evidence.len() + 1);
        let context = format!("{}:{id}", self.selected_case);
        self.evidence.push(Evidence {
            note: text::seal_note(&self.master, source, &context)?,
            file: StoredFile::Inline(files::seal_file(&self.master, bytes, &context)?),
            original_hash: crypto::hash(bytes),
            name: name.into(),
            custodian: "Petugas penerima".into(),
            pending: false,
            size: bytes.len(),
            id: id.clone(),
        });
        self.record("Bukti diterima", id);
        Ok(())
    }

    pub(super) fn apply(&mut self, action: &str, data: &Value) -> R<Value> {
        let field = |name: &str| data.get(name).and_then(Value::as_str).unwrap_or("");
        match action {
            "receive" => {
                if field("file").len() > 2_800_000 {
                    return Err("File maksimal 2 MiB.".into());
                }
                let intake = if data["intake"].is_null() {
                    field("source").to_owned()
                } else {
                    Intake::encode(&data["intake"])?
                };
                let mut bytes = B64.decode(field("file")).map_err(|_| "File tidak valid.")?;
                let result = self.receive(field("name"), &intake, &bytes);
                bytes.zeroize();
                result?;
                Ok(self.summary())
            }
            "inspect" => {
                let item = self.evidence.iter().find(|item| item.id == field("id")).ok_or("Bukti tidak ditemukan.")?;
                let context = format!("{}:{}", self.selected_case, item.id);
                let source = text::open_note(&self.master, &item.note, &context)?;
                let intake = Intake::decode(&source);
                let stego_message = intake.as_ref().and_then(|i| i.stego_png.as_deref())
                    .and_then(|b64| B64.decode(b64).ok())
                    .and_then(|png| stego::open_png_message(&self.master, &png, &context).ok());
                let exam_note = intake.as_ref().and_then(|i| i.exam_note.clone());
                let received_at = self.events.iter().find(|event| {
                    event.evidence == item.id && event.action == "Bukti diterima"
                }).map(|event| event.time);
                let storage = match &item.file {
                    StoredFile::Object { r2_key } => format!("Cloudflare R2 ({r2_key})"),
                    StoredFile::Inline(_) => "Memori lokal (Inline)".to_owned(),
                };
                let preview: String = item.note.ciphertext.chars().take(36).collect();
                Ok(json!({
                    "source": if intake.is_none() { Some(source.clone()) } else { None },
                    "intake": intake,
                    "stego_message": stego_message,
                    "stego_png": intake.as_ref().and_then(|i| i.stego_png.clone()),
                    "stego_cover": intake.as_ref().and_then(|i| i.stego_cover.clone()),
                    "note_plaintext": intake.as_ref().map(|i| format!("Kategori: {}\nAsal: {}\nPerolehan: {}\nCatatan: {}\nHasil pemeriksaan: {}", i.category, i.origin, i.acquisition, i.notes, i.exam_note.as_deref().unwrap_or("—"))).unwrap_or(source),
                    "note_envelope": item.note,
                    "exam_note": exam_note,
                    "received_at": received_at,
                    "algorithm": item.file.algorithm(),
                    "storage": storage,
                    "note_algorithm": format!("Vigenère + {}", item.note.algorithm),
                    "note_nonce": item.note.nonce,
                    "note_ciphertext_preview": preview,
                    "hkdf_context": format!("ruang-bukti:{context}:file")
                }))
            }
            "simulation_text_key" | "test_vigenere" => {
                let item = self.evidence.iter().find(|e| e.id == field("id")).ok_or("Bukti tidak ditemukan.")?;
                let context = format!("{}:{}", self.selected_case, item.id);
                if action == "simulation_text_key" {
                    Ok(super::text_simulation::reference(&self.master, &context))
                } else {
                    super::text_simulation::test_key(&self.master, &item.note, &context, field("vigenere_key"))
                }
            }
            "download_plain" => {
                let item = self.evidence.iter().find(|e| e.id == field("id")).ok_or("Bukti tidak ditemukan.")?;
                let context = format!("{}:{}", self.selected_case, item.id);
                let bytes = zeroize::Zeroizing::new(item.file.decrypt(self.objects.as_deref(), &self.master, &context)?);
                if crypto::hash(&bytes) != item.original_hash { return Err("Hash hasil dekripsi tidak cocok. Unduhan dibatalkan.".into()); }
                Ok(json!({"filename": item.name, "base64": B64.encode(&*bytes), "sha256": item.original_hash}))
            }
            "test_audit" => {
                let mut copy = self.events.clone();
                let before = super::audit::verify_events(&copy);
                let first = copy.first_mut().ok_or("Belum ada catatan audit untuk diuji.")?;
                let original = first.action.clone();
                first.action.push_str(" [diubah untuk pengujian]");
                Ok(json!({"before": before, "after": super::audit::verify_events(&copy), "original": original,
                    "changed": copy[0].action, "original_unchanged": self.verify_audit()}))
            }
            "extract_stego" => {
                let item = self.evidence.iter().find(|e| e.id == field("id")).ok_or("Bukti tidak ditemukan.")?;
                if field("png").len() > 1_340_000 { return Err("PNG maksimal 1 MB.".into()); }
                let png = B64.decode(field("png")).map_err(|_| "PNG tidak valid.")?;
                let context = format!("{}:{}", self.selected_case, item.id);
                Ok(json!({"message": stego::open_png_message(&self.master, &png, &context)?}))
            }
            "offer" | "accept" => {
                if !matches!(self.role, "Petugas penerima" | "Penyidik") {
                    return Err("Peran ini hanya dapat memantau serah terima.".into());
                }
                let username = self.username().to_owned();
                let owns_evidence = self.owner(field("id")).is_none_or(|owner| owner == username);
                let recipient = if action == "offer" {
                    Some(self.resolve_recipient(field("id"), field("recipient").trim())?)
                } else {
                    self.last_recipient(field("id")).map(str::to_owned)
                };
                let stego_msg = field("stego_message").trim();
                let item = self.evidence.iter_mut().find(|item| item.id == field("id")).ok_or("Bukti tidak ditemukan.")?;
                let event = if action == "offer" {
                    if item.custodian != self.role || item.pending || !owns_evidence {
                        return Err("Hanya penanggung jawab saat ini dapat mengajukan serah terima.".into());
                    }
                    if self.role == "Petugas penerima" && !stego_msg.is_empty() {
                        let context = format!("{}:{}", self.selected_case, item.id);
                        let source = text::open_note(&self.master, &item.note, &context)?;
                        let mut intake = Intake::from_plain(&source);
                        if field("stego_carrier").len() > 1_340_000 { return Err("Gambar pembawa maksimal 1 MB.".into()); }
                        let carrier = B64.decode(field("stego_carrier")).map_err(|_| "Pilih gambar pembawa terlebih dahulu.")?;
                        let cover = stego::cover_png(&carrier)?;
                        let png = stego::seal_png_message(&self.master, stego_msg, &context, &carrier)?;
                        intake.stego_cover = Some(B64.encode(cover));
                        intake.stego_png = Some(B64.encode(png));
                        item.note = text::seal_note(&self.master, &intake.to_encoded()?, &context)?;
                    }
                    item.pending = true;
                    if self.role == "Petugas penerima" { "Serah terima diajukan" } else { "Pengembalian diajukan" }
                } else {
                    if item.custodian == self.role || !item.pending {
                        return Err("Belum ada serah terima untuk diterima.".into());
                    }
                    if recipient.as_deref().is_some_and(|target| target != username) {
                        return Err("Serah terima ditujukan ke akun lain.".into());
                    }
                    let context = format!("{}:{}", self.selected_case, item.id);
                    if !item.file.verify(self.objects.as_deref(), &self.master, &context, &item.original_hash)? {
                        let id = item.id.clone();
                        self.record("Hash file berbeda", id);
                        return Ok(json!({"accepted":false,"snapshot":self.summary()}));
                    }
                    item.custodian = self.role.into();
                    item.pending = false;
                    if self.role == "Penyidik" { "Bukti diterima penyidik" } else { "Bukti dikembalikan ke petugas" }
                };
                let id = item.id.clone();
                if action == "offer" && self.role == "Petugas penerima" {
                    if let (Some(case), Some(target)) = (self.cases.iter_mut().find(|c| c.id == self.selected_case), recipient.as_ref()) {
                        if case.officer.is_none() { case.officer = Some(username); }
                        case.investigator = Some(target.clone());
                    }
                }
                if let Some(recipient) = recipient { self.record_transfer(event, id, recipient); }
                else { self.record(event, id); }
                Ok(self.summary())
            }
            "examine" => {
                if self.role != "Penyidik" {
                    return Err("Hanya penyidik yang dapat mencatat hasil pemeriksaan.".into());
                }
                let exam = field("exam_note").trim();
                if exam.is_empty() || exam.len() > 600 {
                    return Err("Isi catatan hasil pemeriksaan (1 sampai 600 karakter).".into());
                }
                let username = self.username().to_owned();
                let owns_evidence = self.owner(field("id")).is_none_or(|owner| owner == username);
                let item = self.evidence.iter_mut().find(|item| item.id == field("id")).ok_or("Bukti tidak ditemukan.")?;
                if item.custodian != "Penyidik" || item.pending || !owns_evidence {
                    return Err("Bukti harus diterima oleh akun penyidik ini sebelum mencatat hasil pemeriksaan.".into());
                }
                let context = format!("{}:{}", self.selected_case, item.id);
                let source = text::open_note(&self.master, &item.note, &context)?;
                let mut intake = Intake::from_plain(&source);
                intake.exam_note = Some(exam.to_owned());
                item.note = text::seal_note(&self.master, &intake.to_encoded()?, &context)?;
                let id = item.id.clone();
                self.record("Hasil pemeriksaan penyidik dicatat", id);
                Ok(self.summary())
            }
            "report_pdf" => {
                let item = self.evidence.iter().find(|item| item.id == field("id")).ok_or("Bukti tidak ditemukan.")?;
                let context = format!("{}:{}", self.selected_case, item.id);
                let source = text::open_note(&self.master, &item.note, &context)?;
                let intake = Intake::decode(&source);
                let stego_message = intake.as_ref().and_then(|i| i.stego_png.as_deref())
                    .and_then(|b64| B64.decode(b64).ok())
                    .and_then(|png| stego::open_png_message(&self.master, &png, &context).ok());
                let exam_note = intake.as_ref().and_then(|i| i.exam_note.as_deref());
                let current_case = self.cases.iter().find(|c| c.id == self.selected_case);
                let case_title = current_case.map(|c| c.title.as_str()).unwrap_or("Perkara Forensik");
                let officer = self.last_officer(&item.id)
                    .or_else(|| current_case.and_then(|c| c.officer.as_deref()))
                    .unwrap_or("petugas_bukti");
                let investigator = current_case.and_then(|c| c.investigator.as_deref())
                    .unwrap_or("penyidik");
                let latest_hash = self.events.iter().rev()
                    .find(|e| e.evidence == item.id)
                    .map(|e| e.hash.as_str())
                    .unwrap_or("GENESIS");
                let file_ok = item.file.verify(self.objects.as_deref(), &self.master, &format!("{}:{}", self.selected_case, item.id), &item.original_hash)?;
                let audit_ok = self.verify_audit();
                let pdf_bytes = pdf::generate_handover_pdf(
                    &self.selected_case,
                    case_title,
                    &item.id,
                    &item.name,
                    item.size,
                    officer,
                    investigator,
                    self.owner(&item.id).unwrap_or(&item.custodian),
                    &item.original_hash,
                    latest_hash,
                    stego_message.as_deref(),
                    exam_note,
                    file_ok,
                    audit_ok,
                );
                Ok(json!({
                    "filename": format!("Berita-Acara-{}-{}.pdf", self.selected_case.replace('/', "-"), item.id),
                    "pdf_base64": B64.encode(pdf_bytes)
                }))
            }
            "verify" => {
                let item = self.evidence.iter().find(|item| item.id == field("id")).ok_or("Bukti tidak ditemukan.")?;
                let file_ok = item.file.verify(self.objects.as_deref(), &self.master, &format!("{}:{}",self.selected_case,item.id), &item.original_hash)?;
                let id = item.id.clone();
                self.record(if file_ok {"Hash file cocok"} else {"Hash file berbeda"}, id);
                Ok(json!({"file_ok":file_ok,"audit_ok":self.verify_audit(),"snapshot":self.summary()}))
            }
            _ => Err("Tindakan tidak dikenal.".into()),
        }
    }
}
