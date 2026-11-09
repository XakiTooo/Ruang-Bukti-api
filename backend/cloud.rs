use super::EvidenceService;
pub(crate) use super::files::ObjectStore;
use crate::crypto::{self, Envelope, R};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const SESSION_CONTEXT: &str = "ruang-bukti:cloud-session:v1";
const SESSION_TTL: u64 = 15 * 60;

#[derive(Serialize, Deserialize)]
struct Session {
    username: String,
    expires: u64,
}

fn now() -> R<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|time| time.as_secs())
        .map_err(|_| "Waktu server tidak valid.".into())
}

pub(crate) fn call(request: &Value, objects: Box<dyn ObjectStore>) -> R<Value> {
    let action = request["action"].as_str().unwrap_or("");
    let data = &request["data"];
    let mut service = EvidenceService::configured(objects)?;
    let store = service.store.as_ref().unwrap();
    let key = request["usb_key"].as_str().unwrap_or("");
    let account = if matches!(action, "check_dongle" | "login") {
        store.account(data["username"].as_str().unwrap_or("").trim())?
    } else {
        let envelope: Envelope = serde_json::from_value(request["session"].clone())
            .map_err(|_| "Masuk untuk membuka arsip.")?;
        let session_key = Zeroizing::new(crypto::key(&service.master, SESSION_CONTEXT));
        let plaintext = Zeroizing::new(crypto::open(&session_key, &envelope, SESSION_CONTEXT)
            .map_err(|_| "Sesi tidak valid.")?);
        let session: Session = serde_json::from_slice(&plaintext).map_err(|_| "Sesi tidak valid.")?;
        if session.expires <= now()? { return Err("Sesi berakhir. Keluar lalu masuk kembali.".into()); }
        store.account(&session.username)?
    };
    account.check_dongle(key, request["device_key"].as_str().unwrap_or(""))?;
    if action == "check_dongle" {
        return Ok(json!({"ok": true}));
    }

    service.role = account.role()?;
    service.signed_in = true;
    service.signed_in_user = account.username.clone();
    if action == "login" {
        account.verify(&service.master, data)?;
        service.cases = store.cases()?;
        service.recipients = store.recipients().unwrap_or_default();
        let session = Session { username: account.username, expires: now()? + SESSION_TTL };
        let bytes = Zeroizing::new(serde_json::to_vec(&session).map_err(|_| "Sesi tidak dapat dibuat.")?);
        let session_key = Zeroizing::new(crypto::key(&service.master, SESSION_CONTEXT));
        let token = crypto::seal(&session_key, &bytes, SESSION_CONTEXT, false)?;
        return Ok(json!({"session": token, "snapshot": service.summary()}));
    }
    if action != "inbox" {
        service.cases = store.cases()?;
        service.recipients = store.recipients().unwrap_or_default();
    }
    if matches!(action, "list" | "receive" | "offer" | "accept" | "verify" | "inspect") {
        if let Some(case) = request["case_id"].as_str().filter(|id| !id.is_empty()) {
            service.open_case(case)?;
        }
    }
    if action == "list" { return Ok(service.summary()); }
    service.call(action, data)
}
