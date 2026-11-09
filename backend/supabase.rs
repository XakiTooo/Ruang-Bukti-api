use super::{auth::Account, CaseInfo, Event, Evidence};
use crate::crypto::{self, R};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{env, time::Duration};
use zeroize::{Zeroize, Zeroizing};

pub struct SupabaseStore {
    url: String,
    secret: Zeroizing<String>,
    agent: ureq::Agent,
}

#[derive(Deserialize)]
pub struct Snapshot {
    pub revision: u64,
    pub evidence: Vec<Evidence>,
    pub events: Vec<Event>,
}

impl SupabaseStore {
    pub fn from_env() -> R<Option<(Self, [u8; 32])>> {
        let Ok(url) = env::var("RUANG_BUKTI_SUPABASE_URL") else { return Ok(None) };
        let parsed: ureq::http::Uri = url.parse().map_err(|_| "URL Supabase tidak valid.")?;
        if parsed.scheme_str() != Some("https")
            || !parsed.host().is_some_and(|host| host.ends_with(".supabase.co"))
            || parsed.path() != "/" || parsed.query().is_some()
            || parsed.authority().is_none_or(|authority| authority.as_str().contains('@'))
        {
            return Err("Alamat Supabase harus berupa URL HTTPS proyek.".into());
        }
        let secret = Zeroizing::new(env::var("RUANG_BUKTI_SUPABASE_SECRET_KEY").map_err(|_| "Kunci server Supabase belum tersedia.")?);
        let configured = Zeroizing::new(env::var("RUANG_BUKTI_MASTER_SOURCE").map_err(|_| "Kunci induk belum tersedia.")?);
        let mut master = [0u8; 32];
        if configured.len() != 64 || !configured.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Format kunci induk harus 64 karakter heksadesimal.".into());
        }
        for (index, byte) in master.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&configured[index * 2..index * 2 + 2], 16)
                .map_err(|_| "Kunci induk tidak valid.")?;
        }
        let derived = crypto::key(&master, "ruang-bukti:master:v1");
        master.zeroize();
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false).max_redirects(0)
            .timeout_global(Some(Duration::from_secs(12))).build();
        Ok(Some((Self { url: url.trim_end_matches('/').into(), secret, agent: config.into() }, derived)))
    }

    pub fn cases(&self) -> R<Vec<CaseInfo>> {
        serde_json::from_value(self.rpc("ruang_bukti_cases", json!({}))?)
            .map_err(|_| "Daftar kasus dari Supabase tidak valid.".into())
    }

    pub fn inbox(&self, username: &str) -> R<Value> {
        self.rpc("ruang_bukti_inbox", json!({"account_username": username}))
    }

    pub fn account(&self, username: &str) -> R<Account> {
        if !(3..=40).contains(&username.len()) || !username.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
        }) {
            return Err("Nama pengguna atau kunci akun tidak cocok.".into());
        }
        let account = self.rpc("ruang_bukti_account", json!({"account_username": username}))?;
        if account.is_null() { return Err("Nama pengguna atau kunci akun tidak cocok.".into()); }
        serde_json::from_value(account).map_err(|_| "Data akun Ruang Bukti tidak valid.".into())
    }

    pub fn create_case(&self, case: &CaseInfo) -> R<()> {
        self.rpc("ruang_bukti_create", json!({"case_row":case}))?;
        Ok(())
    }

    pub fn enroll(&self, account: Value, device_hash: &str) -> R<bool> {
        self.rpc("ruang_bukti_enroll", json!({"account_row":account,"device_key_hash":device_hash}))?
            .as_bool().ok_or_else(|| "Respons pendaftaran Supabase tidak valid.".into())
    }

    pub fn read(&self, case_id: &str) -> R<Snapshot> {
        serde_json::from_value(self.rpc("ruang_bukti_read", json!({"case_key":case_id}))?)
            .map_err(|_| "Data Ruang Bukti dari Supabase tidak valid.".into())
    }

    pub fn commit(&self, case_id: &str, revision: u64, action: &str, evidence: Option<&Evidence>, event: &Event) -> R<bool> {
        self.rpc("ruang_bukti_commit_custody", json!({
            "case_key":case_id,"expected_revision": revision, "change_type": action,
            "evidence_row": evidence, "audit_row": event
        }))?.as_bool().ok_or_else(|| "Hasil penyimpanan Supabase tidak valid.".into())
    }

    fn rpc(&self, name: &str, body: Value) -> R<Value> {
        let mut response = self.agent.post(format!("{}/rest/v1/rpc/{name}", self.url))
            .header("apikey", self.secret.as_str())
            .send_json(body).map_err(|_| "Supabase belum bisa dijangkau. Periksa internet dan coba lagi.")?;
        if !response.status().is_success() {
            if name == "ruang_bukti_enroll" && response.status().as_u16() == 409 {
                return Err("Nama akun sudah terdaftar dengan kunci atau peran berbeda.".into());
            }
            return Err(format!("Supabase menolak permintaan ({}). Periksa schema dan konfigurasi lokal.", response.status().as_u16()));
        }
        if response.status().as_u16() == 204 { return Ok(Value::Null); }
        response.body_mut().with_config().limit(40 * 1024 * 1024).read_json()
            .map_err(|_| "Respons Supabase tidak valid atau terlalu besar.".into())
    }
}
