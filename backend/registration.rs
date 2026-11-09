use super::{auth::{valid, valid_hex}, supabase::SupabaseStore};
use crate::{crypto::{self, R}, security};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use serde_json::{json, Value};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) fn authorized(token: &str) -> bool {
    let Ok(expected) = std::env::var("RUANG_BUKTI_ENROLL_TOKEN_HASH") else { return false };
    valid_hex(token) && valid_hex(&expected)
        && bool::from(crypto::hash(token.as_bytes()).as_bytes().ct_eq(expected.as_bytes()))
}

pub(crate) fn enroll(data: &Value) -> R<Value> {
    let field = |name: &str| data[name].as_str().unwrap_or("");
    let username = field("username");
    if !(3..=40).contains(&username.len()) || !username.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
    }) {
        return Err("Nama akun tidak valid.".into());
    }
    let role = field("role");
    if !matches!(role, "Petugas penerima" | "Penyidik" | "Pengawas") {
        return Err("Peran akun tidak valid.".into());
    }
    let password = field("password");
    if !(8..=128).contains(&password.chars().count()) || password.len() > 256 {
        return Err("Sandi akun harus 8–128 karakter dan maksimal 256 byte.".into());
    }
    let account_hash = field("account_key_hash");
    let device_hash = field("device_key_hash");
    if !valid_hex(account_hash) || !valid_hex(device_hash) || account_hash == device_hash {
        return Err("Hash kunci pendaftaran tidak valid.".into());
    }
    let samples: Zeroizing<Vec<Vec<f64>>> = Zeroizing::new(
        serde_json::from_value(data["samples"].clone()).map_err(|_| "Sampel wajah tidak valid.")?
    );
    if samples.len() != 5 || !valid(&samples) {
        return Err("Diperlukan lima sampel wajah yang valid.".into());
    }
    let (store, master) = SupabaseStore::from_env()?.ok_or("Konfigurasi Supabase belum tersedia.")?;
    let master = Zeroizing::new(master);
    let context = format!("ruang-bukti:demo-face:{username}");
    let key = Zeroizing::new(crypto::key(&master, &context));
    let plaintext = Zeroizing::new(serde_json::to_vec(&*samples).map_err(|_| "Template tidak valid.")?);
    let face = crypto::seal(&key, &plaintext, &context, false)?;
    let random = security::random().map_err(|_| "Gagal menyiapkan salt sandi.")?;
    let salt = SaltString::encode_b64(&random[..16]).map_err(|_| "Salt sandi tidak valid.")?;
    let password_hash = Argon2::default().hash_password(password.as_bytes(), &salt)
        .map_err(|_| "Sandi gagal di-hash.")?.to_string();
    let created = store.enroll(json!({"username":username,"role":role,"password_hash":password_hash,
        "dongle_hash":account_hash,"face":face}), device_hash)?;
    Ok(json!({"already_registered":!created}))
}
