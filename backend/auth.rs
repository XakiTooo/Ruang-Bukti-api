use crate::crypto::{self, Envelope, R};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

#[derive(Deserialize)]
pub(super) struct Account {
    pub(super) username: String,
    role: String,
    password_hash: String,
    dongle_hash: Option<String>,
    face: Envelope,
}

impl Account {
    pub(super) fn check_dongle(&self, key: &str) -> R<()> {
        let expected = self.dongle_hash.as_deref().ok_or("Kunci akun belum didaftarkan.")?;
        if key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit())
            || !bool::from(subtle::ConstantTimeEq::ct_eq(crypto::hash(key.as_bytes()).as_bytes(), expected.as_bytes()))
        {
            return Err("Colok flashdisk yang berisi kunci akun ini.".into());
        }
        Ok(())
    }

    pub(super) fn verify(&self, master: &[u8; 32], data: &Value) -> R<()> {
        let password = data["password"].as_str().filter(|p| p.len() <= 256)
            .ok_or("Nama pengguna atau sandi salah.")?;
        let hash = PasswordHash::new(&self.password_hash).map_err(|_| "Konfigurasi sandi rusak.")?;
        Argon2::default().verify_password(password.as_bytes(), &hash)
            .map_err(|_| "Nama pengguna atau sandi salah.")?;

        let samples: Zeroizing<Vec<Vec<f64>>> = Zeroizing::new(
            serde_json::from_value(data["samples"].clone()).map_err(|_| "Sampel wajah tidak valid.")?
        );
        if samples.len() != 3 || !valid(&samples) {
            return Err("Sampel wajah tidak valid.".into());
        }
        let context = format!("ruang-bukti:demo-face:{}", self.username);
        let key = Zeroizing::new(crypto::key(master, &context));
        let plaintext = Zeroizing::new(crypto::open(&key, &self.face, &context)?);
        let references: Zeroizing<Vec<Vec<f64>>> = Zeroizing::new(
            serde_json::from_slice(&plaintext).map_err(|_| "Template wajah tidak valid.")?
        );
        if references.len() != 5 || !valid(&references) {
            return Err("Template wajah tidak valid.".into());
        }
        let sum: f64 = samples.iter().flat_map(|sample| {
            references.iter().map(move |reference| sample.iter().zip(reference)
                .map(|(a, b)| (a - b).powi(2)).sum::<f64>().sqrt())
        }).sum();
        if sum / (samples.len() * references.len()) as f64 >= 0.5 {
            return Err("Wajah belum cocok. Coba lagi dengan wajah menghadap kamera.".into());
        }
        Ok(())
    }

    pub(super) fn role(&self) -> R<&'static str> {
        match self.role.as_str() {
            "Petugas penerima" => Ok("Petugas penerima"),
            "Penyidik" => Ok("Penyidik"),
            "Pengawas" => Ok("Pengawas"),
            _ => Err("Peran akun tidak valid.".into()),
        }
    }
}

fn valid(vectors: &[Vec<f64>]) -> bool {
    vectors.iter().all(|vector| vector.len() == 128 && vector.iter().all(|n| n.is_finite() && n.abs() <= 2.0))
}
