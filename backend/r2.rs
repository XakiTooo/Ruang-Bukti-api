use crate::{backend::cloud::ObjectStore, crypto, crypto::R};
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, PayloadChecksumKind, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use std::{env, time::{Duration, SystemTime}};
use ureq::http::{Request, Response};

const MAX_ENVELOPE: usize = 3 * 1024 * 1024;

pub(crate) struct R2Store {
    endpoint: String,
    bucket: String,
    credentials: Credentials,
    agent: ureq::Agent,
}

impl R2Store {
    pub(crate) fn configured() -> R<Self> {
        let value = |name: &str| env::var(name).ok().filter(|value| !value.is_empty())
            .ok_or_else(|| format!("Konfigurasi {name} belum tersedia."));
        let endpoint = value("R2_ENDPOINT")?;
        let uri: ureq::http::Uri = endpoint.parse().map_err(|_| "Endpoint R2 tidak valid.")?;
        if uri.scheme_str() != Some("https") || uri.path() != "/" || uri.query().is_some()
            || !uri.host().is_some_and(|host| host.ends_with(".r2.cloudflarestorage.com"))
            || uri.authority().is_none_or(|authority| authority.as_str().contains('@'))
        {
            return Err("Gunakan endpoint HTTPS akun Cloudflare R2.".into());
        }
        let bucket = value("R2_BUCKET")?;
        if !(3..=63).contains(&bucket.len()) || !bucket.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
        }) {
            return Err("Nama bucket R2 tidak valid.".into());
        }
        let credentials = Credentials::new(value("R2_ACCESS_KEY_ID")?, value("R2_SECRET_ACCESS_KEY")?, None, None, "ruang-bukti");
        let agent = ureq::Agent::config_builder()
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(10)))
            .build()
            .into();
        Ok(Self { endpoint: endpoint.trim_end_matches('/').into(), bucket, credentials, agent })
    }

    fn request(&self, method: &str, key: &str, body: &[u8]) -> R<Response<ureq::Body>> {
        let digest = key.strip_prefix("ruang-bukti/").ok_or("Referensi R2 tidak valid.")?;
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Referensi R2 tidak valid.".into());
        }
        let url = format!("{}/{}/{}", self.endpoint, self.bucket, key);
        let identity = self.credentials.clone().into();
        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        let parameters = v4::SigningParams::builder().identity(&identity).region("auto").name("s3")
            .time(SystemTime::now()).settings(settings).build().map_err(|_| "Konfigurasi tanda tangan R2 tidak valid.")?;
        let signable = SignableRequest::new(method, url.as_str(), std::iter::empty(), SignableBody::Bytes(body))
            .map_err(|_| "Permintaan R2 tidak valid.")?;
        let (signature, _) = sign(signable, &parameters.into()).map_err(|_| "Permintaan R2 gagal ditandatangani.")?.into_parts();
        let mut request = Request::builder().method(method).uri(url).body(body)
            .map_err(|_| "Permintaan R2 tidak valid.")?;
        signature.apply_to_request_http1x(&mut request);
        let response = self.agent.run(request).map_err(|_| "Cloudflare R2 belum dapat dijangkau.")?;
        if !response.status().is_success() {
            return Err(format!("Cloudflare R2 menolak permintaan ({}).", response.status().as_u16()));
        }
        Ok(response)
    }
}

impl ObjectStore for R2Store {
    fn put(&self, bytes: &[u8]) -> R<String> {
        let key = format!("ruang-bukti/{}", crypto::hash(bytes));
        self.request("PUT", &key, bytes)?;
        Ok(key)
    }

    fn get(&self, key: &str) -> R<Vec<u8>> {
        let mut response = self.request("GET", key, &[])?;
        response.body_mut().with_config().limit(MAX_ENVELOPE as u64).read_to_vec()
            .map_err(|_| "Objek R2 tidak dapat dibaca atau terlalu besar.".into())
    }

    fn delete(&self, key: &str) -> R<()> {
        self.request("DELETE", key, &[])?;
        Ok(())
    }
}
