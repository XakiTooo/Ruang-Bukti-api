#[allow(dead_code)]
#[path = "../backend/mod.rs"]
mod backend;
#[allow(dead_code)]
#[path = "../backend/kripto/envelope.rs"]
mod crypto;
#[path = "../backend/r2.rs"]
mod r2;

mod security {
    pub fn random() -> Result<[u8; 32], getrandom::Error> {
        let mut bytes = [0; 32];
        getrandom::getrandom(&mut bytes)?;
        Ok(bytes)
    }

    pub fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

use http_body_util::{BodyExt, Limited};
use serde_json::{json, Value};
use vercel_runtime::{run, service_fn, Error, Request, Response};

const MAX_REQUEST: usize = 2_810_000;

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(handle)).await
}

async fn handle(request: Request) -> Result<Response<String>, Error> {
    if request.method().as_str() != "POST" {
        return respond(405, json!({"error": "Gunakan POST."}));
    }
    let enrollment_authorized = request.headers().get("authorization").and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer ")).is_some_and(backend::registration::authorized);
    let Ok(body) = Limited::new(request.into_body(), MAX_REQUEST).collect().await else {
        return respond(413, json!({"error": "Permintaan terlalu besar atau tidak dapat dibaca."}));
    };
    let Ok(request) = serde_json::from_slice::<Value>(&body.to_bytes()) else {
        return respond(400, json!({"error": "Permintaan tidak valid."}));
    };
    let enrollment = request["action"].as_str().is_some_and(|action| matches!(action, "enroll_account" | "enrollment_status"));
    if enrollment && !enrollment_authorized {
        return respond(403, json!({"error":"Pendaftaran memerlukan akses pengelola."}));
    }
    if request["action"] == "enrollment_status" {
        return respond(200, json!({"data":{"ok":true}}));
    }
    let result = tokio::task::spawn_blocking(move || {
        if enrollment { return backend::registration::enroll(&request["data"]); }
        let objects = r2::R2Store::configured()?;
        backend::cloud::call(&request, Box::new(objects))
    }).await?;
    match result {
        Ok(data) => respond(200, json!({"data": data})),
        Err(error) => respond(400, json!({"error": error})),
    }
}

fn respond(status: u16, body: Value) -> Result<Response<String>, Error> {
    Ok(Response::builder().status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(body.to_string())?)
}
