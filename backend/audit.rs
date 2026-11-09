use super::EvidenceService;
use crate::crypto;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Event {
    pub(super) action: String,
    pub(super) actor: String,
    pub(super) evidence: String,
    pub(super) time: u64,
    pub(super) previous: String,
    pub(super) hash: String,
    #[serde(default)]
    pub(super) actor_username: Option<String>,
    #[serde(default)]
    pub(super) recipient: Option<String>,
}

impl EvidenceService {
    pub(super) fn record(&mut self, action: &'static str, evidence: String) {
        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let previous = self.events.last().map(|event| event.hash.clone()).unwrap_or_else(|| "GENESIS".into());
        self.record_to(action, evidence, None, time, previous);
    }

    pub(super) fn record_transfer(&mut self, action: &'static str, evidence: String, recipient: String) {
        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let previous = self.events.last().map(|event| event.hash.clone()).unwrap_or_else(|| "GENESIS".into());
        self.record_to(action, evidence, Some(recipient), time, previous);
    }

    fn record_to(&mut self, action: &'static str, evidence: String, recipient: Option<String>, time: u64, previous: String) {
        let mut event = Event { action: action.into(), actor: self.role.into(), evidence, time, previous,
            hash: String::new(), actor_username: Some(self.username().into()), recipient };
        event.hash = event_hash(&event);
        self.events.push(event);
    }

    pub(super) fn verify_audit(&self) -> bool {
        verify_events(&self.events)
    }
}

pub(super) fn verify_events(events: &[Event]) -> bool {
    let mut previous = "GENESIS";
    for event in events {
        if event.previous != previous ||
            event.hash != event_hash(event)
        {
            return false;
        }
        previous = &event.hash;
    }
    true
}

fn event_hash(event: &Event) -> String {
    let mut fields = json!([event.action, event.actor, event.evidence, event.time, event.previous]);
    if event.actor_username.is_some() || event.recipient.is_some() {
        fields.as_array_mut().unwrap().extend([json!(event.actor_username), json!(event.recipient)]);
    }
    crypto::hash(fields.to_string().as_bytes())
}
