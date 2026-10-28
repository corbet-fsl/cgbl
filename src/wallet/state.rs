//! Original global Store CAS for private wallet publication state.
use super::*;
use crate::storage::{Change, Key, ReadSet, Record};
use std::collections::BTreeMap;

pub(super) fn key() -> Key {
    Key::new("wallet", "publications")
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Signed {
    pub revision: u64,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct State {
    pub version: u8,
    pub revision: u64,
    pub epoch: u64,
    pub key_ring: Vec<u8>,
    pub config: WalletPublicationConfig,
    pub revocations: cplc::Revocations,
    pub transitions: Vec<cbcn::KeyTransition>,
    pub documents: BTreeMap<cplc::SnapshotKind, Signed>,
    pub manifest: Option<Signed>,
    /// Chains the platform has ended, newest last; published in the Communities snapshot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ended: Vec<super::EndedChain>,
}
impl State {
    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        let ring = csgn::KeyRing::from_cbor(&self.key_ring).map_err(|_| Error::Encoding)?;
        cbcn::validate_transition_history(&self.transitions).map_err(|_| Error::Encoding)?;
        if ring.issuer() != "wallet"
            || self.version != 1
            || self.revision == 0
            || self.revision > i64::MAX as u64
            || self.epoch == 0
            || self.epoch > i64::MAX as u64
            || !self.revocations.members.is_empty()
            || self.ended.len() > super::MAX_ENDED
            || self
                .ended
                .iter()
                .map(|entry| entry.fingerprint)
                .collect::<BTreeSet<_>>()
                .len()
                != self.ended.len()
            || self.revocations.devices.len() > cplc::MAX_ENTRIES
            || self.revocations.passkeys.len() > cplc::MAX_ENTRIES
            || self
                .revocations
                .passkeys
                .iter()
                .any(|id| id.is_empty() || id.len() > 1024)
            || self
                .documents
                .values()
                .chain(self.manifest.iter())
                .any(|signed| {
                    signed.revision == 0
                        || signed.revision > self.revision
                        || signed.bytes.is_empty()
                        || signed.bytes.len() > cplc::MAX_DOCUMENT_BYTES + 8192
                })
        {
            return Err(Error::Encoding);
        }
        Ok(())
    }
}
pub(super) struct Retained {
    pub state: State,
    pub read: ReadSet,
}

pub(super) async fn open(
    store: &impl Store,
    config: WalletPublicationConfig,
    initial_ring: Vec<u8>,
    initial_revision: u64,
) -> Result<Retained> {
    let key = key();
    let mut read = store.read(std::slice::from_ref(&key)).await?;
    let state = match read.records.get(&key) {
        Some(record) => {
            if record.deadline != 0 || record.value.len() > max_stored_bytes() {
                return Err(Error::Encoding);
            }
            let state: State =
                serde_json::from_slice(&record.value).map_err(|_| Error::Encoding)?;
            state.validate()?;
            if state.config != config {
                return Err(Error::KeyMismatch);
            }
            state
        }
        None => {
            if initial_revision != 0 {
                return Err(Error::KeyMismatch);
            }
            let state = State {
                version: 1,
                revision: 1,
                epoch: 1,
                config,
                key_ring: initial_ring,
                revocations: cplc::Revocations::default(),
                transitions: Vec::new(),
                documents: BTreeMap::new(),
                manifest: None,
                ended: Vec::new(),
            };
            state.validate()?;
            store.compare_exchange(&read, vec![change(&state)?]).await?;
            read = store.read(std::slice::from_ref(&key)).await?;
            let actual = read.records.get(&key).ok_or(Error::Storage)?;
            if actual.value != serde_json::to_vec(&state).map_err(|_| Error::Encoding)? {
                return Err(Error::Conflict);
            }
            state
        }
    };
    Ok(Retained { state, read })
}
pub(super) fn next(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .filter(|value| *value <= i64::MAX as u64)
        .ok_or(Error::Exhausted)
}
fn max_stored_bytes() -> usize {
    cplc::MAX_DOCUMENT_BYTES
        + 6 * 4 * (cplc::MAX_DOCUMENT_BYTES + 8192)
        + 4 * cbcn::MAX_KEY_TRANSITION_BYTES
}

#[cfg(test)]
#[path = "tests/state.rs"]
mod tests;
pub(super) fn change(state: &State) -> Result<Change> {
    state.validate()?;
    let value = serde_json::to_vec(state).map_err(|_| Error::Encoding)?;
    if value.len() > max_stored_bytes() {
        return Err(Error::Capacity);
    }
    Ok(Change {
        key: key(),
        record: Some(Record { value, deadline: 0 }),
    })
}
