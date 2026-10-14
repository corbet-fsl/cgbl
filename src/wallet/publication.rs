//! Persist the original signed documents and ring transitions before publication.
use super::*;
use crate::storage::ReadSet;
use cplc::SnapshotKind;
use state::{Signed, State};
use std::sync::Arc;

impl<S: Store, K: csgn::Store> Wallet<S, K> {
    pub(super) fn require_live(&mut self) -> Result<()> {
        if self.instance.upgrade().is_none() || self.barrier.live().is_err() {
            self.retained = None;
            self.observed_at = None;
            return Err(Error::Storage);
        }
        Ok(())
    }
    pub(super) async fn current(&mut self) -> Result<Retained> {
        // Taking before the read makes cancellation/refusal terminal for this
        // writer, rather than leaving an apparently usable cached publication.
        let retained = self.retained.take().ok_or(Error::Storage)?;
        self.require_live()?;
        let key = state::key();
        let actual = self.store.read(std::slice::from_ref(&key)).await?;
        self.require_live()?;
        if actual.revisions != retained.read.revisions
            || actual.records.get(&key).map(|entry| entry.value.as_slice())
                != Some(
                    serde_json::to_vec(&retained.state)
                        .map_err(|_| Error::Encoding)?
                        .as_slice(),
                )
        {
            return Err(Error::Conflict);
        }
        Ok(Retained {
            state: retained.state,
            read: actual,
        })
    }
    pub(super) async fn commit(&mut self, next: State, expected: ReadSet) -> Result<()> {
        self.commit_with(next, expected, Vec::new()).await
    }
    pub(super) async fn commit_with(
        &mut self,
        mut next: State,
        expected: ReadSet,
        mut changes: Vec<crate::storage::Change>,
    ) -> Result<()> {
        next.revision = state::next(next.revision)?;
        let change = state::change(&next)?;
        changes.push(change);
        self.require_live()?;
        self.store.compare_exchange(&expected, changes).await?;
        self.require_live()?;
        let key = state::key();
        let read = self.store.read(std::slice::from_ref(&key)).await?;
        self.require_live()?;
        if read.records.get(&key).map(|record| record.value.as_slice())
            != Some(
                serde_json::to_vec(&next)
                    .map_err(|_| Error::Encoding)?
                    .as_slice(),
            )
        {
            return Err(Error::Conflict);
        }
        self.retained = Some(Retained { state: next, read });
        Ok(())
    }
    pub(super) async fn retain_pending_transition(&mut self, now: u64) -> Result<()> {
        let retained = self.current().await?;
        let revision = self.signer.ring_revision().map_err(|_| Error::Signature)?;
        let last = retained
            .state
            .transitions
            .last()
            .map_or(0, |item| item.revision);
        let Some(proof) = self
            .signer
            .pending_transition()
            .map_err(|_| Error::Signature)?
            .map(<[u8]>::to_vec)
        else {
            if revision != last
                || self
                    .signer
                    .key_ring()
                    .map_err(|_| Error::Signature)?
                    .to_cbor()
                    != retained.state.key_ring
            {
                return Err(Error::KeyMismatch);
            }
            self.retained = Some(retained);
            return Ok(());
        };
        if revision == last {
            if retained
                .state
                .transitions
                .last()
                .map(|item| item.proof.as_slice())
                != Some(proof.as_slice())
                || self
                    .signer
                    .key_ring()
                    .map_err(|_| Error::Signature)?
                    .to_cbor()
                    != retained.state.key_ring
            {
                return Err(Error::KeyMismatch);
            }
            self.retained = Some(retained);
        } else {
            if Some(revision) != last.checked_add(1) {
                return Err(Error::KeyMismatch);
            }
            let prior =
                csgn::KeyRing::from_cbor(&retained.state.key_ring).map_err(|_| Error::Signature)?;
            let transition =
                csgn::verify_transition(&prior, &proof, now).map_err(|_| Error::Signature)?;
            let ring = self.signer.key_ring().map_err(|_| Error::Signature)?;
            if transition.previous() != &prior
                || transition.next() != ring
                || transition.revision() != revision
            {
                return Err(Error::KeyMismatch);
            }
            let mut next = retained.state;
            next.transitions
                .push(cbcn::KeyTransition { revision, proof });
            next.key_ring = ring.to_cbor();
            next.epoch = state::next(next.epoch)?;
            // Preserve each signed-document revision floor across ring changes;
            // the next complete collect replaces bytes at higher revisions.
            next.manifest = None;
            self.commit(next, retained.read).await?;
        }
        // Keep the writer fenced across signer acknowledgement too. A lost
        // reply reopens with the exact already retained proof, never a new ring.
        let retained = self.retained.take().ok_or(Error::Storage)?;
        self.require_live()?;
        self.signer
            .acknowledge_transition(revision)
            .await
            .map_err(|_| Error::Signature)?;
        self.require_live()?;
        self.retained = Some(retained);
        Ok(())
    }
    fn until(&self, state: &State, now: u64) -> Result<u64> {
        (now / 86_400 * 86_400)
            .checked_add(state.config.snapshot_seconds)
            .filter(|until| *until > now)
            .ok_or(Error::InvalidTime)
    }
    async fn sign_document(&mut self, kind: SnapshotKind, now: u64) -> Result<Vec<u8>> {
        self.sample(now)?;
        self.key_ring()?;
        let retained = self.current().await?;
        let revision = state::next(
            retained
                .state
                .documents
                .get(&kind)
                .map_or(0, |entry| entry.revision),
        )?;
        // The signed format is the original CPLc public DTO; no new verifier or
        // wallet-specific signing transcript is introduced.
        let content = match kind {
            SnapshotKind::Settings => serde_json::to_value(
                retained
                    .state
                    .config
                    .rulebook
                    .resolve(&crbk::Values::new())
                    .map_err(|_| Error::Policy)?,
            ),
            SnapshotKind::Schema => serde_json::to_value(retained.state.config.schema()),
            SnapshotKind::SchemaVersions => serde_json::to_value(&retained.state.config.schemas),
            SnapshotKind::Communities => Ok(cplc::communities_content(
                &retained.state.config.communities,
                &retained.state.ended,
                now,
            )),
            SnapshotKind::RevocationList => serde_json::to_value(&retained.state.revocations),
        }
        .map_err(|_| Error::Encoding)?;
        let payload = serde_json::to_vec(&cplc::Snapshot {
            community: "wallet".into(),
            revision,
            policy_epoch: retained.state.epoch,
            content,
        })
        .map_err(|_| Error::Encoding)?;
        if payload.len() > cplc::MAX_DOCUMENT_BYTES {
            return Err(Error::Capacity);
        }
        let until = self.until(&retained.state, now)?;
        let bytes = self
            .signer
            .sign(kind.signing_kind(), &payload, now / 86_400 * 86_400, until)
            .await
            .map_err(|_| Error::Signature)?;
        let mut next = retained.state;
        next.documents.insert(
            kind,
            Signed {
                revision,
                bytes: bytes.clone(),
            },
        );
        next.manifest = None;
        self.commit(next, retained.read).await?;
        Ok(bytes)
    }
    async fn sign_manifest(&mut self, now: u64) -> Result<Vec<u8>> {
        self.sample(now)?;
        let ring = self.key_ring()?.to_cbor();
        let retained = self.current().await?;
        let revision = state::next(retained.state.revision)?;
        let payload = serde_json::to_vec(&cplc::TrustManifest {
            purpose: cplc::TrustPurpose::CommunityTrustV1,
            community: "wallet".into(),
            revision,
            policy_epoch: retained.state.epoch,
            key_ring: ring,
            schema_version: retained.state.config.schemas.current,
            balance_revision: None,
            root_board_revision: None,
            ohttp: None,
        })
        .map_err(|_| Error::Encoding)?;
        let until = self.until(&retained.state, now)?;
        let bytes = self
            .signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &payload,
                now / 86_400 * 86_400,
                until,
            )
            .await
            .map_err(|_| Error::Signature)?;
        let mut next = retained.state;
        next.manifest = Some(Signed {
            revision,
            bytes: bytes.clone(),
        });
        self.commit(next, retained.read).await?;
        Ok(bytes)
    }
    /// Original coherent wallet trust feed. Public passport status is separate.
    pub async fn trust_feed(&mut self, now: u64) -> Result<Arc<cbcn::Feed>> {
        let _sdk = self.capture_sdk().await?;
        self.sample(now)?;
        self.reconcile_keys().await?;
        self.key_ring()?;
        let retained = self.current().await?;
        let revision = retained.state.revision;
        let epoch = retained.state.epoch;
        self.retained = Some(retained);
        match self.beacon.current(now) {
            Ok(feed) if feed.revision == revision && feed.policy_epoch == epoch => {
                self.acknowledge_publication().await?;
                self.require_live()?;
                return Ok(feed);
            }
            Err(cbcn::Error::ClockRegression) => {
                self.retained = None;
                return Err(Error::InvalidTime);
            }
            _ => (),
        }
        let candidate = cbcn::collect(
            &mut Publication {
                wallet: self,
                _sdk: &_sdk,
            },
            now,
        )
        .await
        .map_err(|_| Error::Signature)?;
        let feed = self
            .beacon
            .install(candidate, now)
            .map_err(|_| Error::Signature)?;
        self.acknowledge_publication().await?;
        self.require_live()?;
        Ok(feed)
    }
    /// Recheck the original already published Beacon at the final live-clock
    /// boundary with no await. This is cached public data, not fresh membership.
    pub fn published_feed(&mut self, now: u64) -> Result<Arc<cbcn::Feed>> {
        self.sample(now)?;
        self.key_ring()?;
        let state = &self.retained.as_ref().ok_or(Error::Storage)?.state;
        let revision = state.revision;
        let epoch = state.epoch;
        match self.beacon.current(now) {
            Ok(feed) if feed.revision == revision && feed.policy_epoch == epoch => Ok(feed),
            _ => {
                self.retained = None;
                Err(Error::Signature)
            }
        }
    }
    /// Original whole-view Envoy hint; no per-member observations are exported.
    pub async fn trust_changes(&mut self, revision: u64, now: u64) -> Result<cbcn::Announcement> {
        self.trust_feed(now).await?;
        self.beacon
            .changes_since(revision, now)
            .map_err(|_| Error::Signature)
    }
    /// State that a community's key chain ended: the next Communities snapshot
    /// carries the statement, so member devices that pin this fingerprint delete
    /// their local data of it. Idempotent per fingerprint; statements older than
    /// [`cplc::ENDED_RETENTION_SECONDS`] and beyond [`cplc::MAX_ENTRIES`] are
    /// dropped (oldest first).
    pub async fn end_chain(&mut self, entry: cplc::EndedChain, now: u64) -> Result<()> {
        self.sample(now)?;
        let retained = self.current().await?;
        if retained
            .state
            .ended
            .iter()
            .any(|known| known.fingerprint == entry.fingerprint)
        {
            self.retained = Some(retained);
            return Ok(());
        }
        let mut next = retained.state;
        next.ended.retain(|known| {
            known.ended_at.saturating_add(cplc::ENDED_RETENTION_SECONDS) > now
        });
        next.ended.push(entry);
        next.ended.sort_by_key(|known| std::cmp::Reverse(known.ended_at));
        next.ended.truncate(cplc::MAX_ENTRIES);
        next.manifest = None;
        self.commit(next, retained.read).await
    }
    /// Rotate only through the original signer and durable transition-before-ack.
    pub async fn rotate(&mut self, key: csgn::SecretKey, now: u64) -> Result<()> {
        self.sample(now)?;
        let retained = self.current().await?;
        self.signer
            .rotate(key, now / 86_400 * 86_400)
            .await
            .map_err(|_| Error::Signature)?;
        self.require_live()?;
        self.retained = Some(retained);
        self.retain_pending_transition(now).await?;
        self.require_live()
    }
}
// The original publisher is accessible only while trust_feed retains its actual
// SDK barrier. External collect/publish calls cannot skip inventory ownership.
struct Publication<'a, S, K> {
    wallet: &'a mut Wallet<S, K>,
    _sdk: &'a tokio::sync::OwnedMutexGuard<()>,
}
impl<S: Store, K: csgn::Store> cbcn::Publisher for Publication<'_, S, K> {
    fn key_ring(&self) -> cbcn::Result<csgn::KeyRing> {
        self.wallet
            .key_ring()
            .cloned()
            .map_err(|_| cbcn::Error::Publication)
    }
    fn key_transitions(&self) -> cbcn::Result<Vec<cbcn::KeyTransition>> {
        self.wallet
            .key_ring()
            .map_err(|_| cbcn::Error::Publication)?;
        Ok(self
            .wallet
            .retained
            .as_ref()
            .ok_or(cbcn::Error::Publication)?
            .state
            .transitions
            .clone())
    }
    async fn publish(&mut self, kind: cbcn::Kind, now: u64) -> cbcn::Result<Vec<u8>> {
        let kind = match kind {
            cbcn::Kind::Settings => SnapshotKind::Settings,
            cbcn::Kind::Schema => SnapshotKind::Schema,
            cbcn::Kind::SchemaVersions => SnapshotKind::SchemaVersions,
            cbcn::Kind::Communities => SnapshotKind::Communities,
            cbcn::Kind::Revocations => SnapshotKind::RevocationList,
        };
        self.wallet
            .sign_document(kind, now)
            .await
            .map_err(|_| cbcn::Error::Publication)
    }
    async fn manifest(&mut self, now: u64) -> cbcn::Result<Vec<u8>> {
        self.wallet
            .sign_manifest(now)
            .await
            .map_err(|_| cbcn::Error::Publication)
    }
}
