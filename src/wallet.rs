//! Isolated wallet trust publications through the original signer and Beacon.
//! Passport status and its `cgbl:global` issuer remain separate.
use crate::{Error, Global, Result, storage::Store};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(crate) mod barrier;
pub use barrier::{WalletMutation, WalletShutdown};
mod birth;
mod certificate;
mod devices;
mod publication;
mod state;
pub use birth::WalletBirthStatement;
pub use certificate::WalletPasskeyCertificate;
pub use devices::WalletDeviceObservation;
use state::Retained;

/// Explicit host-owned wallet settings and schema history. No policy defaults
/// are discovered. This is configuration data, never admission or a credential.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletPublicationConfig {
    rp_id: String,
    passkey_origin: String,
    rulebook: crbk::Rulebook,
    schemas: cplc::SchemaVersions,
    communities: BTreeSet<String>,
    snapshot_seconds: u64,
}
impl WalletPublicationConfig {
    /// Validate actual configured rulebook/schema owners and publication lifetime.
    /// `communities` is an explicit public directory, never memberships or proof
    /// metadata. Wallet identifiers/roots must not be inserted into that directory.
    pub fn new(
        rp_id: &str,
        passkey_origin: &str,
        rulebook: crbk::Rulebook,
        schemas: cplc::SchemaVersions,
        communities: BTreeSet<String>,
        snapshot_seconds: u64,
    ) -> Result<Self> {
        let config = Self {
            rp_id: rp_id.into(),
            passkey_origin: ckyh::Url::parse(passkey_origin)
                .map_err(|_| Error::Policy)?
                .to_string(),
            rulebook,
            schemas,
            communities,
            snapshot_seconds,
        };
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> Result<()> {
        let origin = ckyh::Url::parse(&self.passkey_origin).map_err(|_| Error::Policy)?;
        // Every passkey ceremony runs in the vault frame on the vault origin
        // `vault.<rp_id>`; the relying party stays the wallet host.
        let vault = format!("vault.{}", self.rp_id);
        if origin.scheme() != "https"
            || origin.host_str() != Some(vault.as_str())
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
        {
            return Err(Error::Policy);
        }
        self.rulebook.validate().map_err(|_| Error::Policy)?;
        self.rulebook
            .resolve(&crbk::Values::new())
            .map_err(|_| Error::Policy)?;
        if self.snapshot_seconds == 0
            || !self.snapshot_seconds.is_multiple_of(86_400)
            || self.snapshot_seconds > i64::MAX as u64
            || self.schemas.purpose != cplc::SchemaVersionsPurpose::SchemaVersionsV1
            || self.schemas.versions.is_empty()
            || self.schemas.versions.len() > cplc::MAX_ENTRIES
            || self.communities.len() > cplc::MAX_ENTRIES
        {
            return Err(Error::Policy);
        }
        for community in &self.communities {
            crate::validate_id(community)?;
        }
        let mut previous: Option<&cshm::Schema> = None;
        for retained in &self.schemas.versions {
            let schema = &retained.schema;
            schema.validate_definition().map_err(|_| Error::Policy)?;
            if schema.community != "wallet"
                || schema.version == 0
                || schema.public.len() + schema.private.len() > cplc::MAX_ENTRIES
                || previous.is_some_and(|prior| prior.version >= schema.version)
            {
                return Err(Error::Policy);
            }
            let expected = previous
                .map(|prior| cshm::classify_changes(prior, schema).map_err(|_| Error::Policy))
                .transpose()?;
            if retained.changes != expected {
                return Err(Error::Policy);
            }
            previous = Some(schema);
        }
        if previous.map(|schema| schema.version) != Some(self.schemas.current)
            || serde_json::to_vec(self).map_err(|_| Error::Encoding)?.len()
                > cplc::MAX_DOCUMENT_BYTES
        {
            return Err(Error::Policy);
        }
        Ok(())
    }
    fn schema(&self) -> &cshm::Schema {
        // The private configuration is validated before owner construction/read.
        &self.schemas.versions[self.schemas.versions.len() - 1].schema
    }
}

/// The most ended chains one Communities snapshot lists; devices refuse a longer list.
pub const MAX_ENDED: usize = 4096;

/// Why a community's key chain ended (the wire names of the platform feed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndedReason {
    /// The community's admins dissolved it.
    Dissolved,
    /// The platform ended it.
    Banned,
}

/// One end-of-chain statement: no names, no member information.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndedChain {
    /// SHA-256 of the ended community's genesis document.
    #[serde(with = "hex32")]
    pub fingerprint: [u8; 32],
    pub reason_class: EndedReason,
    /// Unix seconds at which it ended.
    pub ended_at: u64,
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};
    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let text: String = value.iter().map(|byte| format!("{byte:02x}")).collect();
        serializer.serialize_str(&text)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(D::Error::custom("expected 64 lowercase hex characters"));
        }
        let mut out = [0u8; 32];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).map_err(D::Error::custom)?;
        }
        Ok(out)
    }
}

/// Single configured wallet publisher. No root, passport issuer or arbitrary
/// signing API escapes. Cancellation/storage uncertainty terminally fences this
/// instance; reopen from the actual stores to reconcile the durable winner.
pub struct Wallet<S, K> {
    barrier: std::sync::Arc<barrier::Barrier>,
    pending: Vec<(crate::storage::Key, u64)>,
    publication_reads: Option<crate::storage::ReadSet>,
    passkeys: std::sync::Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
    instance: std::sync::Weak<()>,
    store: S,
    signer: csgn::PersistentSigner<K>,
    retained: Option<Retained>,
    beacon: cbcn::Beacon,
    observed_at: Option<u64>,
}
impl<S: Store + Clone, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    /// Bind a separate literal-wallet signer to this actual global store. The
    /// host supplies the wallet key separately from its passport signing key.
    /// Existing config/key continuity must match exactly; no silent reset.
    pub async fn open_wallet<W: csgn::Store>(
        &self,
        signer: csgn::PersistentSigner<W>,
        config: WalletPublicationConfig,
        passkeys: std::sync::Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
        now: u64,
    ) -> Result<Wallet<S, W>> {
        Wallet::open(
            self.store.clone(),
            signer,
            config,
            passkeys,
            now,
            std::sync::Arc::downgrade(&self.wallet_instance),
            self.wallet_barrier.clone(),
        )
        .await
    }
}

impl<S: Store, K: csgn::Store> Wallet<S, K> {
    async fn open(
        store: S,
        signer: csgn::PersistentSigner<K>,
        config: WalletPublicationConfig,
        passkeys: std::sync::Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
        now: u64,
        instance: std::sync::Weak<()>,
        barrier: std::sync::Arc<barrier::Barrier>,
    ) -> Result<Self> {
        crate::time(now)?;
        config.validate()?;
        barrier.bind(&passkeys)?;
        barrier.live()?;
        let (rp, origins) = passkeys
            .wallet_configuration()
            .map_err(|_| Error::KeyMismatch)?;
        if rp != config.rp_id || origins != [config.passkey_origin.clone()] {
            return Err(Error::KeyMismatch);
        }
        let ring = signer.key_ring().map_err(|_| Error::Signature)?;
        if ring.issuer() != "wallet"
            || ring.max_validity() < config.snapshot_seconds
            || ring
                .active()
                .is_none_or(|key| key.activated_at() % 86_400 != 0)
        {
            return Err(Error::KeyMismatch);
        }
        let initial_ring = ring.to_cbor();
        let revision = signer.ring_revision().map_err(|_| Error::Signature)?;
        let retained = state::open(&store, config, initial_ring, revision).await?;
        let mut owner = Self {
            barrier,
            pending: Vec::new(),
            publication_reads: None,
            passkeys,
            instance,
            store,
            signer,
            retained: Some(retained),
            beacon: cbcn::Beacon::default(),
            observed_at: Some(now),
        };
        owner.retain_pending_transition(now).await?;
        owner.key_ring()?;
        Ok(owner)
    }
    fn sample(&mut self, now: u64) -> Result<()> {
        let floor = self.observed_at.take().ok_or(Error::InvalidTime)?;
        if now < floor {
            self.retained = None;
            return Err(Error::InvalidTime);
        }
        crate::time(now)?;
        self.observed_at = Some(now);
        Ok(())
    }
    /// Original wallet key ring after the owner's durable continuity fence.
    /// This public data is not a live membership or freshness verdict.
    pub fn key_ring(&self) -> Result<&csgn::KeyRing> {
        self.instance.upgrade().ok_or(Error::Storage)?;
        self.barrier.live()?;
        self.observed_at.ok_or(Error::InvalidTime)?;
        let retained = self.retained.as_ref().ok_or(Error::Storage)?;
        let floor = retained
            .state
            .transitions
            .last()
            .map_or(0, |entry| entry.revision);
        if self.signer.ring_revision().map_err(|_| Error::Signature)? != floor
            || self
                .signer
                .pending_transition()
                .map_err(|_| Error::Signature)?
                .is_some()
            || self
                .signer
                .key_ring()
                .map_err(|_| Error::Signature)?
                .to_cbor()
                != retained.state.key_ring
        {
            return Err(Error::KeyMismatch);
        }
        self.signer.key_ring().map_err(|_| Error::Signature)
    }
}
