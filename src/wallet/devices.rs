//! Original wallet device bindings and generation-fenced publication outbox.
use super::certificate::Timing;
use super::*;
use crate::{
    Account, Subject,
    storage::{Change, Key, ReadSet, Record},
};

const BUCKET: &str = "wallet-device";
const MAX_BINDINGS: usize = 128;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    credential: Vec<u8>,
    key: [u8; 32],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Devices {
    version: u8,
    member: String,
    generation: u64,
    pending: bool,
    bindings: Vec<Binding>,
    removed: BTreeSet<[u8; 32]>,
}
impl Devices {
    fn validate(&self, key: &Key) -> Result<ckyh::Uuid> {
        let member = ckyh::Uuid::parse_str(&self.member).map_err(|_| Error::Encoding)?;
        if self.version != 1
            || key.bucket != BUCKET
            || key.id != self.member
            || member.to_string() != self.member
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || self.bindings.len() > MAX_BINDINGS
            || self.removed.len() > cplc::MAX_ENTRIES
            || self.bindings.iter().any(|binding| {
                binding.credential.is_empty()
                    || binding.credential.len() > 1024
                    || binding.key == [0; 32]
            })
            || self.bindings.windows(2).any(|pair| {
                (&pair[0].credential, pair[0].key) >= (&pair[1].credential, pair[1].key)
            })
        {
            return Err(Error::Encoding);
        }
        Ok(member)
    }
    fn change(&self) -> Result<Change> {
        let key = Key::new(BUCKET, &self.member);
        self.validate(&key)?;
        let value = serde_json::to_vec(self).map_err(|_| Error::Encoding)?;
        if value.len() > cplc::MAX_DOCUMENT_BYTES {
            return Err(Error::Capacity);
        }
        Ok(Change {
            key,
            record: Some(Record { value, deadline: 0 }),
        })
    }
}
fn decode(read: &ReadSet, key: &Key) -> Result<Option<Devices>> {
    read.records
        .get(key)
        .map(|record| {
            if record.deadline != 0 || record.value.len() > cplc::MAX_DOCUMENT_BYTES {
                return Err(Error::Encoding);
            }
            let row: Devices =
                serde_json::from_slice(&record.value).map_err(|_| Error::Encoding)?;
            row.validate(key)?;
            Ok(row)
        })
        .transpose()
}

/// Actual current wallet-local member and live public device keys. This is a
/// short observation for the authenticated host, not a continuing capability.
pub struct WalletDeviceObservation {
    member: String,
    devices: Vec<[u8; 32]>,
    checked_at: u64,
}
impl WalletDeviceObservation {
    /// Wallet-local UUID. Never send it to a community or public feed.
    pub fn member(&self) -> &str {
        &self.member
    }
    /// Actual bindings filtered by current original SDK tombstones/eligibility.
    pub fn devices(&self) -> &[[u8; 32]] {
        &self.devices
    }
    /// Actual final owner observation, not a session deadline or cached verdict.
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
}

impl<S: Store, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    fn owns_wallet<W: csgn::Store>(
        &self,
        wallet: &Wallet<S, W>,
        auth: &ckyh::Authentication,
    ) -> Result<()> {
        let instance = wallet.instance.upgrade().ok_or(Error::Storage)?;
        if !std::sync::Arc::ptr_eq(&instance, &self.wallet_instance) || auth.community() != "wallet"
        {
            return Err(Error::KeyMismatch);
        }
        Ok(())
    }
    /// Durably signal a member's additional-key/revoke/self-ban change before
    /// its original leaf mutation. This grants no mutation permission. The host
    /// retains its exact Auth/Global guards, performs the original operation,
    /// and publishes the reconciled feed before acknowledging the generation.
    pub async fn signal_wallet_key_mutation<W: csgn::Store>(
        &self,
        wallet: &mut Wallet<S, W>,
        auth: &ckyh::Authentication,
        mutation: &WalletMutation,
        expires: u64,
        clock: &impl Fn() -> u64,
    ) -> Result<()> {
        self.owns_wallet(wallet, auth)?;
        mutation.same(wallet)?;
        let now = clock();
        wallet.sample(now)?;
        let mut timing = Timing::new(now, expires).inspect_err(|_| wallet.observed_at = None)?;
        let retained = wallet.current().await?;
        timing.sample(wallet, clock())?;
        let subject = Subject::new(auth.member().to_string())?;
        let account = self.wallet_account(&subject, now).await?;
        timing.sample(wallet, clock())?;
        let keys = wallet.passkeys.clone();
        let authentication = auth.clone();
        tokio::task::spawn_blocking(move || keys.public_credential(&authentication))
            .await
            .map_err(|_| Error::Storage)?
            .map_err(|_| Error::Signature)?;
        let completed = clock();
        timing.sample(wallet, completed)?;
        let key = Key::new(BUCKET, subject.as_str());
        let mut read = wallet.store.read(std::slice::from_ref(&key)).await?;
        timing.sample(wallet, clock())?;
        let mut row = decode(&read, &key)?.unwrap_or(Devices {
            version: 1,
            member: subject.as_str().into(),
            generation: 1,
            pending: false,
            bindings: vec![],
            removed: BTreeSet::new(),
        });
        row.generation = state::next(row.generation)?;
        row.pending = true;
        read.revisions.extend(account.revisions);
        read.revisions.extend(retained.read.revisions);
        let mut next = retained.state;
        next.epoch = state::next(next.epoch)?;
        next.manifest = None;
        wallet.commit_with(next, read, vec![row.change()?]).await?;
        let committed = wallet.retained.take().ok_or(Error::Storage)?;
        let returned_at = clock();
        timing
            .sample(wallet, returned_at)
            .map_err(|_| Error::Storage)?;
        wallet.observed_at = Some(returned_at);
        wallet.retained = Some(committed);
        Ok(())
    }

    /// Read original wallet device bindings under the actual current session.
    /// The host retains Auth/Global locks and applies its final output guard.
    pub async fn wallet_devices<W: csgn::Store>(
        &self,
        wallet: &mut Wallet<S, W>,
        auth: &ckyh::Authentication,
        expires: u64,
        clock: &impl Fn() -> u64,
    ) -> Result<WalletDeviceObservation> {
        self.owns_wallet(wallet, auth)?;
        let _sdk = wallet.capture_sdk().await?;
        self.wallet_devices_held(wallet, auth, expires, clock).await
    }
    async fn wallet_devices_held<W: csgn::Store>(
        &self,
        wallet: &mut Wallet<S, W>,
        auth: &ckyh::Authentication,
        expires: u64,
        clock: &impl Fn() -> u64,
    ) -> Result<WalletDeviceObservation> {
        self.owns_wallet(wallet, auth)?;
        let now = clock();
        wallet.sample(now)?;
        let mut timing = Timing::new(now, expires).inspect_err(|_| wallet.observed_at = None)?;
        let retained = wallet.current().await?;
        timing.sample(wallet, clock())?;
        let subject = Subject::new(auth.member().to_string())?;
        let account = self.wallet_account(&subject, now).await?;
        timing.sample(wallet, clock())?;
        let keys = wallet.passkeys.clone();
        let authentication = auth.clone();
        let rows = tokio::task::spawn_blocking(move || {
            keys.public_credential(&authentication)?;
            keys.list(authentication.member())
        })
        .await
        .map_err(|_| Error::Storage)?
        .map_err(|_| Error::Signature)?;
        let after_keys = clock();
        timing.sample(wallet, after_keys)?;
        let key = Key::new(BUCKET, subject.as_str());
        let read = wallet.store.read(std::slice::from_ref(&key)).await?;
        timing.sample(wallet, clock())?;
        let row = decode(&read, &key)?;
        let current = self.wallet_account(&subject, after_keys).await?;
        if current.revisions != account.revisions {
            return Err(Error::Conflict);
        }
        let completed = clock();
        timing.sample(wallet, completed)?;
        let active: BTreeSet<Vec<u8>> = rows
            .into_iter()
            .filter(|key| !key.is_revoked())
            .map(|key| key.credential_id().as_ref().to_vec())
            .collect();
        let devices = row
            .map(|row| {
                row.bindings
                    .into_iter()
                    .filter(|binding| active.contains(&binding.credential))
                    .map(|binding| binding.key)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default()
            .into_iter()
            .collect();
        wallet.observed_at = Some(completed);
        wallet.retained = Some(retained);
        Ok(WalletDeviceObservation {
            member: subject.as_str().into(),
            devices,
            checked_at: completed,
        })
    }
    /// Bind a public device only to the exact passkey that authenticated. The
    /// outbox is durable before replacing any old binding, even on lost replies.
    pub async fn authorize_wallet_device<W: csgn::Store>(
        &self,
        wallet: &mut Wallet<S, W>,
        auth: &ckyh::Authentication,
        device: [u8; 32],
        expires: u64,
        clock: &impl Fn() -> u64,
    ) -> Result<WalletDeviceObservation> {
        self.owns_wallet(wallet, auth)?;
        let _sdk = wallet.capture_sdk().await?;
        if device == [0; 32] {
            return Err(Error::InvalidIdentifier);
        }
        let now = clock();
        wallet.sample(now)?;
        let mut timing = Timing::new(now, expires).inspect_err(|_| wallet.observed_at = None)?;
        let retained = wallet.current().await?;
        timing.sample(wallet, clock())?;
        let subject = Subject::new(auth.member().to_string())?;
        let account = self.wallet_account(&subject, now).await?;
        timing.sample(wallet, clock())?;
        let keys = wallet.passkeys.clone();
        let authentication = auth.clone();
        tokio::task::spawn_blocking(move || keys.public_credential(&authentication))
            .await
            .map_err(|_| Error::Storage)?
            .map_err(|_| Error::Signature)?;
        let observed = clock();
        timing.sample(wallet, observed)?;
        let key = Key::new(BUCKET, subject.as_str());
        let mut read = wallet.store.read(std::slice::from_ref(&key)).await?;
        timing.sample(wallet, clock())?;
        let mut row = decode(&read, &key)?.unwrap_or(Devices {
            version: 1,
            member: subject.as_str().into(),
            generation: 1,
            pending: false,
            bindings: vec![],
            removed: BTreeSet::new(),
        });
        let credential = auth.credential_id().as_ref().to_vec();
        if !row
            .bindings
            .iter()
            .any(|binding| binding.credential == credential && binding.key == device)
        {
            for old in row
                .bindings
                .iter()
                .filter(|binding| binding.credential == credential)
            {
                row.removed.insert(old.key);
            }
            row.bindings
                .retain(|binding| binding.credential != credential);
            row.bindings.push(Binding {
                credential,
                key: device,
            });
            row.bindings
                .sort_by(|a, b| (&a.credential, a.key).cmp(&(&b.credential, b.key)));
            row.generation = state::next(row.generation)?;
            row.pending = true;
            // Original account revisions join this exact mutation CAS. A
            // concurrent suspension cannot become a successful new binding.
            read.revisions.extend(account.revisions);
            read.revisions.extend(retained.read.revisions);
            let mut next = retained.state;
            next.epoch = state::next(next.epoch)?;
            next.manifest = None;
            wallet.commit_with(next, read, vec![row.change()?]).await?;
        } else {
            wallet.retained = Some(retained);
        }
        // Every post-write refusal is uncertainty. Never turn it into a normal
        // retry or leave this writer usable without durable reconciliation.
        match self.wallet_devices_held(wallet, auth, expires, clock).await {
            Ok(observed) => Ok(observed),
            Err(_) => {
                wallet.retained = None;
                wallet.observed_at = None;
                Err(Error::Storage)
            }
        }
    }
}

impl<S: Store, K: csgn::Store> Wallet<S, K> {
    pub(super) async fn reconcile_keys(&mut self, now: u64) -> Result<()> {
        let retained = self.current().await?;
        let mut revocations = cplc::Revocations::default();
        let mut pending = Vec::new();
        let mut observed = ReadSet::default();
        let mut after = String::new();
        loop {
            let page = self.store.list(BUCKET, &after, 128).await?;
            self.require_live()?;
            if page.records.is_empty() {
                break;
            }
            for key in page.records.keys() {
                observed.revisions.insert(key.clone(), page.revisions[key]);
                let row = decode(&page, key)?.ok_or(Error::Encoding)?;
                let member = row.validate(key)?;
                let keys = self.passkeys.clone();
                let passkeys = tokio::task::spawn_blocking(move || keys.list(member))
                    .await
                    .map_err(|_| Error::Storage)?
                    .map_err(|_| Error::Signature)?;
                self.require_live()?;
                let account_key = Key::new("account", &row.member);
                let account_read = self.store.read(std::slice::from_ref(&account_key)).await?;
                self.require_live()?;
                observed.revisions.extend(account_read.revisions.clone());
                let account: Account = account_read
                    .records
                    .get(&account_key)
                    .map(|record| {
                        serde_json::from_slice(&record.value).map_err(|_| Error::Encoding)
                    })
                    .transpose()?
                    .unwrap_or_default();
                let blocked = account.eligible().is_err();
                revocations.devices.extend(row.removed);
                for passkey in passkeys {
                    if passkey.community() != "wallet" || passkey.member() != member {
                        return Err(Error::KeyMismatch);
                    }
                    if passkey.is_revoked() || blocked {
                        let id = passkey.credential_id().as_ref().to_vec();
                        revocations.devices.extend(
                            row.bindings
                                .iter()
                                .filter(|binding| binding.credential == id)
                                .map(|binding| binding.key),
                        );
                        revocations.passkeys.insert(id);
                    }
                }
                if revocations.devices.len() > cplc::MAX_ENTRIES
                    || revocations.passkeys.len() > cplc::MAX_ENTRIES
                {
                    return Err(Error::Capacity);
                }
                if row.pending {
                    pending.push((key.clone(), row.generation));
                }
                after = key.id.clone();
            }
        }
        if retained.state.revocations != revocations {
            let mut next = retained.state;
            next.revocations = revocations;
            next.epoch = state::next(next.epoch)?;
            next.manifest = None;
            self.commit(next, retained.read).await?;
        } else {
            self.retained = Some(retained);
        }
        // Publication installation acknowledges these exact generations later.
        // New mutations remain pending even when a collected old view finishes.
        self.pending = pending;
        self.require_live()?;
        self.publication_reads = Some(observed);
        Ok(())
    }

    pub(super) async fn acknowledge_publication(&mut self) -> Result<()> {
        let retained = self.current().await?;
        let observed = self.publication_reads.take().ok_or(Error::Storage)?;
        let keys: Vec<_> = observed.revisions.keys().cloned().collect();
        let mut read = self.store.read(&keys).await?;
        self.require_live()?;
        if read.revisions != observed.revisions {
            return Err(Error::Conflict);
        }
        let mut changes = Vec::new();
        for (key, generation) in &self.pending {
            let mut row = decode(&read, key)?.ok_or(Error::Encoding)?;
            if row.generation != *generation || !row.pending {
                return Err(Error::Conflict);
            }
            row.pending = false;
            changes.push(row.change()?);
        }
        if !changes.is_empty() {
            read.revisions.extend(retained.read.revisions.clone());
            self.require_live()?;
            self.store.compare_exchange(&read, changes).await?;
        }
        self.require_live()?;
        self.pending.clear();
        self.retained = Some(retained);
        Ok(())
    }
}
