//! The exact retained SDK owner barrier, never a membership permission.
use super::*;
use std::sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

pub(crate) struct Barrier {
    gate: Arc<AsyncMutex<()>>,
    sdk: Mutex<Option<Weak<ckyh::Passkeys<ckyh::LibsqlStore>>>>,
    fenced: AtomicBool,
}
impl Barrier {
    pub(crate) fn new() -> Self {
        Self {
            gate: Arc::default(),
            sdk: Mutex::new(None),
            fenced: AtomicBool::new(false),
        }
    }
    pub(super) fn bind(&self, sdk: &Arc<ckyh::Passkeys<ckyh::LibsqlStore>>) -> Result<()> {
        let mut retained = self.sdk.lock().map_err(|_| Error::Storage)?;
        match &*retained {
            Some(original) if !Weak::ptr_eq(original, &Arc::downgrade(sdk)) => {
                Err(Error::KeyMismatch)
            }
            Some(_) => Ok(()),
            None => {
                *retained = Some(Arc::downgrade(sdk));
                Ok(())
            }
        }
    }
    pub(super) fn live(&self) -> Result<()> {
        if self.fenced.load(Ordering::SeqCst) {
            return Err(Error::Storage);
        }
        Ok(())
    }
    async fn capture(&self) -> Result<OwnedMutexGuard<()>> {
        self.live()?;
        let guard = self.gate.clone().lock_owned().await;
        self.live()?;
        Ok(guard)
    }
}

/// Serialization of one original SDK mutation. This is not mutation permission:
/// the host still validates its exact Auth session and original SDK operation.
/// The private owner/SDK/guard cannot be constructed, cloned or serialized.
pub struct WalletMutation {
    barrier: Arc<Barrier>,
    instance: Weak<()>,
    sdk: Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
    _guard: OwnedMutexGuard<()>,
}
impl WalletMutation {
    /// Refuse a different actual SDK owner, even with identical RP metadata.
    pub fn matches(&self, sdk: &Arc<ckyh::Passkeys<ckyh::LibsqlStore>>) -> bool {
        self.instance.upgrade().is_some()
            && self.barrier.live().is_ok()
            && Arc::ptr_eq(&self.sdk, sdk)
    }
    /// Move the same actual owner barrier into the original blocking SDK worker.
    /// Cancellation of this waiter cannot release it while that worker continues.
    /// No SDK is supplied by the caller and no operation result grants authority.
    pub async fn execute<T: Send + 'static>(
        self,
        operation: impl FnOnce(
            &ckyh::Passkeys<ckyh::LibsqlStore>,
        ) -> std::result::Result<T, ckyh::Error>
        + Send
        + 'static,
    ) -> std::result::Result<T, ckyh::Error> {
        let instance = self.instance.clone();
        let barrier = self.barrier.clone();
        let result = tokio::task::spawn_blocking(move || {
            if self.instance.upgrade().is_none() || self.barrier.live().is_err() {
                return Err(ckyh::Error::Storage);
            }
            let result = operation(&self.sdk);
            if self.instance.upgrade().is_none() || self.barrier.live().is_err() {
                return Err(ckyh::Error::Storage);
            }
            drop(self);
            result
        })
        .await
        .map_err(|_| ckyh::Error::Storage)?;
        if instance.upgrade().is_none() || barrier.live().is_err() {
            return Err(ckyh::Error::Storage);
        }
        result
    }
    pub(super) fn same<S, K>(&self, wallet: &Wallet<S, K>) -> Result<()> {
        if !Weak::ptr_eq(&self.instance, &wallet.instance)
            || !Arc::ptr_eq(&self.barrier, &wallet.barrier)
            || !self.matches(&wallet.passkeys)
        {
            return Err(Error::KeyMismatch);
        }
        Ok(())
    }
}

/// Actual SDK-worker teardown. Hosts fence intake before awaiting this owner
/// under their original total shutdown budget; timeout is not joined success.
#[derive(Clone)]
pub struct WalletShutdown(Arc<Barrier>);
impl WalletShutdown {
    /// Synchronously refuse new inventories, publications and SDK mutation starts.
    pub fn begin_shutdown(&self) {
        self.0.fenced.store(true, Ordering::SeqCst);
    }
    /// Join the actual worker-held barrier before closing its database runtime.
    pub async fn shutdown(&self) {
        self.begin_shutdown();
        let _joined = self.0.gate.clone().lock_owned().await;
    }
}
impl<S: Store, K: csgn::Store> Wallet<S, K> {
    pub(super) async fn capture_sdk(&mut self) -> Result<OwnedMutexGuard<()>> {
        self.require_live()?;
        self.barrier.bind(&self.passkeys)?;
        let retained = self.retained.take().ok_or(Error::Storage)?;
        let floor = self.observed_at.take().ok_or(Error::InvalidTime)?;
        let captured = self.barrier.capture().await;
        if captured.is_err() {
            self.retained = None;
            self.observed_at = None;
        }
        let guard = captured?;
        self.require_live()?;
        self.retained = Some(retained);
        self.observed_at = Some(floor);
        Ok(guard)
    }
    /// Clone only the real worker shutdown owner; no signing or member access.
    pub fn shutdown_handle(&self) -> WalletShutdown {
        WalletShutdown(self.barrier.clone())
    }
}
impl<S: Store, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    /// Hold the original per-owner SDK barrier before signaling an actual
    /// mutation. Auth must move it into the same original SDK worker next.
    /// This creates no account, mutation approval, root or membership authority.
    pub async fn wallet_mutation<W: csgn::Store>(
        &self,
        wallet: &mut Wallet<S, W>,
    ) -> Result<WalletMutation> {
        let instance = wallet.instance.upgrade().ok_or(Error::Storage)?;
        if !Arc::ptr_eq(&instance, &self.wallet_instance) {
            return Err(Error::KeyMismatch);
        }
        drop(instance);
        let guard = wallet.capture_sdk().await?;
        Ok(WalletMutation {
            barrier: wallet.barrier.clone(),
            instance: wallet.instance.clone(),
            sdk: wallet.passkeys.clone(),
            _guard: guard,
        })
    }
}

// Focused kill tests for the barrier.rs survivors in the mut138 brief.
//
// - `bind` pins the first SDK owner: a second, different SDK is refused
//   (kills 23:9 `-> Ok(())` and 25:31 guard `-> false`).
// - `same` requires the identical barrier AND instance AND owner match:
//   a wallet on a different barrier (only that arm firing) is refused
//   (kills 97:9 `-> Ok(())` and both `||` -> `&&` mutants at 98:13/99:13).
//
// NOTE: the three `WalletMutation::execute` `||` -> `&&` mutants
// (79:50, 83:50, 91:41) are unreachable: the pre-, post- and post-await
// guards test the same monotonic state (dead instance or fenced barrier)
// three times, so weakening any single one never changes the outcome while
// the other two stay real. No deterministic single-threaded test can make
// exactly one of the three fire.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStore;
    use std::sync::Arc;

    const RP: &str = "wallet.example.test";
    const ORIGIN: &str = "https://vault.wallet.example.test";
    const DAY: u64 = 86_400;

    async fn passkeys() -> (tempfile::TempDir, Arc<ckyh::Passkeys<ckyh::LibsqlStore>>) {
        let directory = tempfile::tempdir().unwrap();
        let url = ckyh::Url::from_file_path(directory.path().join("wallet.db")).unwrap();
        let db = crlt::Db::open(crlt::Config::new(url.as_str(), ""))
            .await
            .unwrap();
        db.migrate(&[crlt::Migration::new(1, "passkeys", ckyh::LIBSQL_SCHEMA)])
            .await
            .unwrap();
        let keys = Arc::new(
            ckyh::Passkeys::new(
                ckyh::LibsqlStore::new(&db, "wallet", tokio::runtime::Handle::current()).unwrap(),
                "wallet",
                RP,
                &[ckyh::Url::parse(ORIGIN).unwrap()],
            )
            .unwrap(),
        );
        (directory, keys)
    }

    async fn wallet_with(
        barrier: Arc<Barrier>,
        instance: &Arc<()>,
        sdk: Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
    ) -> Wallet<MemoryStore, csgn::MemoryStore> {
        Wallet {
            barrier,
            pending: Vec::new(),
            publication_reads: None,
            passkeys: sdk,
            instance: Arc::downgrade(instance),
            store: MemoryStore::new("barrier-test").unwrap(),
            signer: csgn::PersistentSigner::create(
                csgn::MemoryStore::default(),
                "wallet",
                csgn::SecretKey::from_seed(&mut [47; 32]),
                0,
                30 * DAY,
            )
            .await
            .unwrap(),
            retained: None,
            beacon: cbcn::Beacon::default(),
            observed_at: Some(100),
        }
    }

    async fn mutation_for(
        barrier: Arc<Barrier>,
        instance: &Arc<()>,
        sdk: Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
    ) -> WalletMutation {
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        WalletMutation {
            barrier,
            instance: Arc::downgrade(instance),
            sdk,
            _guard: gate.lock_owned().await,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bind_pins_the_first_sdk_and_refuses_a_different_owner() {
        let barrier = Barrier::new();
        let (_first_dir, first) = passkeys().await;
        let (_second_dir, second) = passkeys().await;
        assert!(barrier.bind(&first).is_ok());
        assert!(barrier.bind(&first).is_ok());
        assert!(matches!(
            barrier.bind(&second),
            Err(crate::Error::KeyMismatch)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn same_accepts_the_identical_owner() {
        let (_dir, sdk) = passkeys().await;
        let instance = Arc::new(());
        let barrier = Arc::new(Barrier::new());
        let mutation = mutation_for(barrier.clone(), &instance, sdk.clone()).await;
        let wallet = wallet_with(barrier, &instance, sdk.clone()).await;
        assert!(mutation.same(&wallet).is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn same_refuses_a_wallet_on_a_different_barrier() {
        let (_dir, sdk) = passkeys().await;
        let instance = Arc::new(());
        let mutation = mutation_for(Arc::new(Barrier::new()), &instance, sdk.clone()).await;
        let wallet = wallet_with(Arc::new(Barrier::new()), &instance, sdk.clone()).await;
        assert!(matches!(
            mutation.same(&wallet),
            Err(crate::Error::KeyMismatch)
        ));
    }
}
