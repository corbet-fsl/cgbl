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
