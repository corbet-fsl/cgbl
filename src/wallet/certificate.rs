//! Original authenticated Keyhole certificate with an exact global account fence.
use super::*;
use crate::{
    Account, Subject,
    storage::{Key, ReadSet},
};
use std::time::{Duration, Instant};

/// Original wallet certificate bytes and the actual final owner clock floor.
/// No construction, cloning or serialization can manufacture this observation.
pub struct WalletPasskeyCertificate {
    bytes: Vec<u8>,
    checked_at: u64,
}
impl WalletPasskeyCertificate {
    /// Original COSE bytes, not current membership by themselves.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Actual completed current-owner observation; never a caller timestamp.
    pub fn checked_at(&self) -> u64 {
        self.checked_at
    }
    /// Consume only the signed bytes after carrying the checked floor onward.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl std::fmt::Debug for WalletPasskeyCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalletPasskeyCertificate([redacted])")
    }
}

struct Registered {
    read: ReadSet,
    subject: Subject,
    timing: Timing,
}

pub(super) struct Timing {
    began: Instant,
    lifetime: Duration,
    expires: u64,
    observed_at: u64,
}
impl Timing {
    pub(super) fn new(now: u64, expires: u64) -> Result<Self> {
        crate::time(now)?;
        if now >= expires {
            return Err(Error::InvalidTime);
        }
        Ok(Self {
            began: Instant::now(),
            lifetime: Duration::from_secs(expires - now),
            expires,
            observed_at: now,
        })
    }
    pub(super) fn sample<S: Store, K: csgn::Store>(
        &mut self,
        wallet: &mut Wallet<S, K>,
        now: u64,
    ) -> Result<()> {
        wallet.require_live()?;
        if now < self.observed_at
            || now >= self.expires
            || self.began.elapsed() >= self.lifetime
            || crate::time(now).is_err()
        {
            wallet.retained = None;
            wallet.observed_at = None;
            return Err(Error::InvalidTime);
        }
        self.observed_at = now;
        Ok(())
    }
}

impl<S: Store, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    pub(super) async fn wallet_account(&self, subject: &Subject, now: u64) -> Result<ReadSet> {
        let key = Key::new("account", subject.as_str());
        let read = self.read(vec![key.clone()]).await?;
        let account: Account = read
            .records
            .get(&key)
            .map(|record| serde_json::from_slice(&record.value).map_err(|_| Error::Encoding))
            .transpose()?
            .unwrap_or_default();
        account.eligible()?;
        Ok(read)
    }
    /// Sign only the actual current authenticated key in the same isolated wallet
    /// owner. The host retains its original Auth session/mutation guard across
    /// this whole call, supplies that grant's exclusive expiry, and rechecks the
    /// exact grant/current key under the wallet policy lock before HTTP release.
    /// No passport, community pseudonym, root or generic signing access results.
    pub async fn wallet_passkey_certificate<W: csgn::Store>(
        &self,
        wallet: &mut Wallet<S, W>,
        authentication: &ckyh::Authentication,
        expires: u64,
        clock: &impl Fn() -> u64,
    ) -> Result<WalletPasskeyCertificate> {
        let instance = wallet.instance.upgrade().ok_or(Error::Storage)?;
        if !std::sync::Arc::ptr_eq(&instance, &self.wallet_instance)
            || authentication.community() != "wallet"
        {
            return Err(Error::KeyMismatch);
        }
        let now = clock();
        wallet.sample(now)?;
        let mut timing = Timing::new(now, expires).inspect_err(|_| wallet.observed_at = None)?;
        wallet.trust_feed(now).await?;
        timing.sample(wallet, clock())?;
        wallet.key_ring()?;
        let _sdk = wallet.capture_sdk().await?;
        timing.sample(wallet, clock())?;
        // The exact writer is unavailable throughout every owner/signing await.
        // Refusal or cancellation cannot leave a usable cached acceptance.
        let retained = wallet.current().await?;
        timing.sample(wallet, clock())?;
        let subject = Subject::new(authentication.member().to_string())?;
        let read = self.wallet_account(&subject, now).await?;
        let mut registered = Registered {
            read,
            subject,
            timing,
        };
        let observed = clock();
        registered.timing.sample(wallet, observed)?;
        let keys = wallet.passkeys.clone();
        let auth = authentication.clone();
        let certificate =
            tokio::task::spawn_blocking(move || keys.wallet_registration_certificate(&auth))
                .await
                .map_err(|_| Error::Storage)?
                .map_err(|_| Error::Signature)?;
        registered.timing.sample(wallet, clock())?;
        let bytes = certificate
            .sign(
                &mut wallet.signer,
                registered.timing.observed_at / 86_400 * 86_400,
            )
            .await
            .map_err(|_| Error::Signature)?;
        registered.timing.sample(wallet, clock())?;
        let keys = wallet.passkeys.clone();
        let auth = authentication.clone();
        tokio::task::spawn_blocking(move || keys.public_credential(&auth))
            .await
            .map_err(|_| Error::Storage)?
            .map_err(|_| Error::Signature)?;
        registered.timing.sample(wallet, clock())?;
        let current = self
            .wallet_account(&registered.subject, registered.timing.observed_at)
            .await?;
        if current.revisions != registered.read.revisions {
            return Err(Error::Conflict);
        }
        // The service still retains the original Auth and Global mutation locks
        // and rechecks its exact grant/current key before the final HTTP guard.
        // Neither this observation nor a local lock freezes remote writers.
        let completed = clock();
        registered.timing.sample(wallet, completed)?;
        let ring = wallet.signer.key_ring().map_err(|_| Error::Signature)?;
        if ring.to_cbor() != retained.state.key_ring {
            return Err(Error::KeyMismatch);
        }
        ckyh::certificate::verify(ring, &bytes, registered.subject.as_str(), completed)
            .map_err(|_| Error::Signature)?;
        wallet.observed_at = Some(completed);
        wallet.retained = Some(retained);
        Ok(WalletPasskeyCertificate {
            bytes,
            checked_at: completed,
        })
    }
}
