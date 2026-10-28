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
    pub(super) observed_at: u64,
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
    pub(super) async fn wallet_account(&self, subject: &Subject) -> Result<ReadSet> {
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
        let read = self.wallet_account(&subject).await?;
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
        let current = self.wallet_account(&registered.subject).await?;
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

// Focused kill tests for the certificate.rs survivors in the mut138 brief.
//
// - `into_bytes` returns the exact signed bytes (kills 26:9 `-> vec![]`,
//   `-> vec![0]` and `-> vec![1]`).
// - `Debug` is the constant redaction (kills 31:9 `-> Ok(Default::default())`).
// - `Timing::sample` refuses a backwards clock, an expired window, a spent
//   lifetime and an invalid clock, and accepts a forward step: each
//   single-arm test kills the matching `||` -> `&&` mutant at
//   67:13/68:13/69:13 (and the whole-body `-> Ok(())` at 65:9), while the
//   forward test kills `<` -> `>` at 66:16.
// - The day-floor factor of `wallet_passkey_certificate` (143:56 `*` -> `/`)
//   is pinned by the `certificate_issued_time_is_the_day_floor` integration
//   test in tests/mut138.rs (it needs a live wallet + ceremony).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStore;
    use std::sync::Arc;

    const T_NOW: u64 = 1_000_000;
    const T_DAY: u64 = 86_400;

    #[test]
    fn into_bytes_returns_the_exact_signed_bytes() {
        let bytes = vec![9u8, 8, 7, 6, 5];
        let certificate = WalletPasskeyCertificate {
            bytes: bytes.clone(),
            checked_at: 42,
        };
        assert_eq!(certificate.into_bytes(), bytes);
    }

    #[test]
    fn debug_is_a_constant_redaction() {
        let certificate = WalletPasskeyCertificate {
            bytes: vec![1, 2, 3],
            checked_at: 7,
        };
        let rendered = format!("{certificate:?}");
        assert_eq!(rendered, "WalletPasskeyCertificate([redacted])");
    }

    async fn timing_wallet() -> (
        tempfile::TempDir,
        Wallet<MemoryStore, csgn::MemoryStore>,
        Arc<()>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let url = ckyh::Url::from_file_path(directory.path().join("wallet.db")).unwrap();
        let db = crlt::Db::open(crlt::Config::new(url.as_str(), ""))
            .await
            .unwrap();
        db.migrate(&[crlt::Migration::new(1, "passkeys", ckyh::LIBSQL_SCHEMA)])
            .await
            .unwrap();
        let passkeys = Arc::new(
            ckyh::Passkeys::new(
                ckyh::LibsqlStore::new(&db, "wallet", tokio::runtime::Handle::current()).unwrap(),
                "wallet",
                "wallet.example.test",
                &[ckyh::Url::parse("https://vault.wallet.example.test").unwrap()],
            )
            .unwrap(),
        );
        let instance = Arc::new(());
        let wallet = Wallet {
            barrier: Arc::new(crate::wallet::barrier::Barrier::new()),
            pending: Vec::new(),
            publication_reads: None,
            passkeys,
            instance: Arc::downgrade(&instance),
            store: MemoryStore::new("timing-test").unwrap(),
            signer: csgn::PersistentSigner::create(
                csgn::MemoryStore::default(),
                "wallet",
                csgn::SecretKey::from_seed(&mut [47; 32]),
                0,
                30 * T_DAY,
            )
            .await
            .unwrap(),
            retained: None,
            beacon: cbcn::Beacon::default(),
            observed_at: Some(T_NOW),
        };
        (directory, wallet, instance)
    }

    fn live_timing(observed_at: u64, expires: u64) -> Timing {
        Timing {
            began: Instant::now(),
            lifetime: Duration::from_secs(3600),
            expires,
            observed_at,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sample_accepts_a_forward_clock_inside_the_window() {
        let (_dir, mut wallet, _instance) = timing_wallet().await;
        let mut timing = live_timing(T_NOW, T_NOW + 3600);
        assert!(timing.sample(&mut wallet, T_NOW).is_ok());
        assert_eq!(timing.observed_at, T_NOW);
        assert!(wallet.observed_at.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sample_refuses_a_backwards_clock_and_fences_the_wallet() {
        let (_dir, mut wallet, _instance) = timing_wallet().await;
        let mut timing = live_timing(T_NOW, T_NOW + 3600);
        assert!(matches!(
            timing.sample(&mut wallet, T_NOW - 1),
            Err(crate::Error::InvalidTime)
        ));
        assert!(wallet.observed_at.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sample_refuses_an_expired_window() {
        let (_dir, mut wallet, _instance) = timing_wallet().await;
        let mut timing = live_timing(T_NOW, T_NOW);
        assert!(matches!(
            timing.sample(&mut wallet, T_NOW),
            Err(crate::Error::InvalidTime)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sample_refuses_a_spent_lifetime() {
        let (_dir, mut wallet, _instance) = timing_wallet().await;
        let mut timing = Timing {
            began: Instant::now(),
            lifetime: Duration::ZERO,
            expires: T_NOW + 3600,
            observed_at: T_NOW,
        };
        assert!(matches!(
            timing.sample(&mut wallet, T_NOW),
            Err(crate::Error::InvalidTime)
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sample_refuses_an_invalid_clock() {
        let (_dir, mut wallet, _instance) = timing_wallet().await;
        let mut timing = live_timing(0, T_NOW + 3600);
        assert!(matches!(
            timing.sample(&mut wallet, 0),
            Err(crate::Error::InvalidTime)
        ));
    }
}
