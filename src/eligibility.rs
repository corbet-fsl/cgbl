//! Read-only original account suspension check for a trusted wallet host.
use crate::{
    Account, Error, Global, Result, Subject,
    storage::{Key, Store},
};

impl<S: Store, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    /// Check original Account eligibility without gates, challenges or mutation.
    /// The host derives the subject from genuine current wallet authentication.
    /// Absence before the first gate is an eligible empty account observation;
    /// it creates no account, facts, passport, or continuing authority lease.
    /// Return the exact trusted post-read observation for the host's next floor.
    pub async fn check_eligibility(
        &self,
        subject: &Subject,
        floor: u64,
        clock: &impl Fn() -> u64,
    ) -> Result<u64> {
        let observed = clock();
        if observed < floor {
            return Err(Error::InvalidTime);
        }
        crate::time(observed)?;
        let key = Key::new("account", subject.as_str());
        let read = self.read(vec![key.clone()]).await?;
        let now = clock();
        if now < observed {
            return Err(Error::InvalidTime);
        }
        crate::time(now)?;
        let account: Account = read
            .records
            .get(&key)
            .map(|record| serde_json::from_slice(&record.value).map_err(|_| Error::Encoding))
            .transpose()?
            .unwrap_or_default();
        account.eligible(now)?;
        Ok(now)
    }
}
