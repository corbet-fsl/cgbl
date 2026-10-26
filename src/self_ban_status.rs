//! Exact own-account receipt lookup; authentication belongs to the trusted host.
use crate::{
    Account, Burn, Global, PermanentReason, Result, Subject,
    storage::{Key, Store},
};

impl<S: Store, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    /// Read only whether an exact subject has a durable permanent self-ban.
    /// The host must derive this subject from a genuine original wallet grant.
    /// A wallet may exist before its first successful gate/Account record; only
    /// that authenticated original wallet permits interpreting absence as false.
    /// This is not eligibility, a block list or authority to return.
    pub async fn self_ban_status(&self, subject: &Subject) -> Result<bool> {
        let key = Key::new("account", subject.as_str());
        let read = self.read(vec![key.clone()]).await?;
        let account: Option<Account> = read
            .records
            .get(&key)
            .map(|record| serde_json::from_slice(&record.value).map_err(|_| crate::Error::Encoding))
            .transpose()?;
        Ok(account
            .is_some_and(|account| account.burn == Some(Burn::Permanent(PermanentReason::SelfBan))))
    }
}
