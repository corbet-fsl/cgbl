//! Read-only domain authorization before a potentially billable contact operation.
use super::ContactBinding;
use crate::{
    Account, CheckId, Error, Global, Result, State, Subject,
    storage::{Key, Store},
};

/// Produced from an authenticated stored policy and the subject's current
/// suspension. This is not a reservation or an engine-atomic currentness lease.
pub struct ContactAuthorization {
    binding: ContactBinding,
    fact_expires_at: u64,
    epoch: u64,
    policy_revision: u64,
    observed_at: u64,
}
impl ContactAuthorization {
    /// Exact sealed subject/check/gate/provider binding observed by the owner.
    pub fn binding(&self) -> &ContactBinding {
        &self.binding
    }
    /// Exclusive expiry from the actual configured policy cohort.
    pub fn fact_expires_at(&self) -> u64 {
        self.fact_expires_at
    }
    /// Original global revocation epoch observed with the stored policy.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Original enabled policy revision observed before dispatch.
    pub fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    /// Exact trusted post-read time to retain as the next host clock floor.
    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }
}

impl<S: Store, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    /// Authenticate exact gate/provider enablement, live policy and subject
    /// eligibility before preparation/dispatch. Samples a trusted caller clock
    /// after awaited storage and refuses rollback. No provider I/O or mutation.
    pub async fn authorize_contact(
        &self,
        gate: &str,
        provider: &str,
        subject: &Subject,
        check: &CheckId,
        clock: &impl Fn() -> u64,
    ) -> Result<ContactAuthorization> {
        let observed = clock();
        crate::time(observed)?;
        let account_key = Key::new("account", subject.as_str());
        let read = self.read(vec![account_key.clone()]).await?;
        let now = clock();
        if now < observed {
            return Err(Error::InvalidTime);
        }
        crate::time(now)?;
        let state: State = read
            .records
            .get(&Key::new("meta", "state"))
            .map(|record| serde_json::from_slice(&record.value).map_err(|_| Error::Encoding))
            .transpose()?
            .ok_or(Error::NoPolicy)?;
        if state.policy.shared_expiry < now {
            return Err(Error::Policy);
        }
        if !state
            .policy
            .gates
            .iter()
            .any(|policy| policy.gate == gate && policy.provider == provider)
        {
            return Err(Error::GateDisabled);
        }
        let account: Account = read
            .records
            .get(&account_key)
            .map(|record| serde_json::from_slice(&record.value).map_err(|_| Error::Encoding))
            .transpose()?
            .unwrap_or_default();
        account.eligible()?;
        let fact_expires_at = state
            .policy
            .shared_expiry
            .checked_add(1)
            .ok_or(Error::InvalidTime)?;
        Ok(ContactAuthorization {
            binding: self.contact_binding(gate, provider, subject, check)?,
            fact_expires_at,
            epoch: state.epoch()?,
            policy_revision: state.policy.revision,
            observed_at: now,
        })
    }
}
