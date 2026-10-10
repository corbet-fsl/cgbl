//! In-process payment handoff. A payment is not proof of person uniqueness.
use crate::{CheckId, Error, GateEvidence, GlobalGate, Result, Subject, validate_id};
use cpmt::payments::{Binding, Evidence};

/// Access at an exact application-defined level during its paid period.
/// Financial details remain inside the reusable payment library.
pub struct PaidAccessGate {
    gate: String,
    provider: String,
    scope: String,
    action: String,
    level: String,
    access: cpmt::access::PaidAccess,
}
impl PaidAccessGate {
    /// Configure the exact context and level; levels have no implicit ordering.
    pub fn new(
        gate: String,
        provider: String,
        scope: String,
        action: String,
        level: String,
        access: cpmt::access::PaidAccess,
    ) -> Result<Self> {
        for id in [&gate, &provider, &scope, &action, &level] {
            validate_id(id)?;
        }
        Ok(Self {
            gate,
            provider,
            scope,
            action,
            level,
            access,
        })
    }
    /// Opaque input used by the host's existing replay and retry handling.
    pub fn input(&self) -> &[u8] {
        self.access.evidence().claim()
    }
}
impl GlobalGate for PaidAccessGate {
    fn id(&self) -> &str {
        &self.gate
    }
    fn provider(&self) -> &str {
        &self.provider
    }
    fn development_only(&self) -> bool {
        false
    }
    async fn verify(
        &self,
        _: &CheckId,
        subject: &Subject,
        input: &[u8],
        now: u64,
    ) -> Result<GateEvidence> {
        let binding = Binding {
            scope: self.scope.clone(),
            subject: subject.as_str().into(),
            action: self.action.clone(),
        };
        let (level, _) = self
            .access
            .in_context(&binding, now)
            .map_err(|_| Error::Gates)?;
        if level != self.level {
            return Err(Error::Gates);
        }
        verify_payment(
            &self.provider,
            &self.scope,
            &self.action,
            self.access.evidence(),
            subject,
            input,
            now,
        )
    }
}

/// One verified payment fact supplied by the payment boundary for a global check.
/// This adapter performs no provider call and cannot cause a charge on retry.
pub struct PaymentGate {
    gate: String,
    provider: String,
    scope: String,
    action: String,
    evidence: Evidence,
}

impl PaymentGate {
    /// Configure the gate identity and exact expected scope/action.
    /// The evidence must come from the payment executor, never from deserialization.
    pub fn new(
        gate: String,
        provider: String,
        scope: String,
        action: String,
        evidence: Evidence,
    ) -> Result<Self> {
        for id in [&gate, &provider, &scope, &action] {
            validate_id(id)?;
        }
        Ok(Self {
            gate,
            provider,
            scope,
            action,
            evidence,
        })
    }
    /// Opaque input for `Global::run_gate`; its existing retry binding retains only
    /// a keyed digest. No wallet, payment ID or provider response crosses here.
    pub fn input(&self) -> &[u8] {
        self.evidence.claim()
    }
}

impl GlobalGate for PaymentGate {
    fn id(&self) -> &str {
        &self.gate
    }
    fn provider(&self) -> &str {
        &self.provider
    }
    fn development_only(&self) -> bool {
        false
    }
    async fn verify(
        &self,
        _check: &CheckId,
        subject: &Subject,
        input: &[u8],
        now: u64,
    ) -> Result<GateEvidence> {
        verify_payment(
            &self.provider,
            &self.scope,
            &self.action,
            &self.evidence,
            subject,
            input,
            now,
        )
    }
}

fn verify_payment(
    provider: &str,
    scope: &str,
    action: &str,
    evidence: &Evidence,
    subject: &Subject,
    input: &[u8],
    now: u64,
) -> Result<GateEvidence> {
    if input != evidence.claim() {
        return Err(Error::Gates);
    }
    let binding = Binding {
        scope: scope.into(),
        subject: subject.as_str().into(),
        action: action.into(),
    };
    let (actual_provider, until) = evidence
        .in_context(&binding, now)
        .map_err(|_| Error::Gates)?;
    if actual_provider != provider {
        return Err(Error::Gates);
    }
    // cgbl's existing evidence boundary is inclusive; cpmt's is exclusive.
    // Subtract before cgbl rounds to days so expiry can never be extended.
    Ok(GateEvidence {
        valid_until: until.checked_sub(1).ok_or(Error::InvalidTime)?,
        uniqueness: None,
    })
}

#[cfg(test)]
#[path = "tests/payments.rs"]
mod tests;
