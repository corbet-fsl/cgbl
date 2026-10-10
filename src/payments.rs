//! In-process payment handoff. A payment is not proof of person uniqueness.
use crate::{CheckId, Error, GateEvidence, GlobalGate, Result, Subject, validate_id};
use cpmt::payments::{Binding, Evidence};

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
        if input != self.input() {
            return Err(Error::Gates);
        }
        let binding = Binding {
            scope: self.scope.clone(),
            subject: subject.as_str().into(),
            action: self.action.clone(),
        };
        let (provider, until) = self
            .evidence
            .in_context(&binding, now)
            .map_err(|_| Error::Gates)?;
        if provider != self.provider {
            return Err(Error::Gates);
        }
        // cgbl's existing evidence boundary is inclusive; cpmt's is exclusive.
        // Subtract before cgbl rounds to days so expiry can never be extended.
        Ok(GateEvidence {
            valid_until: until.checked_sub(1).ok_or(Error::InvalidTime)?,
            uniqueness: None,
        })
    }
}

#[cfg(test)]
#[path = "tests/payments.rs"]
mod tests;
