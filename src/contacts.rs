//! Prepared phone/mailbox handoffs with no provider I/O or registration claim.
//!
//! The trusted host selects the adapter and stable comparison key before the
//! ceremony. Leaf facts retain an opaque binding, not provider/scope metadata;
//! the host must use the context prepared here with that selected adapter.
//! Identifier control establishes comparison within the leaf's identity domain,
//! never one-human uniqueness. Policy and persistence remain with the caller.
use crate::{
    CheckId, Error, FingerprintKey, GateEvidence, GlobalGate, Result, Subject, validate_id,
};
use zeroize::Zeroizing;

mod authorization;
pub use authorization::ContactAuthorization;

/// The actual leaf identity scheme whose stable comparison key is committed.
#[derive(Clone, Copy)]
pub enum ContactDomain {
    Phone,
    Mailbox,
}
impl ContactDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Phone => "cphn.identity.v1:phone.e164",
            Self::Mailbox => "cmbx.identity.v1:mailbox.address",
        }
    }
    pub fn gate(self) -> &'static str {
        match self {
            Self::Phone => "cphn",
            Self::Mailbox => "cmbx",
        }
    }
}
/// Reuse the existing maintained HMAC engine for an opaque key commitment.
/// It binds the exact key, configured comparison scope and fixed leaf identity
/// domain. Pass only a temporary key copy: construction wipes this input.
/// Caller-owned atomic persistence must refuse changed commitments, including
/// conservative migration when older comparison identities lack a commitment.
pub fn comparison_key_binding(
    scope: &str,
    domain: ContactDomain,
    key_copy: &mut [u8; 32],
) -> Result<String> {
    let key = FingerprintKey::from_bytes(key_copy);
    crate::validate_id(scope)?;
    Ok(key.fingerprint(
        scope,
        "contact-comparison-key-binding",
        domain.as_str().as_bytes(),
    ))
}

/// Sealed host context derived by [`crate::Global::contact_binding`] before a
/// leaf ceremony. Never construct expected bindings from a returned fact.
///
/// This is not a member credential and has no deserialization boundary.
/// ```compile_fail
/// let _: cgbl::contacts::ContactBinding = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
pub struct ContactBinding {
    scope: String,
    gate: String,
    provider: String,
    subject: Subject,
    check: CheckId,
    binding: [u8; 32],
}
impl ContactBinding {
    pub(crate) fn derive(
        key: &FingerprintKey,
        scope: &str,
        gate: &str,
        provider: &str,
        subject: &Subject,
        check: &CheckId,
    ) -> Result<Self> {
        for id in [scope, gate, provider] {
            validate_id(id)?;
        }
        check.validate()?;
        let check = key.check_id(scope, subject, gate, provider, check);
        let mut binding = [0; 32];
        for (index, byte) in binding.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&check.as_str()[2 * index..2 * index + 2], 16)
                .expect("the existing keyed check encoding is lowercase hexadecimal");
        }
        Ok(Self {
            scope: scope.into(),
            gate: gate.into(),
            provider: provider.into(),
            subject: subject.clone(),
            check,
            binding,
        })
    }

    /// Prepare the real phone context with this exact global scope and binding.
    /// Keep the comparison key stable across enabled phone providers. The host
    /// must select the configured adapter before using this context, and must not
    /// replace its scope/binding. No dispatch or cost authorization occurs here.
    pub fn phone_context(
        &self,
        operation: [u8; 32],
        identity_key: Zeroizing<[u8; 32]>,
        expires_at: u64,
    ) -> Result<cphn::Context> {
        crate::time(expires_at.checked_sub(1).ok_or(Error::InvalidTime)?)?;
        Ok(cphn::Context {
            binding: self.binding,
            operation,
            scope: self.scope.as_bytes().to_vec(),
            identity_key,
            expires_at,
            include_upstream: false,
        })
    }

    /// Prepare the real mailbox context with this exact global scope and binding.
    /// Keep the comparison key stable across enabled mailbox providers. Adapter
    /// selection and any explicit rich-output request remain trusted host inputs.
    pub fn mailbox_context(
        &self,
        operation: [u8; 32],
        identity_key: Zeroizing<[u8; 32]>,
        expires_at: u64,
    ) -> Result<cmbx::Context> {
        crate::time(expires_at.checked_sub(1).ok_or(Error::InvalidTime)?)?;
        Ok(cmbx::Context {
            binding: self.binding,
            operation,
            scope: self.scope.as_bytes().to_vec(),
            identity_key,
            expires_at,
            include_upstream: false,
        })
    }

    fn verify(&self, check: &CheckId, subject: &Subject, input: &[u8]) -> Result<()> {
        if check != &self.check || subject != &self.subject || input != self.binding {
            return Err(Error::Gates);
        }
        Ok(())
    }
}
impl std::fmt::Debug for ContactBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ContactBinding([redacted])")
    }
}

/// Genuine phone-control fact prepared for one exact authenticated global check.
/// Retrying verification performs no provider I/O and cannot send another code.
/// Simulation cannot cross the typed handoff.
/// ```compile_fail
/// fn promote(binding: cgbl::contacts::ContactBinding, fact: cphn::Simulated) {
///     cgbl::contacts::PhoneGate::new(binding, fact);
/// }
/// ```
pub struct PhoneGate {
    context: ContactBinding,
    fact: cphn::Verified,
}
impl PhoneGate {
    /// Consume a real leaf fact, checked against the independently prepared
    /// expected binding. The selected adapter/comparison context is host-trusted.
    pub fn new(context: ContactBinding, fact: cphn::Verified) -> Result<Self> {
        if fact.binding() != &context.binding {
            return Err(Error::Gates);
        }
        Ok(Self { context, fact })
    }
    /// Opaque retry input. No number, provider body or comparison identity.
    pub fn input(&self) -> &[u8] {
        &self.context.binding
    }
}
impl GlobalGate for PhoneGate {
    fn id(&self) -> &str {
        &self.context.gate
    }
    fn provider(&self) -> &str {
        &self.context.provider
    }
    fn development_only(&self) -> bool {
        false
    }
    async fn verify(
        &self,
        check: &CheckId,
        subject: &Subject,
        input: &[u8],
        now: u64,
    ) -> Result<GateEvidence> {
        self.context.verify(check, subject, input)?;
        evidence(
            b"phone.e164\0",
            self.fact.identity().as_bytes(),
            self.fact.expires_at(),
            now,
        )
    }
}
impl std::fmt::Debug for PhoneGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PhoneGate([redacted])")
    }
}

/// Genuine mailbox-control fact prepared for one exact authenticated global check.
/// Mailbox matching preserves local-part case and aliases, as the leaf specifies.
/// ```compile_fail
/// fn promote(binding: cgbl::contacts::ContactBinding, fact: cmbx::Simulated) {
///     cgbl::contacts::MailboxGate::new(binding, fact);
/// }
/// ```
pub struct MailboxGate {
    context: ContactBinding,
    fact: cmbx::Verified,
}
impl MailboxGate {
    /// Consume a real leaf fact after checking the pre-ceremony binding.
    pub fn new(context: ContactBinding, fact: cmbx::Verified) -> Result<Self> {
        if fact.binding() != &context.binding {
            return Err(Error::Gates);
        }
        Ok(Self { context, fact })
    }
    /// Opaque retry input for the existing global check machinery.
    pub fn input(&self) -> &[u8] {
        &self.context.binding
    }
}
impl GlobalGate for MailboxGate {
    fn id(&self) -> &str {
        &self.context.gate
    }
    fn provider(&self) -> &str {
        &self.context.provider
    }
    fn development_only(&self) -> bool {
        false
    }
    async fn verify(
        &self,
        check: &CheckId,
        subject: &Subject,
        input: &[u8],
        now: u64,
    ) -> Result<GateEvidence> {
        self.context.verify(check, subject, input)?;
        evidence(
            b"mailbox.address\0",
            self.fact.identity().as_bytes(),
            self.fact.expires_at(),
            now,
        )
    }
}
impl std::fmt::Debug for MailboxGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MailboxGate([redacted])")
    }
}

fn evidence(domain: &[u8], identity: &[u8; 32], expires_at: u64, now: u64) -> Result<GateEvidence> {
    if now >= expires_at {
        return Err(Error::Gates);
    }
    // Leaf validity is exclusive. cgbl validity is inclusive and rounded down;
    // subtract first so no leaf evidence is extended by the global projection.
    let valid_until = expires_at - 1;
    let mut canonical = Zeroizing::new(Vec::with_capacity(domain.len() + identity.len()));
    canonical.extend_from_slice(domain);
    canonical.extend_from_slice(identity);
    Ok(GateEvidence {
        valid_until,
        uniqueness: Some(canonical),
    })
}

#[cfg(test)]
#[path = "tests/contacts.rs"]
mod tests;
