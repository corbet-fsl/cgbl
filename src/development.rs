//! Synthetic gate, compiled only with `development-gate` and refused in production.
use crate::{GateEvidence, GlobalGate, Result, Subject};
use zeroize::Zeroizing;
/// Always-passing gate for isolated development. Its input is a synthetic
/// uniqueness token, not a phone number or real identity attribute.
pub struct DevelopmentGate {
    valid_until: u64,
}
impl DevelopmentGate {
    /// Set the test provider's evidence expiry.
    pub fn new(valid_until: u64) -> Self {
        Self { valid_until }
    }
}
impl GlobalGate for DevelopmentGate {
    fn id(&self) -> &str {
        "development"
    }
    fn provider(&self) -> &str {
        "cgbl.test"
    }
    fn development_only(&self) -> bool {
        true
    }
    async fn verify(
        &self,
        _: &crate::CheckId,
        _: &Subject,
        input: &[u8],
        _: u64,
    ) -> Result<GateEvidence> {
        Ok(GateEvidence {
            valid_until: self.valid_until,
            uniqueness: Some(Zeroizing::new(input.to_vec())),
        })
    }
}

// Focused kill tests for the development.rs survivors in the mut138 brief.
// The module only compiles with `development-gate` (debug), so run with
// `cargo test -p cgbl --features development-gate development::`.

#[cfg(test)]
mod tests {
    use super::*;
    use cpsd::rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn development_gate_advertises_the_synthetic_identity() {
        // Kills 17:9 `-> ""` and `-> "xyzzy"`, 20:9 `-> ""` and
        // `-> "xyzzy"`, and 23:9 `-> false`.
        let gate = DevelopmentGate::new(123);
        assert_eq!(gate.id(), "development");
        assert_eq!(gate.provider(), "cgbl.test");
        assert!(gate.development_only());
    }

    #[tokio::test]
    async fn development_verify_returns_the_configured_expiry_and_echoes_the_input() {
        // The 32:9 `Ok(Default::default())` mutant does not compile
        // (GateEvidence has no Default impl); this pins the real contract:
        // the configured expiry and the exact input as uniqueness.
        let gate = DevelopmentGate::new(999);
        let subject = Subject::new("dev-subject").unwrap();
        let mut rng = StdRng::seed_from_u64(7);
        let check = crate::CheckId::generate(&mut rng);
        let evidence = gate.verify(&check, &subject, b"token", 100).await.unwrap();
        assert_eq!(evidence.valid_until, 999);
        let uniqueness = evidence
            .uniqueness
            .expect("development gate echoes its input");
        assert_eq!(&uniqueness[..], &b"token"[..]);
    }
}
