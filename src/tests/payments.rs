use super::*;
use cpmt::payments as p;
use std::sync::Arc;

struct Provider;
#[async_trait::async_trait]
impl p::Adapter for Provider {
    fn capabilities(&self) -> p::Capabilities {
        p::Capabilities {
            id: "local".into(),
            operations: vec!["collect".into()],
        }
    }
    async fn execute(
        &self,
        _: &p::Instruction,
        _: &str,
        _: Option<&p::Private>,
    ) -> p::Result<p::Observation> {
        Ok(p::Observation {
            claim: Some(p::Private::new(b"private-receipt".to_vec())),
            ..p::Observation::fact(p::State::Collected)
        })
    }
    async fn observe(&self, _: &str, _: Option<&p::Private>) -> p::Result<p::Observation> {
        Err(p::Error::Unsupported)
    }
}

async fn gate() -> PaymentGate {
    let mut payments = p::Payments::new(p::MemoryJournal::default(), [7; 32]).unwrap();
    payments.register(Arc::new(Provider)).unwrap();
    let request = p::Instruction {
        id: [1; 32],
        parent: None,
        adapter: "local".into(),
        operation: "collect".into(),
        binding: p::Binding {
            scope: "global".into(),
            subject: "alice".into(),
            action: "admit".into(),
        },
        expires_at: 2000,
        terms: p::Private::new(vec![]),
        evidence: p::Private::new(b"private-wallet".to_vec()),
    };
    let evidence = payments
        .execute(&request, 1100)
        .await
        .unwrap()
        .outcome
        .evidence(&request.binding, p::State::Collected, 1100, 86401)
        .unwrap();
    PaymentGate::new(
        "crpt".into(),
        "local".into(),
        "global".into(),
        "admit".into(),
        evidence,
    )
    .unwrap()
}

#[tokio::test]
async fn global_payment_handoff_binds_context_and_never_claims_person_uniqueness() {
    let mut gate = gate().await;
    let check = CheckId("a".repeat(64));
    let subject = Subject::new("alice").unwrap();
    assert_eq!(gate.id(), "crpt");
    assert_eq!(gate.provider(), "local");
    assert!(!gate.development_only());
    let evidence = gate
        .verify(&check, &subject, gate.input(), 1100)
        .await
        .unwrap();
    assert_eq!(evidence.valid_until, 86400);
    assert!(evidence.uniqueness.is_none());
    for _ in 0..2 {
        assert_eq!(
            gate.verify(&check, &subject, gate.input(), 1100)
                .await
                .unwrap()
                .valid_until,
            86400
        );
    }
    assert!(
        gate.verify(&check, &subject, b"changed", 1100)
            .await
            .is_err()
    );
    assert!(
        gate.verify(&check, &Subject::new("bob").unwrap(), gate.input(), 1100)
            .await
            .is_err()
    );
    assert!(
        gate.verify(&check, &subject, gate.input(), 86401)
            .await
            .is_err()
    );
    gate.provider = "other".into();
    assert!(
        gate.verify(&check, &subject, gate.input(), 1100)
            .await
            .is_err()
    );
    gate.provider = "local".into();
    gate.action = "other".into();
    assert!(
        gate.verify(&check, &subject, gate.input(), 1100)
            .await
            .is_err()
    );
    gate.action = "admit".into();
    gate.scope = "other".into();
    assert!(
        gate.verify(&check, &subject, gate.input(), 1100)
            .await
            .is_err()
    );
    let valid = self::gate().await;
    assert!(
        PaymentGate::new(
            "".into(),
            "local".into(),
            "global".into(),
            "admit".into(),
            valid.evidence
        )
        .is_err()
    );
}
