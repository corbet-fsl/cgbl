use super::*;
use cpmt::payments as p;
use std::sync::Arc;

struct Provider;
impl p::Adapter for Provider {
    fn mode(&self) -> cpmt::cost::Mode {
        cpmt::cost::Mode::Production
    }
    fn max_input_bytes(&self) -> usize {
        16384
    }
    fn capabilities(&self) -> p::Capabilities {
        p::Capabilities {
            id: "local".into(),
            operations: vec!["collect".into()],
        }
    }
    async fn execute(
        &self,
        dispatch: &cpmt::cost::Dispatch<'_>,
        _: &str,
        _: Option<&p::Private>,
    ) -> p::Result<p::Observation> {
        dispatch.check("local", cpmt::cost::Mode::Production)?;
        Ok(p::Observation {
            satisfies_terms: true,
            claim: Some(p::Private::new(b"private-receipt".to_vec())),
            ..p::Observation::fact(p::State::Collected)
        })
    }
    async fn observe(
        &self,
        _: &cpmt::cost::Dispatch<'_>,
        _: Option<&p::Private>,
    ) -> p::Result<p::Observation> {
        Err(p::Error::Unsupported)
    }
}

async fn operation() -> (p::Payments<p::MemoryJournal>, p::Instruction, p::Outcome) {
    let mut payments =
        p::Payments::new(p::MemoryJournal::default(), [7; 32], Arc::new(|| 1100)).unwrap();
    payments.register(Arc::new(Provider)).unwrap();
    let request = p::Instruction {
        id: [1; 32],
        kind: p::Action::Execute,
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
    let outcome = payments
        .dispatch(&request, permit(&payments, &request), 1100)
        .await
        .unwrap()
        .outcome;
    (payments, request, outcome)
}
async fn gate() -> PaymentGate {
    let (_, request, outcome) = operation().await;
    let evidence = outcome
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

fn permit(
    payments: &p::Payments<p::MemoryJournal>,
    request: &p::Instruction,
) -> cpmt::cost::DispatchPermit<String> {
    use cpmt::cost::*;
    let amount = Amount {
        unit: Unit {
            code: "inert-fixture-fee".into(),
            scale: 0,
        },
        atoms: 0,
    };
    let quote = payments
        .preview(
            request,
            Price::Exact(amount.clone()),
            "inert fixture; no provider I/O".into(),
            2000,
        )
        .unwrap();
    Plan::new(
        vec![Offer {
            candidate: Candidate::new("local".into(), ["collect".to_string()]),
            quote,
        }],
        Config::new(["local".into()], ["collect".to_string()]),
        CostOrder::Configured,
        amount,
        1,
        Mode::Production,
        1100,
    )
    .unwrap()
    .start()
    .begin(1100)
    .unwrap()
}

async fn access() -> cpmt::access::PaidAccess {
    let (payments, instruction, outcome) = operation().await;
    payments
        .paid_access(
            &instruction,
            &outcome,
            cpmt::access::Request {
                level: "gold".into(),
                period: cpmt::access::Period {
                    start: 1100,
                    end: 86401,
                },
                requires: p::State::Collected,
            },
            1100,
        )
        .unwrap()
}
#[tokio::test]
async fn paid_access_requires_the_exact_level_and_current_period() {
    let check = CheckId("b".repeat(64));
    let subject = Subject::new("alice").unwrap();
    let mut gate = PaidAccessGate::new(
        "cpmt".into(),
        "local".into(),
        "global".into(),
        "admit".into(),
        "gold".into(),
        access().await,
    )
    .unwrap();
    assert_eq!(gate.id(), "cpmt");
    assert_eq!(gate.provider(), "local");
    assert!(!gate.development_only());
    let evidence = gate
        .verify(&check, &subject, gate.input(), 1100)
        .await
        .unwrap();
    assert_eq!(evidence.valid_until, 86400);
    assert!(evidence.uniqueness.is_none());
    for now in [1099, 86401] {
        assert!(
            gate.verify(&check, &subject, gate.input(), now)
                .await
                .is_err()
        );
    }
    assert!(gate.verify(&check, &subject, b"wrong", 1100).await.is_err());
    assert!(
        gate.verify(&check, &Subject::new("bob").unwrap(), gate.input(), 1100)
            .await
            .is_err()
    );
    gate.level = "platinum".into();
    assert!(
        gate.verify(&check, &subject, gate.input(), 1100)
            .await
            .is_err()
    );
    assert!(
        PaidAccessGate::new(
            "".into(),
            "local".into(),
            "global".into(),
            "admit".into(),
            "gold".into(),
            access().await
        )
        .is_err()
    );
}
