//! Real signed policy authorizes contact costs before any external I/O.
use cgbl::{
    storage::{Key, MemoryStore, Store},
    *,
};
use cpsd::{
    GateId, KeyId,
    rand::{SeedableRng, rngs::StdRng},
};
use std::sync::atomic::{AtomicUsize, Ordering};
const COHORT: u64 = 5 * 86400;
type Facade = Global<MemoryStore, csgn::MemoryStore, cpsd::MemoryStore>;
async fn service() -> (Facade, MemoryStore) {
    let store = MemoryStore::new("global").unwrap();
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "cgbl:global",
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * 86400,
    )
    .await
    .unwrap();
    let issuer = cpsd::IssuerKey::generate(
        &mut StdRng::seed_from_u64(1),
        KeyId::new("contacts").unwrap(),
        vec![GateId::new("cphn").unwrap()],
    )
    .unwrap();
    let facade = Global::open(
        store.clone(),
        cpsd::MemoryStore::new(cpsd::CommunityId::new(b"global").unwrap(), 10).unwrap(),
        issuer,
        signer,
        FingerprintKey::from_bytes(&mut [9; 32]),
        Mode::Production,
        Limits {
            challenge_ttl: 60,
            pending_capacity: 10,
        },
    )
    .await
    .unwrap();
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "policy-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        0,
        30 * 86400,
    )
    .await
    .unwrap();
    let policy = Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        shared_expiry: COHORT,
        gates: vec![GatePolicy {
            gate: "cphn".into(),
            provider: "twilio".into(),
            uniqueness: true,
        }],
    };
    let signed = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            0,
            COHORT + 86400,
        )
        .await
        .unwrap();
    facade
        .install_policy(&signed, authority.key_ring().unwrap(), 100)
        .await
        .unwrap();
    (facade, store)
}
#[tokio::test]
async fn enabled_pair_and_live_subject_receive_the_real_policy_cohort_without_creating_an_account()
{
    let (facade, store) = service().await;
    let subject = Subject::new("alice").unwrap();
    let check = CheckId::generate(&mut StdRng::seed_from_u64(2));
    let authorization = facade
        .authorize_contact("cphn", "twilio", &subject, &check, &|| 100)
        .await
        .unwrap();
    assert_eq!(authorization.fact_expires_at(), COHORT + 1);
    assert_eq!(authorization.epoch(), 1);
    assert_eq!(authorization.policy_revision(), 1);
    let context = authorization
        .binding()
        .phone_context(
            [1; 32],
            zeroize::Zeroizing::new([8; 32]),
            authorization.fact_expires_at(),
        )
        .unwrap();
    assert_eq!(context.expires_at, COHORT + 1);
    assert!(!context.include_upstream);
    assert!(
        store
            .read(&[Key::new("account", subject.as_str())])
            .await
            .unwrap()
            .records
            .is_empty()
    );
    for (gate, provider) in [("cmbx", "twilio"), ("cphn", "disabled")] {
        assert!(matches!(
            facade
                .authorize_contact(gate, provider, &subject, &check, &|| 100)
                .await,
            Err(Error::GateDisabled)
        ));
    }
}
#[tokio::test]
async fn terminal_pre_gate_self_ban_refuses_read_only_contact_authorization() {
    let (facade, _) = service().await;
    let subject = Subject::new("alice").unwrap();
    let check = CheckId::generate(&mut StdRng::seed_from_u64(2));
    facade
        .suspend(
            &subject,
            Suspension::Permanent(PermanentReason::SelfBan),
            100,
        )
        .await
        .unwrap();
    assert!(matches!(
        facade
            .authorize_contact("cphn", "twilio", &subject, &check, &|| 100)
            .await,
        Err(Error::Suspended)
    ));
    let other = Subject::new("bob").unwrap();
    assert!(
        facade
            .authorize_contact("cphn", "twilio", &other, &check, &|| 100)
            .await
            .is_ok()
    );
}
#[tokio::test]
async fn policy_expiry_and_clock_rollback_are_rechecked_after_storage() {
    let (facade, _) = service().await;
    let subject = Subject::new("alice").unwrap();
    let check = CheckId::generate(&mut StdRng::seed_from_u64(2));
    assert!(
        facade
            .authorize_contact("cphn", "twilio", &subject, &check, &|| COHORT)
            .await
            .is_ok()
    );
    for (later, expected_policy) in [(COHORT + 1, true), (99, false)] {
        let calls = AtomicUsize::new(0);
        let clock = || {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                100
            } else {
                later
            }
        };
        let result = facade
            .authorize_contact("cphn", "twilio", &subject, &check, &clock)
            .await;
        if expected_policy {
            assert!(matches!(result, Err(Error::Policy)));
        } else {
            assert!(matches!(result, Err(Error::InvalidTime)));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

#[test]
fn comparison_key_commitments_bind_the_exact_scope_and_identity_domain_and_wipe_input() {
    use cgbl::contacts::{ContactDomain, comparison_key_binding};
    let mut key = [8; 32];
    let phone = comparison_key_binding("global", ContactDomain::Phone, &mut key).unwrap();
    assert_eq!(key, [0; 32]);
    let mut key = [8; 32];
    assert_eq!(
        comparison_key_binding("global", ContactDomain::Phone, &mut key).unwrap(),
        phone
    );
    let mut key = [8; 32];
    assert_ne!(
        comparison_key_binding("global", ContactDomain::Mailbox, &mut key).unwrap(),
        phone
    );
    let mut key = [8; 32];
    assert_ne!(
        comparison_key_binding("other", ContactDomain::Phone, &mut key).unwrap(),
        phone
    );
    let mut key = [9; 32];
    assert_ne!(
        comparison_key_binding("global", ContactDomain::Phone, &mut key).unwrap(),
        phone
    );
    let mut key = [8; 32];
    assert!(comparison_key_binding("", ContactDomain::Phone, &mut key).is_err());
    assert_eq!(key, [0; 32]);
}
