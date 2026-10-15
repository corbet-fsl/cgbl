//! Production-mode composition through real leaf adapters and blind issuance.
//! All transport responses, credentials and price sources below are inert fixtures.
use cgbl::{
    contacts::{ContactBinding, MailboxGate, PhoneGate},
    storage::{MemoryStore, Store},
    *,
};
use cphn::cost;
use cpsd::{
    GateId, HolderSecret, KeyId,
    rand::{SeedableRng, rngs::StdRng},
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use zeroize::Zeroizing;

const DAY: u64 = 86400;
const COHORT: u64 = 5 * DAY;
const PHONE: &str = "+12025550123";
const MAILBOX: &str = "Member+alias@EXAMPLE.com";
fn subject(name: &str) -> Subject {
    Subject::new(name).unwrap()
}
fn check(seed: u64) -> CheckId {
    CheckId::generate(&mut StdRng::seed_from_u64(seed))
}

#[tokio::test]
async fn self_ban_preserves_genuine_verified_gate_facts_and_burned_comparison_identities() {
    let (global, store) = service("global", "twilio").await;
    let alice = subject("self-banning-holder");
    let operation = check(80);
    let binding = global
        .contact_binding("cphn", "twilio", &alice, &operation)
        .unwrap();
    let (fact, _) = phone::fact(&binding, PHONE, COHORT + 1, false).await;
    let phone = PhoneGate::new(binding, fact).unwrap();
    global
        .run_gate(&phone, &alice, phone.input(), 100, &operation)
        .await
        .unwrap();
    let account_key = storage::Key::new("account", alice.as_str());
    let before = store
        .read(std::slice::from_ref(&account_key))
        .await
        .unwrap();
    let before_account: serde_json::Value =
        serde_json::from_slice(&before.records[&account_key].value).unwrap();
    let fingerprints = store.list("fingerprint", "", 10).await.unwrap();
    assert_eq!(fingerprints.records.len(), 1);
    let burn = Burn::Permanent(PermanentReason::SelfBan);
    assert_eq!(
        global
            .burn(&alice, burn.clone(), 101)
            .await
            .unwrap(),
        2
    );
    assert_eq!(global.burn(&alice, burn, 102).await.unwrap(), 2);
    let after = store
        .read(std::slice::from_ref(&account_key))
        .await
        .unwrap();
    let after_account: serde_json::Value =
        serde_json::from_slice(&after.records[&account_key].value).unwrap();
    for field in ["gates", "fingerprints", "check_ids", "check_inputs"] {
        assert_eq!(before_account[field], after_account[field]);
    }
    let retained = store.list("fingerprint", "", 10).await.unwrap();
    assert_eq!(fingerprints.revisions, retained.revisions);
    for (key, record) in fingerprints.records {
        assert_eq!(record.value, retained.records[&key].value);
        assert_eq!(record.deadline, retained.records[&key].deadline);
    }
    assert!(matches!(
        global
            .run_gate(&phone, &alice, phone.input(), 103, &operation)
            .await,
        Err(Error::Burned)
    ));
    let replacement = subject("replacement-holder");
    let operation = check(81);
    let binding = global
        .contact_binding("cphn", "twilio", &replacement, &operation)
        .unwrap();
    let (fact, _) = phone::fact(&binding, PHONE, COHORT + 1, false).await;
    let phone = PhoneGate::new(binding, fact).unwrap();
    assert!(matches!(
        global
            .run_gate(&phone, &replacement, phone.input(), 103, &operation)
            .await,
        Err(Error::Duplicate)
    ));
}
fn amount() -> cost::Amount {
    cost::Amount {
        unit: cost::Unit {
            code: "FIXTURE".into(),
            scale: 0,
        },
        atoms: 10,
    }
}
fn permit(binding: &str, expiry: u64) -> cost::DispatchPermit<usize> {
    cost::Plan::new(
        vec![cost::Offer {
            candidate: cfbk::Candidate::new(0, ["control"]),
            quote: cost::Quote {
                price: cost::Price::AtMost(amount()),
                source: "inert-fixture-only-tariff".into(),
                valid_until: expiry,
                binding: binding.into(),
            },
        }],
        cfbk::Config::new([0], ["control"]),
        cost::CostOrder::Configured,
        amount(),
        1,
        cost::Mode::Production,
        100,
    )
    .unwrap()
    .start()
    .begin(100)
    .unwrap()
}

// Both concrete adapters execute their real request correlation and projection.
// The fixture implements only the trusted HTTP/state ports, never leaf logic.
macro_rules! leaf_fixture {
    ($module:ident, $leaf:ident, $context:ident, $channel:ident) => {
        mod $module {
            use super::*;
            use $leaf::{Channel, DispatchDeadline, DispatchState, Private, Step, Transport, Twilio, normalize};
            use std::{collections::HashSet, sync::Mutex};

            #[derive(Default)]
            struct Journal(Mutex<HashSet<[u8; 32]>>);
            impl DispatchState for Journal {
                fn reserve(
                    &self, _: &[u8; 32], operation: &[u8; 32], _: &str,
                    _: &cost::Amount, valid_until: u64,
                ) -> std::result::Result<(), $leaf::Error> {
                    if valid_until <= 100 || !self.0.lock().unwrap().insert(*operation) {
                        return Err($leaf::Error::Reservation);
                    }
                    Ok(())
                }
            }
            struct Wire { destination: String, calls: Arc<AtomicUsize> }
            impl Transport for Wire {
                fn mode(&self) -> cost::Mode { cost::Mode::Production }
                async fn send(
                    &self, request: http::Request<Private>,
                ) -> std::result::Result<http::Response<Private>, $leaf::Error> {
                    assert!(request.extensions().get::<DispatchDeadline>().unwrap().valid_until > 100);
                    assert!(request.headers()[http::header::AUTHORIZATION].is_sensitive());
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    let checking = request.uri().path().ends_with("/VerificationCheck");
                    Ok(http::Response::new(Private::new(serde_json::to_vec(&serde_json::json!({
                        "sid": format!("VE{}", "0".repeat(32)),
                        "account_sid": format!("AC{}", "0".repeat(32)),
                        "service_sid": format!("VA{}", "0".repeat(32)),
                        "to": self.destination,
                        "channel": Channel::$channel.as_str(),
                        "status": if checking { "approved" } else { "pending" },
                        "valid": checking,
                        "private_extension": "private-fixture-upstream",
                    })).unwrap())))
                }
            }
            pub async fn fact(
                binding: &ContactBinding, destination: &str, expiry: u64, rich: bool,
            ) -> ($leaf::Verified, Arc<AtomicUsize>) {
                let mut context = binding.$context([3; 32], Zeroizing::new([8; 32]), expiry).unwrap();
                context.include_upstream = rich;
                let adapter = Twilio::new(
                    format!("AC{}", "0".repeat(32)),
                    format!("VA{}", "0".repeat(32)),
                    Private::new(b"inert-fixture-secret".to_vec()),
                    cost::Mode::Production,
                ).unwrap();
                let calls = Arc::new(AtomicUsize::new(0));
                let wire = Wire { destination: normalize(destination).unwrap(), calls: calls.clone() };
                let journal = Journal::default();
                let begin = adapter.prepare_begin(destination, Channel::$channel, context, 100).unwrap();
                let authorization = super::permit(begin.binding(), expiry);
                let Step::Pending(pending) = begin.dispatch(&journal, &wire, authorization, &|| 100).await.unwrap() else {
                    panic!("real leaf should correlate the fixture pending ceremony");
                };
                let prepared = adapter.prepare_check(pending, "123456", [4; 32], 100).unwrap();
                let authorization = super::permit(prepared.binding(), expiry);
                let Step::Verified(fact) = prepared.dispatch(&journal, &wire, authorization, &|| 100).await.unwrap() else {
                    panic!("real leaf should authenticate the fixture approval");
                };
                assert_eq!(calls.load(Ordering::SeqCst), 2);
                (fact, calls)
            }
        }
    }
}
leaf_fixture!(phone, cphn, phone_context, Sms);
leaf_fixture!(mailbox, cmbx, mailbox_context, Email);

type Service = Global<MemoryStore, csgn::MemoryStore, cpsd::MemoryStore>;
async fn service(scope: &str, provider: &str) -> (Service, MemoryStore) {
    let store = MemoryStore::new(scope).unwrap();
    let keys = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        format!("cgbl:{scope}"),
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let issuer = cpsd::IssuerKey::generate(
        &mut StdRng::seed_from_u64(1),
        KeyId::new("shared-key").unwrap(),
        ["cphn", "cmbx"]
            .map(|gate| GateId::new(gate).unwrap())
            .to_vec(),
    )
    .unwrap();
    let global = Global::open(
        store.clone(),
        cpsd::MemoryStore::new(cpsd::CommunityId::new(scope.as_bytes()).unwrap(), 10).unwrap(),
        issuer,
        keys,
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
        30 * DAY,
    )
    .await
    .unwrap();
    let policy = Policy {
        version: 1,
        scope: scope.into(),
        revision: 1,
        epoch: 1,
        shared_expiry: COHORT,
        gates: ["cphn", "cmbx"]
            .map(|gate| GatePolicy {
                gate: gate.into(),
                provider: provider.into(),
                uniqueness: true,
            })
            .to_vec(),
    };
    let signed = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            0,
            COHORT + DAY,
        )
        .await
        .unwrap();
    global
        .install_policy(&signed, authority.key_ring().unwrap(), 100)
        .await
        .unwrap();
    (global, store)
}

#[tokio::test]
async fn genuine_phone_and_mailbox_control_reach_a_real_blind_passport_in_production_mode() {
    let (global, store) = service("global", "twilio").await;
    let alice = subject("alice");
    let phone_check = check(1);
    let mailbox_check = check(2);
    let phone_binding = global
        .contact_binding("cphn", "twilio", &alice, &phone_check)
        .unwrap();
    let mailbox_binding = global
        .contact_binding("cmbx", "twilio", &alice, &mailbox_check)
        .unwrap();
    let (phone_fact, phone_calls) = phone::fact(&phone_binding, PHONE, COHORT + 1, true).await;
    let (mailbox_fact, mailbox_calls) =
        mailbox::fact(&mailbox_binding, MAILBOX, COHORT + 1, true).await;
    assert!(phone_fact.upstream().is_some());
    assert!(mailbox_fact.upstream().is_some());
    let phone = PhoneGate::new(phone_binding, phone_fact).unwrap();
    let mailbox = MailboxGate::new(mailbox_binding, mailbox_fact).unwrap();
    assert_eq!(phone.id(), "cphn");
    assert_eq!(mailbox.id(), "cmbx");
    assert_eq!(phone.provider(), "twilio");
    assert_eq!(mailbox.provider(), "twilio");
    assert!(!phone.development_only());
    assert!(!mailbox.development_only());
    assert_eq!(format!("{phone:?}"), "PhoneGate([redacted])");
    assert_eq!(format!("{mailbox:?}"), "MailboxGate([redacted])");
    for _ in 0..2 {
        let phone_result = global
            .run_gate(&phone, &alice, phone.input(), 100, &phone_check)
            .await
            .unwrap();
        let mailbox_result = global
            .run_gate(&mailbox, &alice, mailbox.input(), 100, &mailbox_check)
            .await
            .unwrap();
        assert_eq!(phone_result.valid_until, COHORT);
        assert_eq!(mailbox_result.valid_until, COHORT);
    }
    assert_eq!(phone_calls.load(Ordering::SeqCst), 2);
    assert_eq!(mailbox_calls.load(Ordering::SeqCst), 2);
    assert!(matches!(
        global
            .run_gate(&phone, &alice, b"changed", 100, &phone_check)
            .await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        global
            .run_gate(&mailbox, &alice, b"changed", 100, &mailbox_check)
            .await,
        Err(Error::Conflict)
    ));
    let mut rng = StdRng::seed_from_u64(99);
    let session = Session::authenticated(alice.clone(), [7; 32]).unwrap();
    let challenge = global
        .challenge(&mut rng, &session, 100, 150)
        .await
        .unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let (request, pending) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
    let blind = global
        .issue(&mut rng, &session, &challenge, &request, 101)
        .await
        .unwrap();
    assert_eq!(blind.attributes().valid_until, COHORT);
    let passport = pending.finish(&blind).unwrap();
    let presentation_request = cpsd::PresentationRequest::for_epoch(
        &mut rng,
        cpsd::CommunityId::new(b"consumer").unwrap(),
        1,
        [GateId::new("cphn").unwrap(), GateId::new("cmbx").unwrap()],
        200,
        COHORT,
    )
    .unwrap();
    let mut consumer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "consumer",
        csgn::SecretKey::from_seed(&mut [8; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let signed = consumer
        .sign(
            csgn::Kind::Credential,
            &presentation_request.to_bytes(),
            0,
            201,
        )
        .await
        .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        presentation_request.community().clone(),
        consumer.key_ring().unwrap().clone(),
    );
    let proof = passport.present(&mut rng, &expected, &signed, 200).unwrap();
    let verified = cpsd::verify(
        &mut rng,
        &[global.issuer_public_key().clone()],
        &presentation_request,
        &proof,
    )
    .unwrap();
    assert_eq!(verified, secret.pseudonym(presentation_request.community()));
    for bucket in ["account", "fingerprint", "challenge"] {
        for record in store
            .list(bucket, "", 100)
            .await
            .unwrap()
            .records
            .into_values()
        {
            let data = String::from_utf8(record.value).unwrap();
            for private in [
                PHONE,
                "Member+alias",
                "private-fixture-upstream",
                "inert-fixture-secret",
                "123456",
            ] {
                assert!(
                    !data.contains(private),
                    "private leaf data reached {bucket}"
                );
            }
        }
    }
}

#[tokio::test]
async fn facts_reject_independently_changed_binding_provider_subject_scope_and_check() {
    let (global, _) = service("global", "twilio").await;
    let alice = subject("alice");
    let operation = check(11);
    let binding = global
        .contact_binding("cphn", "twilio", &alice, &operation)
        .unwrap();
    for (gate, provider, who, operation) in [
        ("cmbx", "twilio", subject("alice"), check(11)),
        ("cphn", "other", subject("alice"), check(11)),
        ("cphn", "twilio", subject("bob"), check(11)),
        ("cphn", "twilio", subject("alice"), check(12)),
    ] {
        let other = global
            .contact_binding(gate, provider, &who, &operation)
            .unwrap();
        let (fact, _) = phone::fact(&other, PHONE, COHORT + 1, false).await;
        assert!(matches!(
            PhoneGate::new(binding.clone(), fact),
            Err(Error::Gates)
        ));
        let (fact, _) = mailbox::fact(&other, MAILBOX, COHORT + 1, false).await;
        assert!(matches!(
            MailboxGate::new(binding.clone(), fact),
            Err(Error::Gates)
        ));
    }
    let (other_global, _) = service("other-global", "twilio").await;
    let other = other_global
        .contact_binding("cphn", "twilio", &alice, &operation)
        .unwrap();
    let (fact, _) = phone::fact(&other, PHONE, COHORT + 1, false).await;
    assert!(matches!(
        PhoneGate::new(binding.clone(), fact),
        Err(Error::Gates)
    ));
    let (fact, _) = phone::fact(&binding, PHONE, COHORT + 1, false).await;
    let phone = PhoneGate::new(binding.clone(), fact).unwrap();
    let (fact, _) = mailbox::fact(&binding, MAILBOX, COHORT + 1, false).await;
    let mailbox = MailboxGate::new(binding, fact).unwrap();
    for (who, input, operation) in [
        (subject("bob"), phone.input(), check(11)),
        (alice.clone(), b"changed".as_slice(), check(11)),
        (alice.clone(), phone.input(), check(12)),
    ] {
        assert!(matches!(
            global.run_gate(&phone, &who, input, 100, &operation).await,
            Err(Error::Gates)
        ));
        assert!(matches!(
            global
                .run_gate(&mailbox, &who, input, 100, &operation)
                .await,
            Err(Error::Gates)
        ));
    }
    let other_binding = global
        .contact_binding("cphn", "disabled", &alice, &check(11))
        .unwrap();
    let (fact, _) = phone::fact(&other_binding, PHONE, COHORT + 1, false).await;
    let disabled = PhoneGate::new(other_binding, fact).unwrap();
    assert!(matches!(
        global
            .run_gate(&disabled, &alice, disabled.input(), 100, &check(11))
            .await,
        Err(Error::GateDisabled)
    ));
}

#[tokio::test]
async fn canonical_comparison_identity_blocks_a_second_subject_for_both_domains() {
    let (global, _) = service("global", "twilio").await;
    for (index, name) in ["alice", "bob"].into_iter().enumerate() {
        let who = subject(name);
        let operation = check(20 + index as u64);
        let binding = global
            .contact_binding("cphn", "twilio", &who, &operation)
            .unwrap();
        let destination = if index == 0 { PHONE } else { "+1 202 555 0123" };
        let (fact, _) = phone::fact(&binding, destination, COHORT + 1, false).await;
        let gate = PhoneGate::new(binding, fact).unwrap();
        let result = global
            .run_gate(&gate, &who, gate.input(), 100, &operation)
            .await;
        assert_eq!(result.is_ok(), index == 0);
        if index == 1 {
            assert!(matches!(result, Err(Error::Duplicate)));
        }
        let binding = global
            .contact_binding("cmbx", "twilio", &who, &operation)
            .unwrap();
        let destination = if index == 0 {
            MAILBOX
        } else {
            "Member+alias@example.com"
        };
        let (fact, _) = mailbox::fact(&binding, destination, COHORT + 1, false).await;
        let gate = MailboxGate::new(binding, fact).unwrap();
        let result = global
            .run_gate(&gate, &who, gate.input(), 100, &operation)
            .await;
        assert_eq!(result.is_ok(), index == 0);
        if index == 1 {
            assert!(matches!(result, Err(Error::Duplicate)));
        }
    }
}

#[tokio::test]
async fn exclusive_expiry_is_not_extended_and_short_facts_cannot_issue_the_passport_cohort() {
    let (global, _) = service("global", "twilio").await;
    let who = subject("alice");
    let operation = check(30);
    for expiry in [101, COHORT] {
        let binding = global
            .contact_binding("cphn", "twilio", &who, &operation)
            .unwrap();
        let (fact, _) = phone::fact(&binding, PHONE, expiry, false).await;
        let phone = PhoneGate::new(binding, fact).unwrap();
        let binding = global
            .contact_binding("cmbx", "twilio", &who, &operation)
            .unwrap();
        let (fact, _) = mailbox::fact(&binding, MAILBOX, expiry, false).await;
        let mailbox = MailboxGate::new(binding, fact).unwrap();
        assert!(matches!(
            global
                .run_gate(&phone, &who, phone.input(), expiry, &operation)
                .await,
            Err(Error::Gates)
        ));
        assert!(matches!(
            global
                .run_gate(&mailbox, &who, mailbox.input(), expiry, &operation)
                .await,
            Err(Error::Gates)
        ));
        if expiry == COHORT {
            assert_eq!(
                global
                    .run_gate(&phone, &who, phone.input(), 100, &operation)
                    .await
                    .unwrap()
                    .valid_until,
                COHORT - DAY
            );
            assert_eq!(
                global
                    .run_gate(&mailbox, &who, mailbox.input(), 100, &operation)
                    .await
                    .unwrap()
                    .valid_until,
                COHORT - DAY
            );
            let session = Session::authenticated(who.clone(), [7; 32]).unwrap();
            assert!(matches!(
                global
                    .challenge(&mut StdRng::seed_from_u64(30), &session, 100, 150)
                    .await,
                Err(Error::Gates)
            ));
        }
    }
}
