use super::*;

fn binding() -> ContactBinding {
    ContactBinding::derive(
        &FingerprintKey::from_bytes(&mut [7; 32]),
        "global",
        "cphn",
        "twilio",
        &Subject::new("alice").unwrap(),
        &CheckId("a".repeat(64)),
    )
    .unwrap()
}

#[test]
fn expected_bindings_are_private_and_derived_from_every_independent_context_field() {
    let expected = binding();
    let key = FingerprintKey::from_bytes(&mut [7; 32]);
    for (scope, gate, provider, subject, check) in [
        ("other", "cphn", "twilio", "alice", "a"),
        ("global", "cmbx", "twilio", "alice", "a"),
        ("global", "cphn", "other", "alice", "a"),
        ("global", "cphn", "twilio", "bob", "a"),
        ("global", "cphn", "twilio", "alice", "b"),
    ] {
        let different = ContactBinding::derive(
            &key,
            scope,
            gate,
            provider,
            &Subject::new(subject).unwrap(),
            &CheckId(check.repeat(64)),
        )
        .unwrap();
        assert_ne!(expected.binding, different.binding);
        assert!(
            expected
                .verify(&different.check, &expected.subject, &expected.binding)
                .is_err()
        );
    }
    assert_eq!(format!("{expected:?}"), "ContactBinding([redacted])");
    expected
        .verify(&expected.check, &expected.subject, &expected.binding)
        .unwrap();
    assert!(
        expected
            .verify(
                &expected.check,
                &Subject::new("bob").unwrap(),
                &expected.binding
            )
            .is_err()
    );
    assert!(
        expected
            .verify(&expected.check, &expected.subject, b"changed")
            .is_err()
    );
}

#[test]
fn host_context_rejects_invalid_identifiers_checks_and_exclusive_lifetimes() {
    let key = FingerprintKey::from_bytes(&mut [7; 32]);
    let subject = Subject::new("alice").unwrap();
    for (scope, gate, provider, check) in [
        ("", "cphn", "twilio", "a".repeat(64)),
        ("global", "invalid gate", "twilio", "a".repeat(64)),
        ("global", "cphn", "", "a".repeat(64)),
        ("global", "cphn", "twilio", "invalid".into()),
    ] {
        assert!(
            ContactBinding::derive(&key, scope, gate, provider, &subject, &CheckId(check)).is_err()
        );
    }
    let expected = binding();
    for expiry in [0, 1, cpsd::TIME_LIMIT + 1] {
        assert!(
            expected
                .phone_context([1; 32], Zeroizing::new([8; 32]), expiry)
                .is_err()
        );
        assert!(
            expected
                .mailbox_context([1; 32], Zeroizing::new([8; 32]), expiry)
                .is_err()
        );
    }
    let phone = expected
        .phone_context([1; 32], Zeroizing::new([8; 32]), 86401)
        .unwrap();
    let mailbox = expected
        .mailbox_context([2; 32], Zeroizing::new([9; 32]), 86401)
        .unwrap();
    assert_eq!(phone.binding, expected.binding);
    assert_eq!(mailbox.binding, expected.binding);
    assert_eq!(phone.scope, b"global");
    assert_eq!(mailbox.scope, b"global");
    assert!(!phone.include_upstream);
    assert!(!mailbox.include_upstream);
}

#[test]
fn opaque_uniqueness_preserves_domain_and_never_extends_an_exclusive_expiry() {
    let phone = evidence(b"phone.e164\0", &[8; 32], 86401, 86400).unwrap();
    let mailbox = evidence(b"mailbox.address\0", &[8; 32], 86401, 86400).unwrap();
    assert_eq!(phone.valid_until, 86400);
    assert_ne!(phone.uniqueness, mailbox.uniqueness);
    assert!(evidence(b"phone.e164\0", &[8; 32], 86401, 86401).is_err());
    assert!(evidence(b"phone.e164\0", &[8; 32], 0, 0).is_err());
}
