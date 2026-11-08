//! One-ceremony registration birth items through the genuine Global, Keyhole, wallet signer
//! and ckmg device keys: device, genesis, passport and stamp are first-only and idempotent.
use super::*;

const MEMBER: u128 = 27;
const COMMITMENT: [u8; 32] = [44; 32];
const PRF: [u8; 32] = [9; 32];

fn account() -> String {
    ckyh::Uuid::from_u128(MEMBER).to_string()
}
fn birth_session() -> Session {
    Session::authenticated(Subject::new(account()).unwrap(), [7; 32]).unwrap()
}
fn prf(seed: [u8; 32]) -> ckmg::passkey::PrfOutput {
    ckmg::passkey::PrfOutput::from_bytes(&seed).unwrap()
}
fn device_key(seed: [u8; 32]) -> [u8; 32] {
    *ckmg::passkey::device_public_key(&prf(seed), "wallet")
        .unwrap()
        .value()
}
/// The origin the device signs: the configured vault origin without a path.
fn origin() -> String {
    ORIGIN.into()
}
fn device_signature(
    seed: [u8; 32],
    purpose: ckmg::DeviceFormat,
    origin: &str,
    auth: &ckyh::Authentication,
    commitment: [u8; 32],
) -> [u8; 64] {
    let payload = ckmg::wallet_birth_device_payload(
        origin,
        &account(),
        auth.credential_id().as_ref(),
        &commitment,
        &device_key(seed),
    )
    .unwrap();
    match purpose {
        // The opening signs the session format too, under another tag.
        ckmg::DeviceFormat::DeviceSession => {
            ckmg::passkey::sign_device_session(&prf(seed), "wallet", &payload).unwrap()
        }
        _ => ckmg::passkey::sign_device_birth(&prf(seed), "wallet", purpose, &payload).unwrap(),
    }
}
fn bind_signature(seed: [u8; 32], auth: &ckyh::Authentication) -> [u8; 64] {
    device_signature(
        seed,
        ckmg::DeviceFormat::WalletBirthDevice,
        &origin(),
        auth,
        COMMITMENT,
    )
}

/// A first registration that retained the creation commitment `c`, then a login.
async fn born() -> (
    tempfile::TempDir,
    Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
    ckyh::Authentication,
) {
    let directory = tempfile::tempdir().unwrap();
    let url = ckyh::Url::from_file_path(directory.path().join("wallet.db")).unwrap();
    let db = crlt::Db::open(crlt::Config::new(url.as_str(), ""))
        .await
        .unwrap();
    db.migrate(&[crlt::Migration::new(1, "passkeys", ckyh::LIBSQL_SCHEMA)])
        .await
        .unwrap();
    let keys = Arc::new(
        ckyh::Passkeys::new(
            ckyh::LibsqlStore::new(&db, "wallet", tokio::runtime::Handle::current()).unwrap(),
            "wallet",
            RP,
            &[ckyh::Url::parse(ORIGIN).unwrap()],
        )
        .unwrap(),
    );
    let owner = keys.clone();
    let authentication = tokio::task::spawn_blocking(move || {
        let mut token = SoftToken::new(true).unwrap().0;
        let member = ckyh::Uuid::from_u128(MEMBER);
        let (mut challenge, pending) = owner
            .start_initial_registration(member, Some(COMMITMENT))
            .unwrap();
        challenge
            .public_key
            .authenticator_selection
            .as_mut()
            .unwrap()
            .require_resident_key = false;
        let response = token
            .perform_register(
                ckyh::Url::parse(ORIGIN).unwrap(),
                challenge.public_key,
                300_000,
            )
            .unwrap();
        owner
            .finish_registration(
                pending,
                &response.into(),
                ckyh::CreationMonth::new(2026, 10).unwrap(),
            )
            .unwrap();
        let (challenge, pending) = owner.start_authentication(member).unwrap();
        let response = token
            .perform_auth(
                ckyh::Url::parse(ORIGIN).unwrap(),
                challenge.public_key,
                300_000,
            )
            .unwrap();
        owner
            .finish_authentication(pending, &response.into())
            .unwrap()
    })
    .await
    .unwrap();
    (directory, keys, authentication)
}

/// The genuine ckmg genesis receipt of the wallet lineage, made with the device PRF.
async fn genesis_receipt(seed: [u8; 32]) -> ckmg::Receipt {
    use ckmg::{Authority, Authorization, Binding, Commit, DeviceInfo, Error, Locator};
    #[derive(Clone, Default)]
    struct Memory(Arc<Mutex<std::collections::HashMap<Locator, Vec<u8>>>>);
    impl ckmg::SecureStore for Memory {
        async fn load(
            &mut self,
            location: &Locator,
        ) -> std::result::Result<Option<Vec<u8>>, Error> {
            Ok(self.0.lock().unwrap().get(location).cloned())
        }
        async fn compare_exchange(
            &mut self,
            location: &Locator,
            expected: Option<[u8; 32]>,
            next: &[u8],
        ) -> std::result::Result<Commit, Error> {
            let mut data = self.0.lock().unwrap();
            if data
                .get(location)
                .map(|value| *blake3::hash(value).as_bytes())
                != expected
            {
                return Ok(Commit::Conflict);
            }
            data.insert(*location, next.to_vec());
            Ok(Commit::Committed)
        }
    }
    struct Clock;
    impl ckmg::Clock for Clock {
        fn now(&mut self) -> std::result::Result<u64, Error> {
            Ok(1_800_000_000)
        }
    }
    struct Allow;
    impl Authority for Allow {
        async fn check(&mut self, _request: Authorization<'_>) -> std::result::Result<(), Error> {
            Ok(())
        }
    }
    let mut keys = ckmg::Keys::new(Memory::default(), Clock, ckmg::SystemEntropy, Allow);
    keys.create_scope(
        &prf(seed),
        Binding::new("wallet", &account()).unwrap(),
        DeviceInfo::new("fixture", &[9; 16]).unwrap(),
        b"fixture",
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn birth_device_is_first_only_idempotent_and_bound_to_its_exact_fields() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, auth) = born().await;
    let mut wallet = wallet(&global, keys, csgn::MemoryStore::default(), false).await;
    let k = device_key(PRF);
    // A signature over another purpose, origin, commitment or key refuses and leaves the
    // writer usable.
    let wrong = [
        device_signature(
            PRF,
            ckmg::DeviceFormat::DeviceSession,
            &origin(),
            &auth,
            COMMITMENT,
        ),
        device_signature(
            PRF,
            ckmg::DeviceFormat::WalletBirthPassport,
            &origin(),
            &auth,
            COMMITMENT,
        ),
        device_signature(
            PRF,
            ckmg::DeviceFormat::WalletBirthDevice,
            "https://vault.other.test",
            &auth,
            COMMITMENT,
        ),
        device_signature(
            PRF,
            ckmg::DeviceFormat::WalletBirthDevice,
            &format!("{ORIGIN}/"),
            &auth,
            COMMITMENT,
        ),
        device_signature(
            PRF,
            ckmg::DeviceFormat::WalletBirthDevice,
            &origin(),
            &auth,
            [45; 32],
        ),
    ];
    for signature in wrong {
        assert!(matches!(
            global
                .authorize_wallet_birth_device(&mut wallet, &auth, k, &signature, NOW + 60, &|| NOW)
                .await,
            Err(Error::Signature)
        ));
    }
    // K's signature cannot bind another key.
    assert!(matches!(
        global
            .authorize_wallet_birth_device(
                &mut wallet,
                &auth,
                device_key([10; 32]),
                &bind_signature(PRF, &auth),
                NOW + 60,
                &|| NOW
            )
            .await,
        Err(Error::Signature)
    ));
    let first = global
        .authorize_wallet_birth_device(
            &mut wallet,
            &auth,
            k,
            &bind_signature(PRF, &auth),
            NOW + 60,
            &|| NOW,
        )
        .await
        .unwrap();
    assert_eq!(first.devices(), &[k]);
    assert!(first.births().is_empty());
    // Same request: same result, no new generation.
    let same = global
        .authorize_wallet_birth_device(
            &mut wallet,
            &auth,
            k,
            &bind_signature(PRF, &auth),
            NOW + 60,
            &|| NOW,
        )
        .await
        .unwrap();
    assert_eq!(same.devices(), &[k]);
    // Another correctly signed device: refused, the first binding stays.
    let other = [10; 32];
    assert!(matches!(
        global
            .authorize_wallet_birth_device(
                &mut wallet,
                &auth,
                device_key(other),
                &bind_signature(other, &auth),
                NOW + 60,
                &|| NOW
            )
            .await,
        Err(Error::Duplicate)
    ));
    let observed = global
        .wallet_devices(&mut wallet, &auth, NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert_eq!(observed.devices(), &[k]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_step_up_binding_or_a_second_passkey_closes_the_birth_device() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, auth) = born().await;
    let mut owner = wallet(&global, keys.clone(), csgn::MemoryStore::default(), false).await;
    global
        .authorize_wallet_device(&mut owner, &auth, [49; 32], NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert!(matches!(
        global
            .authorize_wallet_birth_device(
                &mut owner,
                &auth,
                device_key(PRF),
                &bind_signature(PRF, &auth),
                NOW + 60,
                &|| NOW
            )
            .await,
        Err(Error::Duplicate)
    ));
    // A second live passkey of the account ends the birth grant in cgbl too.
    let (_other, keys, auth) = born().await;
    let owner = keys.clone();
    tokio::task::spawn_blocking(move || {
        let mut token = SoftToken::new(true).unwrap().0;
        let (mut challenge, pending) = owner
            .start_registration(ckyh::Uuid::from_u128(MEMBER))
            .unwrap();
        challenge
            .public_key
            .authenticator_selection
            .as_mut()
            .unwrap()
            .require_resident_key = false;
        let response = token
            .perform_register(
                ckyh::Url::parse(ORIGIN).unwrap(),
                challenge.public_key,
                300_000,
            )
            .unwrap();
        owner
            .finish_registration(
                pending,
                &response.into(),
                ckyh::CreationMonth::new(2026, 10).unwrap(),
            )
            .unwrap();
    })
    .await
    .unwrap();
    let (global, _, _, _) = make().await;
    let mut second = wallet(&global, keys, csgn::MemoryStore::default(), false).await;
    assert!(matches!(
        global
            .authorize_wallet_birth_device(
                &mut second,
                &auth,
                device_key(PRF),
                &bind_signature(PRF, &auth),
                NOW + 60,
                &|| NOW
            )
            .await,
        Err(Error::Duplicate)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn two_racing_birth_device_requests_bind_exactly_one() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, auth) = born().await;
    let signer = csgn::MemoryStore::default();
    let mut left = wallet(&global, keys.clone(), signer.clone(), false).await;
    let mut right = wallet(&global, keys, signer, true).await;
    let other = [10; 32];
    let (first, second) = (bind_signature(PRF, &auth), bind_signature(other, &auth));
    let clock = || NOW;
    let (a, b) = tokio::join!(
        global.authorize_wallet_birth_device(
            &mut left,
            &auth,
            device_key(PRF),
            &first,
            NOW + 60,
            &clock
        ),
        global.authorize_wallet_birth_device(
            &mut right,
            &auth,
            device_key(other),
            &second,
            NOW + 60,
            &clock
        ),
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let winner = a.as_ref().or(b.as_ref()).unwrap().devices().to_vec();
    assert!(winner == [device_key(PRF)] || winner == [device_key(other)]);
    for loser in [a, b].into_iter().filter_map(|result| result.err()) {
        assert!(matches!(
            loser,
            Error::Duplicate | Error::Conflict | Error::Storage
        ));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn birth_genesis_is_wallet_signed_listed_once_and_verifies_offline() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, auth) = born().await;
    let mut wallet = wallet(&global, keys, csgn::MemoryStore::default(), false).await;
    let receipt = genesis_receipt(PRF).await;
    let digest = receipt.passkey_challenge().unwrap();
    // No bound birth device yet.
    assert!(matches!(
        global
            .wallet_birth_genesis(&mut wallet, &auth, digest, NOW + 60, &|| NOW)
            .await,
        Err(Error::Challenge)
    ));
    let k = device_key(PRF);
    assert_eq!(*receipt.attested_lineage().unwrap().1.value(), k);
    global
        .authorize_wallet_birth_device(
            &mut wallet,
            &auth,
            k,
            &bind_signature(PRF, &auth),
            NOW + 60,
            &|| NOW,
        )
        .await
        .unwrap();
    let statement = global
        .wallet_birth_genesis(&mut wallet, &auth, digest, NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert_eq!(statement.at(), NOW / DAY * DAY);
    let same = global
        .wallet_birth_genesis(&mut wallet, &auth, digest, NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert_eq!(
        (same.bytes(), same.at()),
        (statement.bytes(), statement.at())
    );
    assert!(matches!(
        global
            .wallet_birth_genesis(&mut wallet, &auth, [3; 32], NOW + 60, &|| NOW)
            .await,
        Err(Error::Duplicate)
    ));
    // The account's own row lists exactly this statement.
    let observed = global
        .wallet_devices(&mut wallet, &auth, NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert_eq!(
        observed.births(),
        &[cchr::birth_statement_digest(statement.bytes())]
    );
    // The offline verifier accepts it under the wallet ring, and the restoring check holds.
    let evidence =
        cchr::BirthGenesisEvidence::new(receipt, statement.bytes().to_vec(), statement.at());
    let ring = wallet.key_ring().unwrap();
    let verified = cchr::verify_birth_genesis(
        ring,
        &evidence,
        &cchr::wallet_fingerprint(None),
        &account(),
        NOW,
    )
    .unwrap();
    verified
        .check_restoring(auth.credential_id().as_ref(), &k)
        .unwrap();
    assert_eq!(verified.statement().commitment(), &COMMITMENT);
    assert!(
        cchr::verify_birth_genesis(
            ring,
            &evidence,
            &cchr::wallet_fingerprint(None),
            "other",
            NOW
        )
        .is_err()
    );
}

/// The passport and the first stamp: gate, birth passport bound to K, birth stamp.
#[tokio::test(flavor = "multi_thread")]
async fn birth_passport_and_birth_stamp_are_first_only_idempotent_and_race_once() {
    let (mut global, _, _, _) = make().await;
    let mut rng = StdRng::seed_from_u64(31);
    let stamp_key = cpsd::StampIssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("stamp").unwrap(),
        &cpsd::StampParams::new(DAY).unwrap(),
    )
    .unwrap();
    global
        .attach_stamps(stamp_key, StampRate::default())
        .unwrap();
    let (_directory, keys, auth) = born().await;
    let mut wallet = wallet(&global, keys, csgn::MemoryStore::default(), false).await;
    let session = birth_session();
    global
        .run_gate(
            &Provider::default(),
            &session_subject(),
            b"input",
            100,
            &check(),
        )
        .await
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [61; 32]);
    let challenge = global
        .challenge(&mut rng, &session, 100, 150)
        .await
        .unwrap();
    let request = holder
        .begin_issuance(&mut rng, global.issuer_public_key(), &challenge)
        .unwrap();
    let passport_signature = |seed: [u8; 32], purpose, request: &IssuanceRequest| {
        ckmg::passkey::sign_device_birth(
            &prf(seed),
            "wallet",
            purpose,
            &ckmg::wallet_birth_passport_payload(&request.to_bytes()),
        )
        .unwrap()
    };
    // Without a bound birth device there is no K to check.
    assert!(matches!(
        global
            .issue_birth_passport(
                &mut rng,
                &session,
                &challenge,
                &request,
                &passport_signature(PRF, ckmg::DeviceFormat::WalletBirthPassport, &request),
                100
            )
            .await,
        Err(Error::Challenge)
    ));
    global
        .authorize_wallet_birth_device(
            &mut wallet,
            &auth,
            device_key(PRF),
            &bind_signature(PRF, &auth),
            NOW + 60,
            &|| NOW,
        )
        .await
        .unwrap();
    // Wrong tag or another key's signature refuses.
    for signature in [
        passport_signature(PRF, ckmg::DeviceFormat::WalletBirthDevice, &request),
        passport_signature([10; 32], ckmg::DeviceFormat::WalletBirthPassport, &request),
    ] {
        assert!(matches!(
            global
                .issue_birth_passport(&mut rng, &session, &challenge, &request, &signature, 100)
                .await,
            Err(Error::Signature)
        ));
    }
    // Two racing requests on the same challenge: exactly one is issued.
    let mut rival = cpsd::OpaqueHolder::from_seed(&mut [61; 32]);
    let rival_request = rival
        .begin_issuance(&mut rng, global.issuer_public_key(), &challenge)
        .unwrap();
    let signature = passport_signature(PRF, ckmg::DeviceFormat::WalletBirthPassport, &request);
    let rival_signature =
        passport_signature(PRF, ckmg::DeviceFormat::WalletBirthPassport, &rival_request);
    let (mut left_rng, mut right_rng) = (StdRng::seed_from_u64(1), StdRng::seed_from_u64(2));
    let (left, right) = tokio::join!(
        global.issue_birth_passport(
            &mut left_rng,
            &session,
            &challenge,
            &request,
            &signature,
            100
        ),
        global.issue_birth_passport(
            &mut right_rng,
            &session,
            &challenge,
            &rival_request,
            &rival_signature,
            100
        ),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let (winner, request, signature, holder) = match (left, right) {
        (Ok(passport), Err(error)) => {
            assert!(matches!(error, Error::Duplicate | Error::Conflict));
            (passport, request, signature, &mut holder)
        }
        (Err(error), Ok(passport)) => {
            assert!(matches!(error, Error::Duplicate | Error::Conflict));
            (passport, rival_request, rival_signature, &mut rival)
        }
        _ => unreachable!(),
    };
    // The same request again: the same passport, no new issue.
    let again = global
        .issue_birth_passport(&mut rng, &session, &challenge, &request, &signature, 100)
        .await
        .unwrap();
    assert_eq!(again.to_bytes(), winner.to_bytes());
    holder.finish_issuance(&winner).unwrap();

    // The first stamp, without an assertion.
    let (nonce, stamp_public) = global
        .stamp_challenge(&mut rng, &session, 100)
        .await
        .unwrap();
    let action = |seed: u8| {
        (
            cpsd::StampScope::new(
                cpsd::CommunityId::new("community-1").unwrap(),
                cpsd::CommunityFingerprint::from_bytes([1; 32]),
            ),
            cpsd::StampAction::new(
                cpsd::ActionKind::new("lineage.pair").unwrap(),
                cpsd::PayloadDigest::from_bytes([seed; 32]),
                cpsd::StampSalt::generate(&mut StdRng::seed_from_u64(u64::from(seed))),
            ),
        )
    };
    let first = holder
        .begin_stamp(&mut rng, &stamp_public, &nonce, &[action(1)], 100)
        .unwrap();
    holder.cancel_stamp();
    let second = holder
        .begin_stamp(&mut rng, &stamp_public, &nonce, &[action(2)], 100)
        .unwrap();
    holder.cancel_stamp();
    let (mut left_rng, mut right_rng) = (StdRng::seed_from_u64(3), StdRng::seed_from_u64(4));
    let (left, right) = tokio::join!(
        global.issue_birth_stamp(&mut left_rng, &session, &first, &nonce, 100),
        global.issue_birth_stamp(&mut right_rng, &session, &second, &nonce, 100),
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    let (stamp, request, other) = match (left, right) {
        (Ok(stamp), Err(error)) => {
            assert!(matches!(error, Error::Duplicate | Error::Conflict));
            (stamp, first, second)
        }
        (Err(error), Ok(stamp)) => {
            assert!(matches!(error, Error::Duplicate | Error::Conflict));
            (stamp, second, first)
        }
        _ => unreachable!(),
    };
    // Same request: the same stamp. Another request: refused, even after the winner.
    let again = global
        .issue_birth_stamp(&mut rng, &session, &request, &nonce, 100)
        .await
        .unwrap();
    assert_eq!(again.to_bytes(), stamp.to_bytes());
    assert!(matches!(
        global
            .issue_birth_stamp(&mut rng, &session, &other, &nonce, 100)
            .await,
        Err(Error::Duplicate)
    ));
}

fn session_subject() -> Subject {
    Subject::new(account()).unwrap()
}

/// Condition of the review: once any normal (assertion-confirmed) stamp exists for the account,
/// no assertion-free stamp is possible, whatever the request; the normal path keeps working.
#[tokio::test(flavor = "multi_thread")]
async fn a_normal_stamp_closes_the_birth_stamp_for_good() {
    let (mut global, _, _, _) = make().await;
    let mut rng = StdRng::seed_from_u64(41);
    let stamp_key = cpsd::StampIssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("stamp").unwrap(),
        &cpsd::StampParams::new(DAY).unwrap(),
    )
    .unwrap();
    global
        .attach_stamps(stamp_key, StampRate::default())
        .unwrap();
    let (_directory, keys, auth) = born().await;
    let mut wallet = wallet(&global, keys, csgn::MemoryStore::default(), false).await;
    let session = birth_session();
    global
        .run_gate(
            &Provider::default(),
            &session_subject(),
            b"input",
            100,
            &check(),
        )
        .await
        .unwrap();
    global
        .authorize_wallet_birth_device(
            &mut wallet,
            &auth,
            device_key(PRF),
            &bind_signature(PRF, &auth),
            NOW + 60,
            &|| NOW,
        )
        .await
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [62; 32]);
    let challenge = global
        .challenge(&mut rng, &session, 100, 150)
        .await
        .unwrap();
    let request = holder
        .begin_issuance(&mut rng, global.issuer_public_key(), &challenge)
        .unwrap();
    let signature = ckmg::passkey::sign_device_birth(
        &prf(PRF),
        "wallet",
        ckmg::DeviceFormat::WalletBirthPassport,
        &ckmg::wallet_birth_passport_payload(&request.to_bytes()),
    )
    .unwrap();
    let passport = global
        .issue_birth_passport(&mut rng, &session, &challenge, &request, &signature, 100)
        .await
        .unwrap();
    holder.finish_issuance(&passport).unwrap();
    let action = |seed: u8| {
        (
            cpsd::StampScope::new(
                cpsd::CommunityId::new("community-1").unwrap(),
                cpsd::CommunityFingerprint::from_bytes([1; 32]),
            ),
            cpsd::StampAction::new(
                cpsd::ActionKind::new("lineage.pair").unwrap(),
                cpsd::PayloadDigest::from_bytes([seed; 32]),
                cpsd::StampSalt::generate(&mut StdRng::seed_from_u64(u64::from(seed))),
            ),
        )
    };
    // A normal stamp first (the host verified an assertion over the confirmation challenge).
    let (nonce, stamp_public) = global
        .stamp_challenge(&mut rng, &session, 100)
        .await
        .unwrap();
    let normal = holder
        .begin_stamp(&mut rng, &stamp_public, &nonce, &[action(1)], 100)
        .unwrap();
    let confirmation = normal.confirmation_challenge(&nonce);
    let stamp = global
        .issue_stamp(&mut rng, &session, &normal, &nonce, confirmation, 100)
        .await
        .unwrap();
    let epoch = global.stamp_epoch(100).await.unwrap();
    holder.finish_stamp(&stamp, epoch, 100).unwrap();
    // Every later assertion-free stamp is refused: another request and the very same one.
    let (nonce, stamp_public) = global
        .stamp_challenge(&mut rng, &session, 100)
        .await
        .unwrap();
    let birth = holder
        .begin_stamp(&mut rng, &stamp_public, &nonce, &[action(2)], 100)
        .unwrap();
    for request in [&birth, &normal] {
        assert!(matches!(
            global
                .issue_birth_stamp(&mut rng, &session, request, &nonce, 100)
                .await,
            Err(Error::Duplicate)
        ));
    }
    // The normal path is not affected by the closed item.
    let confirmation = birth.confirmation_challenge(&nonce);
    let next = global
        .issue_stamp(&mut rng, &session, &birth, &nonce, confirmation, 100)
        .await
        .unwrap();
    holder.finish_stamp(&next, epoch, 100).unwrap();
}
