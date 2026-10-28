//! Stamp edge behaviour: replay identity, window boundaries, ring recording,
//! holder binding and challenge capacity.
//!
//! Each test pins one behaviour of `Global`'s stamp surface that no other
//! test observes, so weakening the product code turns the test red.
use cgbl::{
    storage::{MemoryStore, Store},
    *,
};
use cpsd::rand::{SeedableRng, rngs::StdRng};

const DAY: u64 = 86_400;
const COHORT: u64 = 5 * DAY;

type Facade = Global<MemoryStore, csgn::MemoryStore, cpsd::MemoryStore>;

fn subject(id: &str) -> Subject {
    Subject::new(id).unwrap()
}
fn session(id: &str) -> Session {
    Session::authenticated(subject(id), [7; 32]).unwrap()
}
fn check() -> CheckId {
    CheckId::generate(&mut cpsd::rand::rngs::OsRng)
}
fn issuer() -> cpsd::IssuerKey {
    cpsd::IssuerKey::generate(
        &mut StdRng::seed_from_u64(1),
        cpsd::KeyId::new("key").unwrap(),
        vec![cpsd::GateId::new("phone").unwrap()],
    )
    .unwrap()
}
fn fingerprints() -> FingerprintKey {
    FingerprintKey::from_bytes(&mut [9; 32])
}
async fn make() -> Facade {
    let store = MemoryStore::new("global").unwrap();
    let keys = csgn::MemoryStore::default();
    let issuance = cpsd::MemoryStore::new(cpsd::CommunityId::new(b"global").unwrap(), 2).unwrap();
    let signer = csgn::PersistentSigner::create(
        keys.clone(),
        "cgbl:global",
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let global = Global::open(
        store,
        issuance,
        issuer(),
        signer,
        fingerprints(),
        Mode::Production,
        Limits {
            challenge_ttl: 60,
            pending_capacity: 100,
        },
    )
    .await
    .unwrap();
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    install(&global, &mut authority, 1, 1, 100).await.unwrap();
    global
}

async fn install(
    global: &Facade,
    authority: &mut csgn::PersistentSigner<csgn::MemoryStore>,
    revision: u64,
    epoch: u64,
    now: u64,
) -> Result<()> {
    let policy = Policy {
        version: 1,
        scope: "global".into(),
        revision,
        epoch,
        shared_expiry: COHORT,
        gates: vec![GatePolicy {
            gate: "phone".into(),
            provider: "sms".into(),
            uniqueness: true,
        }],
    };
    let bytes = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            0,
            COHORT + DAY,
        )
        .await
        .unwrap();
    global
        .install_policy(&bytes, authority.key_ring().unwrap(), now)
        .await
}

#[derive(Default)]
struct Provider;
impl GlobalGate for Provider {
    fn id(&self) -> &str {
        "phone"
    }
    fn provider(&self) -> &str {
        "sms"
    }
    fn development_only(&self) -> bool {
        false
    }
    async fn verify(&self, _: &CheckId, _: &Subject, input: &[u8], _: u64) -> Result<GateEvidence> {
        Ok(GateEvidence {
            valid_until: COHORT,
            uniqueness: Some(zeroize::Zeroizing::new(input.to_vec())),
        })
    }
}

async fn enrolled(global: &Facade, holder: &mut cpsd::OpaqueHolder, who: &str, rng: &mut StdRng) {
    global
        .run_gate(&Provider, &subject(who), b"unique", 100, &check())
        .await
        .unwrap();
    let challenge = global
        .challenge(rng, &session(who), 100, 150)
        .await
        .unwrap();
    let request = holder
        .begin_issuance(rng, global.issuer_public_key(), &challenge)
        .unwrap();
    let blind = global
        .issue(rng, &session(who), &challenge, &request, 100)
        .await
        .unwrap();
    holder.finish_issuance(&blind).unwrap();
}

fn stamp_key(rng: &mut StdRng) -> cpsd::StampIssuerKey {
    cpsd::StampIssuerKey::generate(
        rng,
        cpsd::KeyId::new("stamp").unwrap(),
        &cpsd::StampParams::new(DAY).unwrap(),
    )
    .unwrap()
}

fn action(seed: u8) -> (cpsd::StampScope, cpsd::StampAction) {
    let mut rng = StdRng::seed_from_u64(u64::from(seed));
    (
        cpsd::StampScope::new(
            cpsd::CommunityId::new("community-1").unwrap(),
            cpsd::CommunityFingerprint::from_bytes([1; 32]),
        ),
        cpsd::StampAction::new(
            cpsd::ActionKind::new("lineage.pair").unwrap(),
            cpsd::PayloadDigest::from_bytes([seed; 32]),
            cpsd::StampSalt::generate(&mut rng),
        ),
    )
}

/// Issue one stamp and keep every party: the nonce, the exact request bytes
/// and the blind stamp, plus the stamp public key the wallet advertised.
#[allow(clippy::type_complexity)]
async fn issue_first(
    global: &Facade,
    holder: &mut cpsd::OpaqueHolder,
    rng: &mut StdRng,
    who: &str,
    now: u64,
    seed: u8,
) -> (
    cpsd::IssuanceChallenge,
    cpsd::StampPublicKey,
    cpsd::StampIssuanceRequest,
    cpsd::BlindStamp,
) {
    let (nonce, public) = global
        .stamp_challenge(rng, &session(who), now)
        .await
        .unwrap();
    let request = holder
        .begin_stamp(rng, &public, &nonce, &[action(seed)], now)
        .unwrap();
    let confirmation = request.confirmation_challenge(&nonce);
    let stamp = global
        .issue_stamp(rng, &session(who), &request, &nonce, confirmation, now)
        .await
        .unwrap();
    let epoch = global.stamp_epoch(now).await.unwrap();
    holder.finish_stamp(&stamp, epoch, now).unwrap();
    (nonce, public, request, stamp)
}

#[tokio::test(flavor = "multi_thread")]
async fn stamp_public_key_is_none_before_attach_and_some_after() {
    let mut global = make().await;
    assert!(global.stamp_public_key().is_none());
    let mut rng = StdRng::seed_from_u64(510);
    let key = stamp_key(&mut rng);
    let expected = key.public_key().to_bytes();
    global.attach_stamps(key, StampRate::default()).unwrap();
    assert_eq!(
        global.stamp_public_key().map(|key| key.to_bytes()),
        Some(expected)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_rejects_a_replay_window_over_a_day() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(511);
    assert!(matches!(
        global.attach_stamps(
            stamp_key(&mut rng),
            StampRate {
                replay_seconds: DAY + 1
            }
        ),
        Err(Error::Capacity)
    ));
    assert!(
        global
            .attach_stamps(
                stamp_key(&mut rng),
                StampRate {
                    replay_seconds: DAY
                }
            )
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn exact_replay_returns_the_same_stamp_without_a_new_confirmation() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(512);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [61; 32]);
    enrolled(&global, &mut holder, "member", &mut rng).await;
    let (_, _, request, stamp) =
        issue_first(&global, &mut holder, &mut rng, "member", 100, 1).await;
    for now in [100, 699] {
        let again = global
            .replay_stamp(&session("member"), &request, now)
            .await
            .unwrap();
        assert_eq!(again.map(|blind| blind.to_bytes()), Some(stamp.to_bytes()));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_different_request_never_replays() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(513);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [61; 32]);
    enrolled(&global, &mut holder, "member", &mut rng).await;
    let (nonce, public, _, _) = issue_first(&global, &mut holder, &mut rng, "member", 100, 1).await;
    // Same nonce, different action: different request bytes, never issued.
    let other = holder
        .begin_stamp(&mut rng, &public, &nonce, &[action(2)], 100)
        .unwrap();
    assert!(
        global
            .replay_stamp(&session("member"), &other, 100)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn replay_ends_when_the_window_closes() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(514);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [61; 32]);
    enrolled(&global, &mut holder, "member", &mut rng).await;
    // Default replay window is 600 s: the reply kept at 100 ends at 700,
    // exclusive. Both the closing tick and every later tick replay nothing.
    let (_, _, request, _) = issue_first(&global, &mut holder, &mut rng, "member", 100, 1).await;
    for now in [700, 701, 1000] {
        assert!(
            global
                .replay_stamp(&session("member"), &request, now)
                .await
                .unwrap()
                .is_none(),
            "replay at {now} must be refused"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_replay_answers_none_without_touching_accounts() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(515);
    let key = stamp_key(&mut rng);
    let public = key.public_key().clone();
    global
        .attach_stamps(key, StampRate { replay_seconds: 0 })
        .unwrap();
    // "ghost" was never enrolled: with replay disabled the wallet answers
    // None before it looks at any account.
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [63; 32]);
    let nonce = cpsd::IssuanceChallenge::generate(&mut rng);
    let request = holder
        .begin_stamp(&mut rng, &public, &nonce, &[action(3)], 100)
        .unwrap();
    assert!(
        global
            .replay_stamp(&session("ghost"), &request, 100)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stamp_epoch_is_the_signed_status_epoch() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(516);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    assert_eq!(global.stamp_epoch(100).await.unwrap(), 1);
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    install(&global, &mut authority, 2, 2, 180).await.unwrap();
    assert_eq!(global.stamp_epoch(200).await.unwrap(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn issued_stamp_key_is_recorded_in_the_signed_status_ring() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(517);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [61; 32]);
    enrolled(&global, &mut holder, "member", &mut rng).await;
    issue_first(&global, &mut holder, &mut rng, "member", 100, 1).await;
    let expected = global.stamp_public_key().unwrap().to_bytes();
    let signed = global.signed_status(150, 2 * DAY).await.unwrap();
    let status = Status::verify(&signed, global.key_ring().unwrap(), "global", 1, 1, 150).unwrap();
    assert_eq!(
        status.stamp_public_key.as_deref(),
        Some(expected.as_slice())
    );
    assert_eq!(status.stamp_keys.len(), 1);
    assert_eq!(status.stamp_keys[0].public_key, expected);
    assert_eq!(
        (
            status.stamp_keys[0].valid_from,
            status.stamp_keys[0].valid_until
        ),
        (100, None)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn attached_key_is_recorded_even_before_the_first_stamp() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(518);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    let expected = global.stamp_public_key().unwrap().to_bytes();
    let signed = global.signed_status(100, 2 * DAY).await.unwrap();
    let status = Status::verify(&signed, global.key_ring().unwrap(), "global", 1, 1, 150).unwrap();
    assert_eq!(status.stamp_keys.len(), 1);
    assert_eq!(status.stamp_keys[0].public_key, expected);
    assert_eq!(
        (
            status.stamp_keys[0].valid_from,
            status.stamp_keys[0].valid_until
        ),
        (100, None)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stamp_for_another_holders_secret_is_a_holder_change() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(519);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    // The passport is bound to the first holder's secret ...
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [61; 32]);
    enrolled(&global, &mut holder, "member", &mut rng).await;
    // ... so a request built from a different secret is refused as a holder
    // change, not as a generic passport failure.
    let mut stranger = cpsd::OpaqueHolder::from_seed(&mut [64; 32]);
    let (nonce, public) = global
        .stamp_challenge(&mut rng, &session("member"), 100)
        .await
        .unwrap();
    let request = stranger
        .begin_stamp(&mut rng, &public, &nonce, &[action(4)], 100)
        .unwrap();
    let confirmation = request.confirmation_challenge(&nonce);
    assert!(matches!(
        global
            .issue_stamp(
                &mut rng,
                &session("member"),
                &request,
                &nonce,
                confirmation,
                100
            )
            .await,
        Err(Error::HolderChanged)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wrong_confirmation_is_a_challenge_refusal() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(520);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [61; 32]);
    enrolled(&global, &mut holder, "member", &mut rng).await;
    let (nonce, public) = global
        .stamp_challenge(&mut rng, &session("member"), 100)
        .await
        .unwrap();
    let request = holder
        .begin_stamp(&mut rng, &public, &nonce, &[action(5)], 100)
        .unwrap();
    // The user verification covered another challenge, not this request.
    assert!(matches!(
        global
            .issue_stamp(&mut rng, &session("member"), &request, &nonce, [9; 32], 100)
            .await,
        Err(Error::Challenge)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn only_two_stamp_challenges_stay_outstanding() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(521);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [61; 32]);
    enrolled(&global, &mut holder, "member", &mut rng).await;
    // The issuance store holds two outstanding challenges: the third
    // reservation is refused as capacity, never as a generic failure.
    global
        .stamp_challenge(&mut rng, &session("member"), 100)
        .await
        .unwrap();
    global
        .stamp_challenge(&mut rng, &session("member"), 100)
        .await
        .unwrap();
    assert!(matches!(
        global
            .stamp_challenge(&mut rng, &session("member"), 100)
            .await,
        Err(Error::Capacity)
    ));
}
