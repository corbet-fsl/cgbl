//! P9a: the per-member daily stamp budget is an invisible technical brake.
//!
//! Honest flows (pairing or restore with 50 communities) stay far below the
//! ceiling; the ceiling itself still applies at STAMP_MAX_PER_DAY.
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
    let policy = Policy {
        version: 1,
        scope: "global".into(),
        revision: 1,
        epoch: 1,
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
        .install_policy(&bytes, authority.key_ring().unwrap(), 100)
        .await
        .unwrap();
    global
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

async fn issue_one(
    global: &Facade,
    holder: &mut cpsd::OpaqueHolder,
    rng: &mut StdRng,
    who: &str,
    now: u64,
    seed: u8,
) -> Result<()> {
    let (nonce, public) = global.stamp_challenge(rng, &session(who), now).await?;
    let request = holder
        .begin_stamp(rng, &public, &nonce, &[action(seed)], now)
        .map_err(|_| Error::Challenge)?;
    let confirmation = request.confirmation_challenge(&nonce);
    let stamp = global
        .issue_stamp(rng, &session(who), &request, &nonce, confirmation, now)
        .await?;
    let epoch = global.stamp_epoch(now).await?;
    holder
        .finish_stamp(&stamp, epoch, now)
        .map_err(|_| Error::Passport)?;
    Ok(())
}

#[test]
fn stamp_ceiling_is_4096_per_utc_day() {
    assert_eq!(cgbl::STAMP_MAX_PER_DAY, 4096);
}

#[tokio::test(flavor = "multi_thread")]
async fn honest_pairing_or_restore_with_50_communities_stays_far_below_the_ceiling() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(90);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [61; 32]);
    enrolled(&global, &mut holder, "member", &mut rng).await;
    for i in 0..50u8 {
        issue_one(&global, &mut holder, &mut rng, "member", 100, i)
            .await
            .unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_ceiling_still_applies_at_4096() {
    let mut global = make().await;
    let mut rng = StdRng::seed_from_u64(91);
    global
        .attach_stamps(stamp_key(&mut rng), StampRate::default())
        .unwrap();
    let mut holder = cpsd::OpaqueHolder::from_seed(&mut [62; 32]);
    enrolled(&global, &mut holder, "member", &mut rng).await;
    for i in 0..cgbl::STAMP_MAX_PER_DAY {
        let seed = (i % 250) as u8;
        issue_one(&global, &mut holder, &mut rng, "member", 100, seed)
            .await
            .unwrap();
    }
    assert!(matches!(
        global
            .stamp_challenge(&mut rng, &session("member"), 100)
            .await,
        Err(Error::Capacity)
    ));
}
