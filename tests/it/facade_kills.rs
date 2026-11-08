//! Focused mutation-kill tests for the `src/facade.rs` survivors (mut133).
//!
//! Every test below runs under default features (no `development-gate`),
//! so the prescribed `cargo mutants --file src/facade.rs` run executes them.
//! Tests only; no product code is touched.
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
fn issuer_for(seed: u64, gates: &[&str]) -> cpsd::IssuerKey {
    cpsd::IssuerKey::generate(
        &mut StdRng::seed_from_u64(seed),
        cpsd::KeyId::new("shared-key").unwrap(),
        gates
            .iter()
            .map(|s| cpsd::GateId::new(*s).unwrap())
            .collect(),
    )
    .unwrap()
}
fn fingerprints() -> FingerprintKey {
    FingerprintKey::from_bytes(&mut [9; 32])
}
async fn open_memory(
    scope: &str,
    ttl: u64,
    cap: u32,
    issuer: cpsd::IssuerKey,
) -> (Facade, MemoryStore) {
    let store = MemoryStore::new(scope).unwrap();
    let keys = csgn::MemoryStore::default();
    let signer = csgn::PersistentSigner::create(
        keys,
        format!("cgbl:{scope}"),
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let global = Global::open(
        store.clone(),
        cpsd::MemoryStore::new(cpsd::CommunityId::new(scope.as_bytes()).unwrap(), 20).unwrap(),
        issuer,
        signer,
        fingerprints(),
        Mode::Production,
        Limits {
            challenge_ttl: ttl,
            pending_capacity: cap,
        },
    )
    .await
    .unwrap();
    (global, store)
}
async fn authority() -> csgn::PersistentSigner<csgn::MemoryStore> {
    csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "global-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap()
}
fn base_policy(scope: &str, revision: u64, epoch: u64, expiry: u64) -> Policy {
    Policy {
        version: 1,
        scope: scope.into(),
        revision,
        epoch,
        shared_expiry: expiry,
        gates: vec![GatePolicy {
            gate: "phone".into(),
            provider: "sms".into(),
            uniqueness: true,
        }],
    }
}
async fn install_signed<S: Store, K: csgn::Store, I: cpsd::IssuanceStore>(
    global: &Global<S, K, I>,
    authority: &mut csgn::PersistentSigner<csgn::MemoryStore>,
    policy: &Policy,
    now: u64,
    valid_until: u64,
) -> Result<()> {
    let bytes = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(policy).unwrap(),
            now / DAY * DAY,
            valid_until,
        )
        .await
        .unwrap();
    global
        .install_policy(&bytes, authority.key_ring().unwrap(), now)
        .await
}
async fn install<S: Store, K: csgn::Store, I: cpsd::IssuanceStore>(
    global: &Global<S, K, I>,
    policy: &Policy,
    now: u64,
) -> Result<()> {
    install_signed(
        global,
        &mut authority().await,
        policy,
        now,
        policy.shared_expiry + DAY,
    )
    .await
}
/// External provider fixture: fixed validity, keeps the raw input.
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
            valid_until: COHORT + 37,
            uniqueness: Some(zeroize::Zeroizing::new(input.to_vec())),
        })
    }
}
/// Same wire shape as [`Provider`] but with caller-chosen evidence expiry.
struct FixedGate {
    valid_until: u64,
}
impl GlobalGate for FixedGate {
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
            valid_until: self.valid_until,
            uniqueness: Some(zeroize::Zeroizing::new(input.to_vec())),
        })
    }
}
struct MailGate;
impl GlobalGate for MailGate {
    fn id(&self) -> &str {
        "mail"
    }
    fn provider(&self) -> &str {
        "post"
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
async fn proven_person<S: Store, K: csgn::Store, I: cpsd::IssuanceStore>(
    global: &Global<S, K, I>,
    who: &str,
) {
    global
        .run_gate(
            &Provider,
            &subject(who),
            format!("unique-{who}").as_bytes(),
            100,
            &check(),
        )
        .await
        .unwrap();
}

// ---- Global::open (facade.rs:105, 125) ----

#[tokio::test]
async fn production_open_rejects_an_issuer_with_the_development_gate() {
    let keys = csgn::MemoryStore::default();
    let signer = csgn::PersistentSigner::create(
        keys,
        "cgbl:gate105",
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    // `mode == Mode::Production` with `!=` would skip this fence and open.
    assert!(matches!(
        Global::open(
            MemoryStore::new("gate105").unwrap(),
            cpsd::MemoryStore::new(cpsd::CommunityId::new(b"gate105").unwrap(), 5).unwrap(),
            issuer_for(1, &["development"]),
            signer,
            fingerprints(),
            Mode::Production,
            Limits {
                challenge_ttl: 60,
                pending_capacity: 5
            },
        )
        .await,
        Err(Error::DevelopmentDisabled)
    ));
}

#[tokio::test]
async fn reopening_with_a_rotated_issuer_key_is_a_key_mismatch() {
    let scope = "gate125";
    let store = MemoryStore::new(scope).unwrap();
    let keys = csgn::MemoryStore::default();
    let issuance =
        cpsd::MemoryStore::new(cpsd::CommunityId::new(scope.as_bytes()).unwrap(), 5).unwrap();
    let signer = csgn::PersistentSigner::create(
        keys.clone(),
        format!("cgbl:{scope}"),
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    Global::open(
        store.clone(),
        issuance.clone(),
        issuer_for(1, &["phone"]),
        signer,
        fingerprints(),
        Mode::Production,
        Limits {
            challenge_ttl: 60,
            pending_capacity: 5,
        },
    )
    .await
    .unwrap();
    // A rotated issuer must be refused: the `saved != binding` guard replaced
    // with `false` would accept it and open successfully.
    let signer_name = format!("cgbl:{scope}");
    let signer = csgn::PersistentSigner::open(
        keys,
        signer_name.as_str(),
        csgn::SecretKey::from_seed(&mut [2; 32]),
        10,
    )
    .await
    .unwrap();
    assert!(matches!(
        Global::open(
            store.clone(),
            issuance.clone(),
            issuer_for(2, &["phone"]),
            signer,
            fingerprints(),
            Mode::Production,
            Limits {
                challenge_ttl: 60,
                pending_capacity: 5
            },
        )
        .await,
        Err(Error::KeyMismatch)
    ));
}

// ---- install_policy bounds (facade.rs:183-211) ----

#[tokio::test]
async fn policy_at_the_exact_shared_expiry_tick_is_still_current() {
    // `shared_expiry < now` with `<=` would refuse the boundary tick.
    let (global, _) = open_memory("exp183", 60, 5, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("exp183", 1, 1, COHORT), COHORT)
        .await
        .unwrap();
    assert!(matches!(
        install(&global, &base_policy("exp183", 2, 2, COHORT), COHORT + 1).await,
        Err(Error::Policy)
    ));
}

#[tokio::test]
async fn empty_gate_catalogue_is_refused() {
    // Kills the `||` -> `&&` mutants on the empty/len/uniqueness rows: any one
    // of them with `&&` would accept this policy.
    let (global, _) = open_memory("exp185", 60, 5, issuer_for(1, &["phone"])).await;
    let mut policy = base_policy("exp185", 1, 1, COHORT);
    policy.gates.clear();
    assert!(matches!(
        install(&global, &policy, 10).await,
        Err(Error::Policy)
    ));
}

#[tokio::test]
async fn policy_whose_authority_window_ends_at_expiry_is_refused() {
    // shared_expiry >= valid_until with equality: the expiry row's `||` ->
    // `&&` mutant joins it with the empty-catalogue row and would accept this
    // policy (valid gates, so the rest of the chain is clean).
    let (global, _) = open_memory("exp184", 60, 5, issuer_for(1, &["phone"])).await;
    let mut authority = authority().await;
    assert!(matches!(
        install_signed(
            &global,
            &mut authority,
            &base_policy("exp184", 1, 1, COHORT),
            10,
            COHORT
        )
        .await,
        Err(Error::Policy)
    ));
}

#[tokio::test]
async fn policy_for_another_scope_is_refused() {
    // The revision/epoch-style `||` -> `&&` mutants join an early fence with
    // the later gate rows: with `&&` a single-true side installs. A wrong
    // scope (early true, gate rows clean) kills the mutants at the empty,
    // length and uniqueness rows alike.
    let (global, _) = open_memory("exp186x", 60, 5, issuer_for(1, &["phone"])).await;
    assert!(matches!(
        install(&global, &base_policy("another-scope", 1, 1, COHORT), 10).await,
        Err(Error::Policy)
    ));
}

#[tokio::test]
async fn sixty_five_gates_are_refused_but_sixty_four_install() {
    let gate_names: Vec<String> = (0..64).map(|i| format!("g{i:02}")).collect();
    let gate_refs: Vec<&str> = gate_names.iter().map(String::as_str).collect();
    let (global, _) = open_memory("exp186", 60, 5, issuer_for(1, &gate_refs)).await;
    // Exactly MAX_GATES installs: `len > MAX_GATES` with `>=` would refuse it.
    let mut ok = base_policy("exp186", 1, 1, COHORT);
    ok.gates = gate_names
        .iter()
        .map(|g| GatePolicy {
            gate: g.clone(),
            provider: "sms".into(),
            uniqueness: true,
        })
        .collect();
    install(&global, &ok, 10).await.unwrap();
    // One more gate is refused (`>` with `==` would accept it at this line;
    // the issuer loop refuses it too, so this pins the boundary only).
    let mut too_many = base_policy("exp186", 2, 2, COHORT);
    too_many.gates = (0..65)
        .map(|i| GatePolicy {
            gate: format!("g{i:02}"),
            provider: "sms".into(),
            uniqueness: true,
        })
        .collect();
    assert!(matches!(
        install(&global, &too_many, 11).await,
        Err(Error::Policy)
    ));
}

#[tokio::test]
async fn gate_catalogue_without_uniqueness_is_refused() {
    // Kills the uniqueness-row `||` -> `&&`: with `&&` this installs.
    let (global, _) = open_memory("exp187", 60, 5, issuer_for(1, &["phone"])).await;
    let mut policy = base_policy("exp187", 1, 1, COHORT);
    policy.gates[0].uniqueness = false;
    assert!(matches!(
        install(&global, &policy, 10).await,
        Err(Error::Policy)
    ));
}

#[tokio::test]
async fn duplicate_gate_ids_are_refused_even_when_the_issuer_lists_them() {
    // Kills the duplicate/unknown `||` -> `&&`: with `&&` the duplicate case
    // installs (the unknown case still dies in the issuer loop: pin only).
    let (global, _) = open_memory("exp196", 60, 5, issuer_for(1, &["phone"])).await;
    let mut policy = base_policy("exp196", 2, 1, COHORT);
    policy.gates.push(policy.gates[0].clone());
    assert!(matches!(
        install(&global, &policy, 10).await,
        Err(Error::Policy)
    ));
    let mut unknown = base_policy("exp196", 2, 1, COHORT);
    unknown.gates[0].gate = "unknown".into();
    assert!(matches!(
        install(&global, &unknown, 10).await,
        Err(Error::Policy)
    ));
}

#[tokio::test]
async fn policy_revision_and_epoch_advance_by_exactly_one() {
    // Kills the revision/epoch `||` -> `&&`: with `&&` each invalid advance
    // below would install.
    let (global, _) = open_memory("exp211", 60, 5, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("exp211", 1, 1, COHORT), 10)
        .await
        .unwrap();
    for (revision, epoch) in [(1, 2), (2, 1), (2, 3)] {
        assert!(
            matches!(
                install(&global, &base_policy("exp211", revision, epoch, COHORT), 11).await,
                Err(Error::Policy)
            ),
            "revision {revision} epoch {epoch} must be refused"
        );
    }
    install(&global, &base_policy("exp211", 2, 2, COHORT), 11)
        .await
        .unwrap();
}

// ---- run_gate (facade.rs:305, 356) ----

#[tokio::test]
async fn provider_evidence_below_the_floor_tick_is_refused() {
    // Rounded validity 0 < now 100: `<` with `==` would let it through.
    let (global, _) = open_memory("gate305", 60, 5, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("gate305", 1, 1, COHORT), 10)
        .await
        .unwrap();
    assert!(matches!(
        global
            .run_gate(
                &FixedGate { valid_until: 100 },
                &subject("member"),
                b"input",
                100,
                &check()
            )
            .await,
        Err(Error::Gates)
    ));
}

#[tokio::test]
async fn provider_evidence_exactly_on_the_floor_tick_passes() {
    // Rounded validity DAY == now DAY: `<` with `<=` would refuse it.
    let (global, _) = open_memory("gate305b", 60, 5, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("gate305b", 1, 1, COHORT), 10)
        .await
        .unwrap();
    let result = global
        .run_gate(
            &FixedGate {
                valid_until: DAY + 50,
            },
            &subject("member"),
            b"input",
            DAY,
            &check(),
        )
        .await
        .unwrap();
    assert_eq!(result.valid_until, DAY);
}

#[tokio::test]
async fn retired_gates_leave_the_person_record() {
    // `retain(... == id)` with `!=` would keep the retired phone gate.
    let scope = "gate356";
    let (global, store) = open_memory(scope, 60, 5, issuer_for(1, &["phone", "mail"])).await;
    install(&global, &base_policy(scope, 1, 1, COHORT), 10)
        .await
        .unwrap();
    global
        .run_gate(&Provider, &subject("member"), b"phone-input", 100, &check())
        .await
        .unwrap();
    let mut v2 = base_policy(scope, 2, 2, COHORT);
    v2.gates = vec![GatePolicy {
        gate: "mail".into(),
        provider: "post".into(),
        uniqueness: true,
    }];
    install(&global, &v2, 200).await.unwrap();
    global
        .run_gate(&MailGate, &subject("member"), b"mail-input", 200, &check())
        .await
        .unwrap();
    let key = cgbl::storage::Key::new("account", "member");
    let read = store.read(std::slice::from_ref(&key)).await.unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&read.records[&key].value).unwrap();
    for field in ["gates", "check_ids", "check_inputs"] {
        let keys: Vec<&String> = saved[field].as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            vec![&"mail".to_string()],
            "{field} must drop the retired gate"
        );
    }
}

// ---- challenge bounds (facade.rs:429, 441) ----

#[tokio::test]
async fn challenge_deadline_beyond_ttl_is_refused_but_exact_ttl_passes() {
    let (global, _) = open_memory("chal429", 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("chal429", 1, 1, COHORT), 10)
        .await
        .unwrap();
    proven_person(&global, "alice").await;
    let mut rng = StdRng::seed_from_u64(429);
    // deadline - now = 61 > 60: `-` with `/` and `>` with `==` accept it.
    assert!(matches!(
        global
            .challenge(&mut rng, &session("alice"), 100, 161)
            .await,
        Err(Error::InvalidTime)
    ));
    // deadline - now = 60 == ttl: `>` with `>=` would refuse it.
    global
        .challenge(&mut rng, &session("alice"), 100, 160)
        .await
        .unwrap();
}

#[tokio::test]
async fn challenge_deadline_at_shared_expiry_is_accepted() {
    // `deadline > shared_expiry` with `>=` would refuse the boundary.
    let (global, _) = open_memory("chal441", 10 * DAY, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("chal441", 1, 1, 2 * DAY), 100)
        .await
        .unwrap();
    proven_person(&global, "alice").await;
    let mut rng = StdRng::seed_from_u64(441);
    global
        .challenge(&mut rng, &session("alice"), 100, 2 * DAY)
        .await
        .unwrap();
}

// ---- challenge mid-call reservation fence (facade.rs:516-519) ----

fn libsql_migrations() -> Vec<crlt::Migration<'static>> {
    vec![
        crlt::Migration::new(1, "global", cgbl::storage::SCHEMA),
        crlt::Migration::new(2, "signing", csgn::SCHEMA),
        crlt::Migration::new(3, "challenges", cpsd::storage::libsql::SCHEMA),
        crlt::Migration::new(
            4,
            "issuer continuity",
            cpsd::storage::libsql::ISSUANCE_SCHEMA,
        ),
        crlt::Migration::new(
            5,
            "unique holders",
            cpsd::storage::libsql::ISSUANCE_UNIQUENESS_SCHEMA,
        ),
    ]
}
fn libsql_leaf(db: &crlt::Db, scope: &str) -> cpsd::storage::libsql::LibsqlStore {
    cpsd::storage::libsql::LibsqlStore::new(
        db,
        cpsd::CommunityId::new(scope.as_bytes()).unwrap(),
        20,
    )
    .unwrap()
}
async fn libsql_global(
    scope: &str,
) -> (
    Global<cgbl::storage::LibsqlStore, csgn::MemoryStore, cpsd::storage::libsql::LibsqlStore>,
    tempfile::TempDir,
    String,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fence.db");
    let db = crlt::Db::open(crlt::Config::new(format!("file://{}", path.display()), ""))
        .await
        .unwrap();
    db.migrate(&libsql_migrations()).await.unwrap();
    let store = cgbl::storage::LibsqlStore::new(&db, scope).unwrap();
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        format!("cgbl:{scope}"),
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let global = Global::open(
        store,
        libsql_leaf(&db, scope),
        issuer_for(1, &["phone"]),
        signer,
        fingerprints(),
        Mode::Production,
        Limits {
            challenge_ttl: 60,
            pending_capacity: 8,
        },
    )
    .await
    .unwrap();
    let mut authority = authority().await;
    install_signed(
        &global,
        &mut authority,
        &base_policy(scope, 1, 1, COHORT),
        100,
        COHORT + DAY,
    )
    .await
    .unwrap();
    global
        .run_gate(&Provider, &subject("alice"), b"unique-alice", 100, &check())
        .await
        .unwrap();
    let url = format!("file://{}", path.display());
    (global, dir, url)
}
async fn challenge_with_tampered_pending(field: &str, value: String) {
    let scope = format!("fence-{field}");
    let (global, _dir, url) = libsql_global(&scope).await;
    let raw_db =
        libsql::Builder::new_local(std::path::Path::new(url.trim_start_matches("file://")))
            .build()
            .await
            .unwrap();
    let raw = raw_db.connect().unwrap();
    raw.execute_batch(&format!(
        "CREATE TRIGGER tamper_pending AFTER INSERT ON cpsd_challenges BEGIN \
         UPDATE cgbl_record SET value = CAST(json_set(CAST(value AS TEXT), '$.{field}', {value}) AS BLOB), \
         revision = revision + 1 WHERE community_id = '{scope}' AND bucket = 'challenge' AND entry_key = 'alice'; END;"
    ))
    .await
    .unwrap();
    let mut rng = StdRng::seed_from_u64(516);
    // Exactly one reservation check fails: each `||` -> `&&` mutant joins two
    // checks and would let its single-true side through (then Ok).
    assert!(
        matches!(
            global
                .challenge(&mut rng, &session("alice"), 100, 150)
                .await,
            Err(Error::Challenge)
        ),
        "tampered pending.{field} must refuse the challenge"
    );
}

#[tokio::test]
async fn tampered_pending_epoch_refuses_the_challenge() {
    challenge_with_tampered_pending("epoch", "99".to_owned()).await;
}

#[tokio::test]
async fn tampered_pending_session_refuses_the_challenge() {
    let zeros = serde_json::to_string(&[0u8; 32]).unwrap();
    challenge_with_tampered_pending("session", format!("json('{zeros}')")).await;
}

#[tokio::test]
async fn tampered_pending_deadline_refuses_the_challenge() {
    challenge_with_tampered_pending("deadline", "149".to_owned()).await;
}

#[tokio::test]
async fn tampered_pending_nonce_refuses_the_challenge() {
    let eights = serde_json::to_string(&[8u8; 32]).unwrap();
    challenge_with_tampered_pending("nonce", format!("json('{eights}')")).await;
}

// ---- issue_with_deadline_guard (facade.rs:571, 573, 617) ----

async fn challenged<S: Store, K: csgn::Store, I: cpsd::IssuanceStore>(
    global: &Global<S, K, I>,
    rng: &mut StdRng,
    who: &str,
    now: u64,
    deadline: u64,
) -> IssuanceChallenge {
    global
        .challenge(rng, &session(who), now, deadline)
        .await
        .unwrap()
}

#[tokio::test]
async fn issuance_guard_is_not_observed_for_a_wrong_session_or_nonce() {
    let (global, _) = open_memory("guard571", 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("guard571", 1, 1, COHORT), 10)
        .await
        .unwrap();
    proven_person(&global, "alice").await;
    let mut rng = StdRng::seed_from_u64(571);
    let challenge = challenged(&global, &mut rng, "alice", 100, 150).await;
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let (request, _) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
    let wrong_nonce = IssuanceChallenge::generate(&mut rng);
    // Same challenge, other session id: only the session check fails, so the
    // `||` -> `&&` mutant joining it with the nonce check proceeds.
    let other_session = Session::authenticated(subject("alice"), [8; 32]).unwrap();
    let alice_session = session("alice");
    for (auth, nonce) in [(&other_session, &challenge), (&alice_session, &wrong_nonce)] {
        let calls = std::cell::Cell::new(0);
        let result = global
            .issue_with_deadline_guard(&mut rng, auth, nonce, &request, 100, |_| {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .await;
        assert!(matches!(result, Err(Error::Challenge)));
        assert_eq!(calls.get(), 0, "guard must not observe a refused binding");
    }
}

#[tokio::test]
async fn issuance_guard_is_not_observed_past_the_inclusive_deadline() {
    let (global, _) = open_memory("guard573a", 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("guard573a", 1, 1, COHORT), 10)
        .await
        .unwrap();
    proven_person(&global, "alice").await;
    let mut rng = StdRng::seed_from_u64(573);
    let challenge = challenged(&global, &mut rng, "alice", 100, 150).await;
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let (request, _) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
    // now = deadline + 1: `now > deadline` with `==` would proceed.
    let calls = std::cell::Cell::new(0);
    let result = global
        .issue_with_deadline_guard(
            &mut rng,
            &session("alice"),
            &challenge,
            &request,
            151,
            |_| {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )
        .await;
    assert!(matches!(result, Err(Error::Challenge)));
    assert_eq!(calls.get(), 0, "guard must not observe an expired deadline");
}

#[tokio::test]
async fn issuance_guard_observes_the_inclusive_deadline_tick() {
    // now == deadline is accepted: `now > deadline` with `>=` would refuse it.
    let (global, _) = open_memory("guard573b", 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("guard573b", 1, 1, COHORT), 10)
        .await
        .unwrap();
    proven_person(&global, "alice").await;
    let mut rng = StdRng::seed_from_u64(574);
    let challenge = challenged(&global, &mut rng, "alice", 100, 150).await;
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let (request, pending) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
    let calls = std::cell::Cell::new(0);
    let blind = global
        .issue_with_deadline_guard(
            &mut rng,
            &session("alice"),
            &challenge,
            &request,
            150,
            |deadline| {
                calls.set(calls.get() + 1);
                assert_eq!(deadline.inclusive(), 150);
                Ok(())
            },
        )
        .await
        .unwrap();
    assert_eq!(calls.get(), 1);
    pending.finish(&blind).unwrap();
    // A consumed challenge cannot issue twice: cpsd reports the conflict and
    // it surfaces as Challenge (deleting that passport_error arm would
    // surface Passport instead).
    assert!(matches!(
        global
            .issue(&mut rng, &session("alice"), &challenge, &request, 150)
            .await,
        Err(Error::Challenge)
    ));
}

#[tokio::test]
async fn replaying_a_consumed_challenge_maps_to_challenge() {
    // A retry supersedes the outstanding challenge at once: the older one is
    // refused at issuance. Completing a second challenge and then issuing
    // with the consumed first one reaches cpsd's conflict (the facade fence
    // still matches), surfacing Challenge. Deleting that passport_error arm
    // would surface Passport instead.
    let scope = "map878b";
    let (global, _dir, url) = libsql_global(scope).await;
    let mut rng = StdRng::seed_from_u64(878);
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let first = global
        .challenge(&mut rng, &session("alice"), 100, 150)
        .await
        .unwrap();
    let (request, pending) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &first).unwrap();
    let blind = global
        .issue(&mut rng, &session("alice"), &first, &request, 100)
        .await
        .unwrap();
    pending.finish(&blind).unwrap();
    // A superseding challenge, whose stored nonce is rewound to the consumed
    // first challenge via one-shot SQL: the facade fence matches, cpsd
    // refuses the replay.
    let _second = global
        .challenge(&mut rng, &session("alice"), 101, 160)
        .await
        .unwrap();
    let raw_db =
        libsql::Builder::new_local(std::path::Path::new(url.trim_start_matches("file://")))
            .build()
            .await
            .unwrap();
    let raw = raw_db.connect().unwrap();
    let first_bytes = serde_json::to_string(&first.to_bytes()).unwrap();
    raw.execute_batch(&format!(
        "UPDATE cgbl_record SET value = CAST(json_set(CAST(value AS TEXT), '$.nonce', json('{first_bytes}')) AS BLOB), \
         revision = revision + 1 WHERE community_id = '{scope}' AND bucket = 'challenge' AND entry_key = 'alice';"
    ))
    .await
    .unwrap();
    assert!(matches!(
        global
            .issue(&mut rng, &session("alice"), &first, &request, 101)
            .await,
        Err(Error::Challenge)
    ));
}

// ---- cpsd error mapping extras (facade.rs:878-880) ----

#[tokio::test]
async fn full_challenge_store_maps_to_capacity() {
    // Deleting the StorageCapacity arm would surface Error::Passport.
    let scope = "map879";
    let store = MemoryStore::new(scope).unwrap();
    let keys = csgn::MemoryStore::default();
    let signer = csgn::PersistentSigner::create(
        keys,
        format!("cgbl:{scope}"),
        csgn::SecretKey::from_seed(&mut [2; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let global = Global::open(
        store,
        cpsd::MemoryStore::new(cpsd::CommunityId::new(scope.as_bytes()).unwrap(), 1).unwrap(),
        issuer_for(1, &["phone"]),
        signer,
        fingerprints(),
        Mode::Production,
        Limits {
            challenge_ttl: 60,
            pending_capacity: 8,
        },
    )
    .await
    .unwrap();
    install(&global, &base_policy(scope, 1, 1, COHORT), 10)
        .await
        .unwrap();
    proven_person(&global, "alice").await;
    proven_person(&global, "bob").await;
    let mut rng = StdRng::seed_from_u64(879);
    global
        .challenge(&mut rng, &session("alice"), 100, 150)
        .await
        .unwrap();
    assert!(matches!(
        global.challenge(&mut rng, &session("bob"), 100, 150).await,
        Err(Error::Capacity)
    ));
}

#[tokio::test]
async fn broken_challenge_store_maps_to_storage() {
    // Deleting the Storage arm would surface Error::Passport.
    let scope = "map880";
    let (global, _dir, url) = libsql_global(scope).await;
    let raw_db =
        libsql::Builder::new_local(std::path::Path::new(url.trim_start_matches("file://")))
            .build()
            .await
            .unwrap();
    raw_db
        .connect()
        .unwrap()
        .execute_batch("DROP TABLE cpsd_challenges")
        .await
        .unwrap();
    let mut rng = StdRng::seed_from_u64(880);
    assert!(matches!(
        global
            .challenge(&mut rng, &session("alice"), 100, 150)
            .await,
        Err(Error::Storage)
    ));
}

// ---- revocations / prune limits (facade.rs:672, 684) ----

#[tokio::test]
async fn revocation_and_prune_limits_accept_exactly_one_thousand() {
    // `limit > 1000` with `>=` would refuse the boundary.
    let (global, _) = open_memory("lim1000", 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("lim1000", 1, 1, COHORT), 10)
        .await
        .unwrap();
    assert!(global.revocations("", 1000).await.unwrap().is_empty());
    assert_eq!(global.prune_challenges(100, 1000).await.unwrap(), 0);
    assert!(matches!(
        global.revocations("", 1001).await,
        Err(Error::Capacity)
    ));
    assert!(matches!(
        global.revocations("", 0).await,
        Err(Error::Capacity)
    ));
    assert!(matches!(
        global.prune_challenges(100, 1001).await,
        Err(Error::Capacity)
    ));
    assert!(matches!(
        global.prune_challenges(100, 0).await,
        Err(Error::Capacity)
    ));
}

// ---- public_status cache (facade.rs:741) ----

#[tokio::test]
async fn public_status_after_rotation_reuses_the_unchanged_snapshot() {
    // A rotation changes neither epoch, revision nor shared expiry, and the
    // retired key still verifies: the cached snapshot must be served
    // byte-identically. `==` with `!=` on any of those three clauses would
    // re-sign with the new key instead.
    let scope = "stat741";
    let (mut global, _) = open_memory(scope, 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy(scope, 1, 1, COHORT), 10)
        .await
        .unwrap();
    let first = global.public_status(100, 2 * DAY).await.unwrap();
    // Rotate strictly before the snapshot's expiry so the retired key is
    // retained and the cached snapshot still verifies.
    global
        .rotate_signing_key(csgn::SecretKey::from_seed(&mut [4; 32]), DAY + 100)
        .await
        .unwrap();
    let second = global.public_status(DAY + 200, 2 * DAY).await.unwrap();
    assert_eq!(second, first);
    Status::verify(&second, global.key_ring().unwrap(), scope, 1, 1, DAY + 200).unwrap();
}

// ---- signed_status / rotate (facade.rs:785, 812, 813) ----

#[tokio::test]
async fn signed_status_issues_at_the_utc_day_floor() {
    // `now / DAY * DAY` with `/` in place of `*` would issue at 1970-01-01.
    let scope = "stat785";
    let (mut global, _) = open_memory(scope, 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy(scope, 1, 1, COHORT), 10)
        .await
        .unwrap();
    let signed = global.signed_status(2 * DAY + 500, 4 * DAY).await.unwrap();
    let verified = global
        .key_ring()
        .unwrap()
        .verify(&signed, csgn::Kind::SettingsSnapshot, 2 * DAY + 500)
        .unwrap();
    assert_eq!(verified.issued_at(), 2 * DAY);
    assert_eq!(verified.valid_until(), 4 * DAY);
}

#[tokio::test]
async fn rotate_signing_key_moves_the_active_key_to_the_day_floor() {
    // Deleting the body (replace with Ok) or perturbing `now / DAY * DAY`
    // would leave the old key active or activate at the wrong timestamp.
    let scope = "rot812";
    let (mut global, _) = open_memory(scope, 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy(scope, 1, 1, COHORT), 10)
        .await
        .unwrap();
    let before = global.key_ring().unwrap().active().unwrap().activated_at();
    assert_eq!(before, 0);
    let first = global.signed_status(100, 2 * DAY).await.unwrap();
    Status::verify(&first, global.key_ring().unwrap(), scope, 1, 1, 150).unwrap();
    global
        .rotate_signing_key(csgn::SecretKey::from_seed(&mut [4; 32]), 2 * DAY + 500)
        .await
        .unwrap();
    assert_eq!(
        global.key_ring().unwrap().active().unwrap().activated_at(),
        2 * DAY
    );
    // New snapshots verify under the rotated ring.
    let second = global.signed_status(2 * DAY + 600, 4 * DAY).await.unwrap();
    Status::verify(
        &second,
        global.key_ring().unwrap(),
        scope,
        1,
        1,
        2 * DAY + 600,
    )
    .unwrap();
}

// ---- Status::verify minima (facade.rs:840) ----

#[tokio::test]
async fn status_verify_enforces_epoch_and_revision_minima() {
    // The scope/epoch join with `&&` and `epoch <` with `>` would both accept
    // a snapshot below the required epoch.
    let scope = "stat840";
    let (mut global, _) = open_memory(scope, 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy(scope, 1, 1, COHORT), 10)
        .await
        .unwrap();
    let signed = global.signed_status(100, 2 * DAY).await.unwrap();
    Status::verify(&signed, global.key_ring().unwrap(), scope, 1, 1, 100).unwrap();
    assert!(matches!(
        Status::verify(&signed, global.key_ring().unwrap(), scope, 2, 1, 100),
        Err(Error::Policy)
    ));
    assert!(matches!(
        Status::verify(&signed, global.key_ring().unwrap(), scope, 1, 2, 100),
        Err(Error::Policy)
    ));
    assert!(
        Status::verify(&signed, global.key_ring().unwrap(), "other", 1, 1, 100).is_err(),
        "a snapshot for another scope must not verify"
    );
}

// ---- passport error mapping (facade.rs:876, 877) ----

async fn issued_passport<S: Store, K: csgn::Store, I: cpsd::IssuanceStore>(
    global: &Global<S, K, I>,
    rng: &mut StdRng,
    who: &str,
    secret: &cpsd::HolderSecret,
    now: u64,
) {
    let challenge = challenged(global, rng, who, now, now + 50).await;
    let (request, pending) =
        cpsd::request_issue(rng, secret, global.issuer_public_key(), &challenge).unwrap();
    let blind = global
        .issue(rng, &session(who), &challenge, &request, now)
        .await
        .unwrap();
    pending.finish(&blind).unwrap();
}

#[tokio::test]
async fn changed_holder_maps_to_holder_changed() {
    // Deleting the IssuerTagMismatch arm would surface Error::Passport.
    let (global, _) = open_memory("map876", 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("map876", 1, 1, COHORT), 10)
        .await
        .unwrap();
    proven_person(&global, "alice").await;
    let mut rng = StdRng::seed_from_u64(876);
    let first = cpsd::HolderSecret::generate(&mut rng);
    issued_passport(&global, &mut rng, "alice", &first, 100).await;
    issued_passport(&global, &mut rng, "alice", &first, 101).await;
    let challenge = challenged(&global, &mut rng, "alice", 102, 160).await;
    let other = cpsd::HolderSecret::generate(&mut rng);
    let (changed, _) =
        cpsd::request_issue(&mut rng, &other, global.issuer_public_key(), &challenge).unwrap();
    assert!(matches!(
        global
            .issue(&mut rng, &session("alice"), &challenge, &changed, 102)
            .await,
        Err(Error::HolderChanged)
    ));
}

#[tokio::test]
async fn claimed_holder_tag_maps_to_duplicate() {
    // Deleting the IssuerTagClaimed arm would surface Error::Passport.
    let (global, _) = open_memory("map877", 60, 8, issuer_for(1, &["phone"])).await;
    install(&global, &base_policy("map877", 1, 1, COHORT), 10)
        .await
        .unwrap();
    proven_person(&global, "alice").await;
    proven_person(&global, "bob").await;
    let mut rng = StdRng::seed_from_u64(877);
    let secret = cpsd::HolderSecret::generate(&mut rng);
    issued_passport(&global, &mut rng, "alice", &secret, 100).await;
    let challenge = challenged(&global, &mut rng, "bob", 102, 160).await;
    let (duplicate, _) =
        cpsd::request_issue(&mut rng, &secret, global.issuer_public_key(), &challenge).unwrap();
    assert!(matches!(
        global
            .issue(&mut rng, &session("bob"), &challenge, &duplicate, 102)
            .await,
        Err(Error::Duplicate)
    ));
}
