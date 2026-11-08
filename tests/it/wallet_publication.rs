//! Focused kill tests for the `src/wallet/publication.rs` survivors.
//! Each test isolates one operator so the listed mutant flips its verdict
//! while the real code passes.
//!
//! - `current` (26:13 `||` -> `&&`): a concurrent same-content rewrite bumps
//!   the store revision without changing the bytes. The real fence refuses
//!   with `Conflict`; the mutant proceeds because the bytes still match.
//! - `retain_pending_transition` (`Some(revision) != last.checked_add(1)` at
//!   115:31, the three transition-field `!=` at 123:38/124:38/125:42): a
//!   staged out-of-band transition retained through a reopen must commit.
//!   Each `==` mutant refuses the legitimate handoff with `KeyMismatch`.
//! - `Publication::key_transitions` (369:9 `-> Ok(vec![])`): the feed after
//!   that reopen must carry the retained proof, not an empty history.
//! - `until` (152:23 `*` -> `+` and `*` -> `/`): the day floor plus the
//!   snapshot is the signature expiry. Window probes past the real expiry
//!   expose both mutants.
//! - `sign_document` (204:63 `*` -> `/`) and `sign_manifest` (242:30 `*` ->
//!   `/`): the validity start is the day floor, not a double quotient. A
//!   probe before the real floor is not yet valid under the real code.
//! - `sign_document` (181:42 guard -> false): with no ended chain the
//!   Communities payload carries no `ended` key at all.
//! - `trust_feed` (266:25 guard -> false, 266:39/266:72 `==` -> `!=`): a
//!   second feed at the same clock reuses the cached publication (same Arc).
//! - `trust_feed` (266:51 `&&` -> `||`): after `record_ended` bumps the
//!   revision the stale cache must not be returned; the revision advances.
//! - `published_feed` (303:25 guard -> true, 303:51 `&&` -> `||`): after
//!   `record_ended` the recheck refuses with `Signature` and fences the view.
//! - `rotate` (346:30 `/` -> `%`/`*`, 346:39 `*` -> `+`/`/`): the committed
//!   signer state carries the day floor of the rotation time.
//!
//! The remaining brief-listed mutants are genuinely unreachable here and are
//! reported in PROGRESS instead of tested:
//! - `retain_pending_transition` 97:21, 103:17, 104:17, 109:21 need a pending
//!   proof whose revision already equals the retained floor; a retain always
//!   acknowledges immediately, so no reopen can observe that state.
//! - `retain_pending_transition` 124:17, 125:17 need exactly one transition
//!   field to mismatch, but the verified transition always endorses the
//!   installed ring at the signer's own revision.
//! - `until` 154:36 `>` -> `>=`: `until - now` is at least one second, so the
//!   boundary never occurs.
//! - `sign_document` 198:26 `>` -> `==`/`>=`: no payload can reach
//!   `MAX_DOCUMENT_BYTES` (config-derived content is bounded by the config
//!   size check, revocations by the capacity guard, ended chains by
//!   `MAX_ENDED`).
//! - `trust_feed` 271:13 (delete the `ClockRegression` arm): `sample` fences
//!   every backward clock before the Beacon is consulted.

use cgbl::{
    storage::{MemoryStore, Store},
    *,
};
use cpsd::rand::{SeedableRng, rngs::StdRng};
use std::{collections::BTreeSet, sync::Arc};

const DAY: u64 = 86_400;
const NOW: u64 = 100;
const RP: &str = "wallet.example.test";
const ORIGIN: &str = "https://vault.wallet.example.test";
const SNAPSHOT: u64 = 2 * DAY;

type WalletOwner = Wallet<MemoryStore, csgn::MemoryStore>;
type Facade = Global<MemoryStore, csgn::MemoryStore, cpsd::MemoryStore>;

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

fn configuration() -> WalletPublicationConfig {
    let mut book = crbk::Rulebook::default();
    book.define(
        "quota",
        crbk::Setting {
            value_type: crbk::SettingType::Integer,
            nullable: false,
            default: serde_json::json!(17),
            bounds: crbk::Bounds {
                min: Some(0.into()),
                max: Some(100.into()),
            },
            lowest_layer: crbk::Layer::Community,
            kind: crbk::SettingKind::Technical,
        },
    )
    .unwrap();
    let schema = serde_json::from_value(serde_json::json!({
        "community":"wallet", "version":1,
        "public":[{"id":"consent","label":"Receive invitations?","kind":{"type":"yes_no"},
            "required":true,"filterable":false,"change_preset":"stable","no_contact_details":false}],
        "private":[]
    }))
    .unwrap();
    WalletPublicationConfig::new(
        RP,
        ORIGIN,
        book,
        cplc::SchemaVersions {
            purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
            current: 1,
            versions: vec![cplc::SchemaVersion {
                schema,
                changes: None,
            }],
        },
        BTreeSet::new(),
        SNAPSHOT,
    )
    .unwrap()
}

async fn setup() -> (Facade, MemoryStore) {
    let store = MemoryStore::new("global").unwrap();
    let keys = csgn::MemoryStore::default();
    let issuance = cpsd::MemoryStore::new(cpsd::CommunityId::new(b"global").unwrap(), 2).unwrap();
    let key = csgn::SecretKey::from_seed(&mut [2; 32]);
    let signer = csgn::PersistentSigner::create(keys, "cgbl:global", key, 0, 30 * DAY)
        .await
        .unwrap();
    let global = Global::open(
        store.clone(),
        issuance,
        issuer(),
        signer,
        fingerprints(),
        Mode::Production,
        Limits {
            challenge_ttl: 60,
            pending_capacity: 2,
        },
    )
    .await
    .unwrap();
    (global, store)
}

/// Enrolled passkey owners with exactly the configured origin; no ceremony is
/// needed because `open_wallet` only reads the retained RP/origin pair.
async fn passkeys() -> (tempfile::TempDir, Arc<ckyh::Passkeys<ckyh::LibsqlStore>>) {
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
    (directory, keys)
}

fn wallet_key(seed: u8) -> csgn::SecretKey {
    csgn::SecretKey::from_seed(&mut [seed; 32])
}

async fn open_wallet(
    global: &Facade,
    keys: Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
    signer_store: csgn::MemoryStore,
    seed: u8,
    now: u64,
) -> WalletOwner {
    let signer =
        csgn::PersistentSigner::create(signer_store, "wallet", wallet_key(seed), 0, 30 * DAY)
            .await
            .unwrap();
    global
        .open_wallet(signer, configuration(), keys, now)
        .await
        .unwrap()
}

fn ended_chain() -> EndedChain {
    EndedChain {
        fingerprint: [0xab; 32],
        reason_class: EndedReason::Banned,
        ended_at: NOW,
    }
}

// ---- current (26:13 `||` -> `&&`) ----

#[tokio::test(flavor = "multi_thread")]
async fn stale_same_content_rewrite_fences_the_writer() {
    let (global, store) = setup().await;
    let (_directory, keys) = passkeys().await;
    let mut wallet = open_wallet(&global, keys, csgn::MemoryStore::default(), 47, NOW).await;
    wallet.trust_feed(NOW).await.unwrap();
    // A concurrent writer wins the race with byte-identical content: the
    // store revision moves but the bytes do not. The real fence refuses with
    // `Conflict`; the `&&` mutant at 26:13 proceeds because the bytes match.
    let key = storage::Key::new("wallet", "publications");
    let read = store.read(std::slice::from_ref(&key)).await.unwrap();
    let bytes = read.records[&key].value.clone();
    store
        .compare_exchange(
            &read,
            vec![storage::Change {
                key: key.clone(),
                record: Some(storage::Record {
                    value: bytes,
                    deadline: 0,
                }),
            }],
        )
        .await
        .unwrap();
    assert!(matches!(wallet.trust_feed(NOW).await, Err(Error::Conflict)));
}

// ---- retain_pending_transition handoff + key_transitions ----

#[tokio::test(flavor = "multi_thread")]
async fn staged_transition_reopens_and_publishes_with_retained_proof() {
    let (global, _) = setup().await;
    let (_directory, keys) = passkeys().await;
    let signer_store = csgn::MemoryStore::default();
    // A fresh wallet creates the floor-0 publication state.
    let first = open_wallet(&global, keys.clone(), signer_store.clone(), 47, DAY).await;
    drop(first);
    // Stage the ring transition out-of-band, then retain it through a reopen.
    // The real handoff commits the floor-1 state; the `==` mutants at 115:31
    // and 123:38/124:38/125:42 refuse it with `KeyMismatch`.
    let mut staged =
        csgn::PersistentSigner::open(signer_store.clone(), "wallet", wallet_key(47), DAY)
            .await
            .unwrap();
    staged
        .rotate_with_proof(wallet_key(48), DAY, DAY + SNAPSHOT)
        .await
        .unwrap();
    let mut wallet = global
        .open_wallet(staged, configuration(), keys, DAY)
        .await
        .unwrap();
    let feed = wallet.trust_feed(DAY).await.unwrap();
    // The published feed carries the retained proof, not an empty history
    // (kills 369:9 `-> Ok(vec![])`).
    assert_eq!(feed.policy_epoch, 2);
    assert_eq!(feed.key_transitions.len(), 1);
    assert_eq!(feed.key_transitions[0].revision, 1);
    assert!(!feed.key_transitions[0].proof.is_empty());
}

// ---- until (152:23 `*` -> `+` / `*` -> `/`) ----

#[tokio::test(flavor = "multi_thread")]
async fn document_window_ends_at_day_floor_plus_snapshot() {
    let (global, _) = setup().await;
    let (_directory, keys) = passkeys().await;
    let mut wallet = open_wallet(&global, keys, csgn::MemoryStore::default(), 47, NOW).await;
    let feed = wallet.trust_feed(NOW).await.unwrap();
    let ring = wallet.key_ring().unwrap();
    ring.verify(&feed.settings, csgn::Kind::SettingsSnapshot, NOW)
        .unwrap();
    // Real expiry is `0 + SNAPSHOT`; the `+` mutant stretches it by a day.
    assert!(
        ring.verify(
            &feed.settings,
            csgn::Kind::SettingsSnapshot,
            NOW + SNAPSHOT + 1_000
        )
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn document_window_survives_its_own_snapshot_day() {
    let (global, _) = setup().await;
    let (_directory, keys) = passkeys().await;
    let mut wallet = open_wallet(&global, keys, csgn::MemoryStore::default(), 47, NOW).await;
    let feed = wallet.trust_feed(DAY + 100).await.unwrap();
    let ring = wallet.key_ring().unwrap();
    ring.verify(&feed.settings, csgn::Kind::SettingsSnapshot, DAY + 100)
        .unwrap();
    // Real expiry is `86400 + SNAPSHOT`; the `/` mutant collapses the floor
    // to zero and expires a day early.
    ring.verify(&feed.settings, csgn::Kind::SettingsSnapshot, 200_000)
        .unwrap();
}

// ---- sign windows (204:63, 242:30 `*` -> `/`) ----

#[tokio::test(flavor = "multi_thread")]
async fn document_validity_starts_at_the_day_floor() {
    let (global, _) = setup().await;
    let (_directory, keys) = passkeys().await;
    let mut wallet = open_wallet(&global, keys, csgn::MemoryStore::default(), 47, NOW).await;
    let feed = wallet.trust_feed(DAY + 100).await.unwrap();
    // Real validity starts at 86400; the `/` mutant starts at zero.
    assert!(
        wallet
            .key_ring()
            .unwrap()
            .verify(&feed.settings, csgn::Kind::SettingsSnapshot, NOW)
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn manifest_validity_starts_at_the_day_floor() {
    let (global, _) = setup().await;
    let (_directory, keys) = passkeys().await;
    let mut wallet = open_wallet(&global, keys, csgn::MemoryStore::default(), 47, NOW).await;
    let feed = wallet.trust_feed(DAY + 100).await.unwrap();
    // Real validity starts at 86400; the `/` mutant starts at zero.
    assert!(
        wallet
            .key_ring()
            .unwrap()
            .verify(&feed.manifest, csgn::Kind::SettingsSnapshot, NOW)
            .is_err()
    );
}

// ---- Communities guard (181:42 guard -> false) ----

#[tokio::test(flavor = "multi_thread")]
async fn communities_snapshot_omits_ended_when_no_chain_ended() {
    let (global, _) = setup().await;
    let (_directory, keys) = passkeys().await;
    let mut wallet = open_wallet(&global, keys, csgn::MemoryStore::default(), 47, NOW).await;
    let feed = wallet.trust_feed(NOW).await.unwrap();
    let signed = wallet
        .key_ring()
        .unwrap()
        .verify(&feed.communities, csgn::Kind::CommunitiesSnapshot, NOW)
        .unwrap();
    let view: cplc::Snapshot<serde_json::Value> = serde_json::from_slice(signed.payload()).unwrap();
    // The real arm publishes the bare directory; the guard-false mutant
    // always wraps it with an (empty) `ended` list.
    assert!(view.content.get("ended").is_none());
}

// ---- trust_feed cache guard (266:25/39/72, 266:51) ----

#[tokio::test(flavor = "multi_thread")]
async fn second_feed_at_same_clock_reuses_the_cached_publication() {
    let (global, _) = setup().await;
    let (_directory, keys) = passkeys().await;
    let mut wallet = open_wallet(&global, keys, csgn::MemoryStore::default(), 47, NOW).await;
    let first = wallet.trust_feed(NOW).await.unwrap();
    // Nothing changed, so the fast path returns the installed publication
    // itself. The guard-false mutant and both `==` -> `!=` mutants recollect
    // instead and hand back a different Arc.
    let second = wallet.trust_feed(NOW).await.unwrap();
    assert!(Arc::ptr_eq(&first, &second));
}

#[tokio::test(flavor = "multi_thread")]
async fn revision_bump_after_record_ended_forces_a_fresh_collection() {
    let (global, _) = setup().await;
    let (_directory, keys) = passkeys().await;
    let mut wallet = open_wallet(&global, keys, csgn::MemoryStore::default(), 47, NOW).await;
    let first = wallet.trust_feed(NOW).await.unwrap();
    wallet.record_ended(ended_chain(), NOW).await.unwrap();
    // The revision moved while the epoch did not; the real guard misses and
    // recollects. The `||` mutant returns the stale cached feed instead.
    let second = wallet.trust_feed(NOW).await.unwrap();
    assert!(second.revision > first.revision);
}

// ---- published_feed guard (303:25, 303:51) ----

#[tokio::test(flavor = "multi_thread")]
async fn published_feed_after_record_ended_refuses_and_fences() {
    let (global, _) = setup().await;
    let (_directory, keys) = passkeys().await;
    let mut wallet = open_wallet(&global, keys, csgn::MemoryStore::default(), 47, NOW).await;
    wallet.trust_feed(NOW).await.unwrap();
    wallet.record_ended(ended_chain(), NOW).await.unwrap();
    // The retained view no longer matches the installed feed; the recheck
    // refuses with `Signature` and drops the view. Both mutants (guard ->
    // true, `&&` -> `||`) return the stale cached feed instead.
    assert!(matches!(wallet.published_feed(NOW), Err(Error::Signature)));
    assert!(wallet.key_ring().is_err());
}

// ---- rotate floor (346:30 `/` -> `%`/`*`, 346:39 `*` -> `+`/`/`) ----

#[tokio::test(flavor = "multi_thread")]
async fn rotation_commits_the_day_floor_to_signer_state() {
    let (global, _) = setup().await;
    let (_directory, keys) = passkeys().await;
    let signer_store = csgn::MemoryStore::default();
    let mut wallet = open_wallet(&global, keys, signer_store.clone(), 47, NOW).await;
    // A plain rotation cannot retain a transition (the writer fences), but
    // the signer commit must carry the day floor of the rotation time. Every
    // floor mutant records a different activation instant instead.
    assert!(wallet.rotate(wallet_key(48), DAY + 100).await.is_err());
    let saved = csgn::Store::load(&signer_store, "wallet")
        .await
        .unwrap()
        .unwrap();
    let activated = saved.state.key_ring().active().unwrap().activated_at();
    assert_eq!(activated, DAY);
}
