//! Focused kill tests for the `src/wallet.rs` survivors listed in the mut128
//! brief. Each test isolates one operator so the listed mutant flips its
//! verdict while the real code passes.
//!
//! `Wallet::open` gates (lines 222-230):
//! - duplicated enrolled origins refuse even when the RP matches
//!   (kills 222:31 `||` -> `&&`: exactly one side differs).
//! - a short `max_validity` refuses even with the right issuer and an aligned
//!   activation (kills 227:13 and 228:13 `||` -> `&&`).
//! - a misaligned activation refuses even with a long `max_validity`
//!   (kills 228:13 `||` -> `&&`; the 227 mutant still refuses here).
//! - `max_validity` equal to `snapshot_seconds` opens (kills both 227:36
//!   `<` -> `==` and `<` -> `<=`, which wrongly refuse the boundary).
//! - a nonzero day-aligned activation opens (kills 230:54 `%` -> `/`, which
//!   computes `86400 / 86400 = 1 != 0` and wrongly refuses).
//! - a foreign issuer refuses (documents the first disjunct; the retained
//!   state validation backstops it, so no open mutant is killed by this one).
//!
//! `Wallet::key_ring` (lines 275-287): the `||` -> `&&` mutants at 276:13 and
//! 281:13 need exactly one of {revision mismatch, pending transition} true
//! with matching rings in a live wallet. No public path produces that state:
//! `open` and `retain_pending_transition` reconcile-or-fence (a desync clears
//! the retained view, so `key_ring` refuses with `Storage` on every variant),
//! and the signer proof operations that bump the revision or stage a pending
//! transition are not exposed through `Wallet`. Reported as unreachable in
//! PROGRESS instead of tested here.

use cgbl::{storage::MemoryStore, *};
use cpsd::rand::{SeedableRng, rngs::StdRng};
use std::{collections::BTreeSet, sync::Arc};

const DAY: u64 = 86_400;
const NOW: u64 = 100;
const ALIGNED_NOW: u64 = 2 * DAY;
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

fn configuration_with(rp: &str, origin: &str, snapshot: u64) -> WalletPublicationConfig {
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
        rp,
        origin,
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
        snapshot,
    )
    .unwrap()
}

async fn global() -> Facade {
    let key = csgn::SecretKey::from_seed(&mut [2; 32]);
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "cgbl:global",
        key,
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    Global::open(
        MemoryStore::new("global").unwrap(),
        cpsd::MemoryStore::new(cpsd::CommunityId::new(b"global").unwrap(), 2).unwrap(),
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
    .unwrap()
}

/// Enrolled passkey owners with exactly these origins; no ceremony is needed
/// because `open_wallet` only reads the retained RP/origin pair.
async fn passkeys(
    rp: &str,
    origins: &[ckyh::Url],
) -> (tempfile::TempDir, Arc<ckyh::Passkeys<ckyh::LibsqlStore>>) {
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
            rp,
            origins,
        )
        .unwrap(),
    );
    (directory, keys)
}

async fn signer(
    issuer: &str,
    seed: u8,
    activated_at: u64,
    max_validity: u64,
) -> csgn::PersistentSigner<csgn::MemoryStore> {
    csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        issuer,
        csgn::SecretKey::from_seed(&mut [seed; 32]),
        activated_at,
        max_validity,
    )
    .await
    .unwrap()
}

fn url(text: &str) -> ckyh::Url {
    ckyh::Url::parse(text).unwrap()
}

// ---- hex32 stride (159:63 `*` -> `/`) ----

#[test]
fn ended_chain_hex_decode_uses_stride_not_quotient() {
    let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
    let chain = cgbl::EndedChain {
        fingerprint: bytes,
        reason_class: cgbl::EndedReason::Banned,
        ended_at: 100,
    };
    let text = serde_json::to_string(&chain).unwrap();
    assert!(text.contains("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    // The `/` mutant reads `text[index / 2 ..]` so every odd byte decodes from
    // the previous pair; distinct bytes expose it.
    let back: cgbl::EndedChain = serde_json::from_str(&text).unwrap();
    assert_eq!(back.fingerprint, bytes);
}

// ---- open RP/origin fence (222:31 `||` -> `&&`) ----

#[tokio::test(flavor = "multi_thread")]
async fn duplicated_enrolled_origin_refuses_wallet_open() {
    let global = global().await;
    // Same RP, but the enrolled origins are not exactly the single configured
    // vault origin. The real fence refuses; the `&&` mutant accepts.
    let (_directory, keys) = passkeys(RP, &[url(ORIGIN), url(ORIGIN)]).await;
    let wallet = global
        .open_wallet(
            signer("wallet", 47, 0, 30 * DAY).await,
            configuration_with(RP, ORIGIN, SNAPSHOT),
            keys,
            NOW,
        )
        .await;
    assert!(wallet.is_err());
}

// ---- open ring fence (227:13, 228:13 `||` -> `&&`) ----

#[tokio::test(flavor = "multi_thread")]
async fn short_max_validity_refuses_wallet_open() {
    let global = global().await;
    let (_directory, keys) = passkeys(RP, &[url(ORIGIN)]).await;
    // Right issuer, aligned activation, but the ring lifetime is shorter than
    // the publication snapshot. The real fence refuses; both `&&` mutants
    // wrongly proceed to a successful open.
    let wallet = global
        .open_wallet(
            signer("wallet", 47, 0, DAY).await,
            configuration_with(RP, ORIGIN, SNAPSHOT),
            keys,
            NOW,
        )
        .await;
    assert!(wallet.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn misaligned_activation_refuses_wallet_open() {
    let global = global().await;
    let (_directory, keys) = passkeys(RP, &[url(ORIGIN)]).await;
    // Long lifetime and right issuer, but the activation is not day-aligned.
    // The real fence refuses; the 228 `&&` mutant wrongly opens.
    let wallet = global
        .open_wallet(
            signer("wallet", 47, 1, 30 * DAY).await,
            configuration_with(RP, ORIGIN, SNAPSHOT),
            keys,
            NOW,
        )
        .await;
    assert!(wallet.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_issuer_refuses_wallet_open() {
    let global = global().await;
    let (_directory, keys) = passkeys(RP, &[url(ORIGIN)]).await;
    let wallet = global
        .open_wallet(
            signer("not-the-wallet", 47, 0, 30 * DAY).await,
            configuration_with(RP, ORIGIN, SNAPSHOT),
            keys,
            NOW,
        )
        .await;
    assert!(wallet.is_err());
}

// ---- open boundary accepts (227:36 `<` -> `==` / `<=`, 230:54 `%` -> `/`) ----

#[tokio::test(flavor = "multi_thread")]
async fn max_validity_equal_to_snapshot_opens() {
    let global = global().await;
    let (_directory, keys) = passkeys(RP, &[url(ORIGIN)]).await;
    // Exactly at the boundary: `<` accepts, while `==` and `<=` wrongly refuse.
    let wallet: WalletOwner = global
        .open_wallet(
            signer("wallet", 47, 0, SNAPSHOT).await,
            configuration_with(RP, ORIGIN, SNAPSHOT),
            keys,
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(wallet.key_ring().unwrap().issuer(), "wallet");
}

#[tokio::test(flavor = "multi_thread")]
async fn day_aligned_nonzero_activation_opens() {
    let global = global().await;
    let (_directory, keys) = passkeys(RP, &[url(ORIGIN)]).await;
    // `86400 % 86400 == 0` accepts; the `/` mutant computes `1 != 0`.
    let wallet: WalletOwner = global
        .open_wallet(
            signer("wallet", 47, DAY, 30 * DAY).await,
            configuration_with(RP, ORIGIN, SNAPSHOT),
            keys,
            ALIGNED_NOW,
        )
        .await
        .unwrap();
    assert_eq!(wallet.key_ring().unwrap().issuer(), "wallet");
}

// ---- rotation without retention fences the writer ----

#[tokio::test(flavor = "multi_thread")]
async fn rotated_signer_without_retention_refuses_key_ring() {
    let global = global().await;
    let (_directory, keys) = passkeys(RP, &[url(ORIGIN)]).await;
    let mut wallet: WalletOwner = global
        .open_wallet(
            signer("wallet", 47, 0, 30 * DAY).await,
            configuration_with(RP, ORIGIN, SNAPSHOT),
            keys,
            NOW,
        )
        .await
        .unwrap();
    // The plain rotation changes the ring without retaining a transition, so
    // the writer is fenced: every `key_ring` variant refuses here.
    assert!(
        wallet
            .rotate(csgn::SecretKey::from_seed(&mut [48; 32]), NOW)
            .await
            .is_err()
    );
    assert!(wallet.key_ring().is_err());
}
