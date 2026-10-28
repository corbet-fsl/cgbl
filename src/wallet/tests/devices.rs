//! Focused kill tests for the `src/wallet/devices.rs` survivors: every
//! rejection arm of `Devices::validate`, the exact-boundary accepts, and the
//! deadline precheck of `decode`. Each single-violation test isolates one
//! operator so the listed mutant flips its verdict while the real code passes.
//!
//! `Devices::validate` is a chain `O0 || O1 || ... || O11`. Replacing the
//! `||` between `Oi` and `Oi+1` with `&&` accepts a row that violates exactly
//! one of the two neighbours, so each single-violation rejection test below
//! kills the two `||` mutants flanking its operand (first/last kill one).
//! Boundary accepts (`generation == i64::MAX`, 128 bindings, 256 removed,
//! 4 births, 1024-byte credential, equal adjacent bindings) kill the `>`
//! weakenings and the `>=` -> `<` strictness loss.
use super::*;
use crate::storage::{Key, ReadSet, Record};
use std::collections::BTreeSet;

// `acknowledge_publication` conflict-guard kills: the guard refuses with
// `Conflict` when the stored row no longer matches the generation observed
// during `reconcile_keys` OR the row is no longer pending. Replacing the
// `||` with `&&` accepts a row that violates exactly one side, so each
// single-violation test below fails on the mutant while the real code
// refuses. The wallet is built in-crate (the guard is `pub(super)`): a
// genuine state row plus one injected device row, with `pending` claiming
// the pre-acknowledgment observation.

use crate::storage::{MemoryStore, Store};
use std::sync::Arc;

const ACK_RP: &str = "wallet.example.test";
const ACK_ORIGIN: &str = "https://vault.wallet.example.test";
const ACK_DAY: u64 = 86_400;
const ACK_NOW: u64 = 100;

fn ack_config() -> WalletPublicationConfig {
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
        ACK_RP,
        ACK_ORIGIN,
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
        2 * ACK_DAY,
    )
    .unwrap()
}

struct AckWallet {
    wallet: Wallet<MemoryStore, csgn::MemoryStore>,
    _instance: Arc<()>,
    _directory: tempfile::TempDir,
}

/// Genuine wallet state plus one device row `(member, generation, pending)`,
/// with `pending` claiming `claimed_generation` for that row as a finished
/// `reconcile_keys` observation would.
async fn ack_wallet(
    member: &str,
    generation: u64,
    pending: bool,
    claimed_generation: u64,
) -> AckWallet {
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
            ACK_RP,
            &[ckyh::Url::parse(ACK_ORIGIN).unwrap()],
        )
        .unwrap(),
    );
    let store = MemoryStore::new("wallet-ack-test").unwrap();
    let secret = csgn::SecretKey::from_seed(&mut [47; 32]);
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "wallet",
        secret,
        0,
        30 * ACK_DAY,
    )
    .await
    .unwrap();
    let ring = signer.key_ring().unwrap().to_cbor();
    let retained = state::open(&store, ack_config(), ring, 0).await.unwrap();
    let key = Key::new(BUCKET, member);
    let read = store.read(std::slice::from_ref(&key)).await.unwrap();
    let value = serde_json::json!({
        "version": 1,
        "member": member,
        "generation": generation,
        "pending": pending,
        "bindings": [],
        "removed": [],
        "births": [],
    });
    store
        .compare_exchange(
            &read,
            vec![Change {
                key: key.clone(),
                record: Some(Record {
                    value: serde_json::to_vec(&value).unwrap(),
                    deadline: 0,
                }),
            }],
        )
        .await
        .unwrap();
    let observed = store.read(std::slice::from_ref(&key)).await.unwrap();
    let instance = Arc::new(());
    let wallet = Wallet {
        barrier: Arc::new(crate::wallet::barrier::Barrier::new()),
        pending: vec![(key, claimed_generation)],
        publication_reads: Some(observed),
        passkeys: keys,
        instance: Arc::downgrade(&instance),
        store,
        signer,
        retained: Some(retained),
        beacon: cbcn::Beacon::default(),
        observed_at: Some(ACK_NOW),
    };
    AckWallet {
        wallet,
        _instance: instance,
        _directory: directory,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn acknowledge_rejects_generation_moved_on_with_live_pending_flag() {
    // Kills 445:46 `||` -> `&&`: the stored generation (2) differs from the
    // observed one (1) while the row is still pending, so only `||` refuses.
    let member = ckyh::Uuid::from_u128(901).to_string();
    let mut setup = ack_wallet(&member, 2, true, 1).await;
    assert!(matches!(
        setup.wallet.acknowledge_publication().await,
        Err(crate::Error::Conflict)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn acknowledge_rejects_already_applied_generation_with_matching_number() {
    // Kills 445:46 `||` -> `&&`: generations match (2 == 2) but the stored
    // row is already applied, so only `||` refuses.
    let member = ckyh::Uuid::from_u128(902).to_string();
    let mut setup = ack_wallet(&member, 2, false, 2).await;
    assert!(matches!(
        setup.wallet.acknowledge_publication().await,
        Err(crate::Error::Conflict)
    ));
}

const LIMIT: u64 = i64::MAX as u64;

fn member() -> String {
    ckyh::Uuid::from_u128(27).to_string()
}

fn key32(n: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[28..32].copy_from_slice(&n.to_be_bytes());
    key
}

fn binding(credential: Vec<u8>, key: [u8; 32]) -> Binding {
    Binding { credential, key }
}

/// One valid binding; credentials `vec![n]` sort by their single byte.
fn sorted_bindings(count: u8) -> Vec<Binding> {
    (0..count).map(|n| binding(vec![n], key32(1))).collect()
}

fn valid() -> Devices {
    Devices {
        version: 1,
        member: member(),
        generation: 1,
        pending: false,
        bindings: vec![binding(vec![9], key32(1))],
        removed: BTreeSet::new(),
        births: vec![],
    }
}

fn key_for(row: &Devices) -> Key {
    Key::new(BUCKET, &row.member)
}

fn is_encoding(result: &Result<ckyh::Uuid>) -> bool {
    matches!(result, Err(crate::Error::Encoding))
}

// Rejection arms: each violates exactly one operand.

#[test]
fn version_other_than_one_is_rejected() {
    // Kills 49:13 `||` -> `&&` (version/bucket pair).
    let mut row = valid();
    row.version = 2;
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn wrong_bucket_is_rejected() {
    // Kills 49:13 and 50:13 `||` -> `&&`.
    let row = valid();
    assert!(is_encoding(
        &row.validate(&Key::new("wallet-device-x", &row.member))
    ));
}

#[test]
fn wrong_id_is_rejected() {
    // Kills 50:13 and 51:13 `||` -> `&&`.
    let row = valid();
    assert!(is_encoding(
        &row.validate(&Key::new(BUCKET, "someone-else"))
    ));
}

#[test]
fn noncanonical_member_spelling_is_rejected() {
    // Uppercase parses to the same UUID but is not the canonical spelling,
    // so the round-trip comparison fails. Kills 51:13 and 52:13 `||` -> `&&`.
    let mut row = valid();
    row.member = member().to_uppercase();
    assert_ne!(row.member, member());
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn zero_generation_is_rejected() {
    // Kills 52:13 and 53:13 `||` -> `&&`.
    let mut row = valid();
    row.generation = 0;
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn generation_past_i64_max_is_rejected() {
    // Kills 53:13 and 54:13 `||` -> `&&`, and 53:32 `>` -> `==`
    // (i64::MAX + 1 is not equal to the bound, so the mutant accepts).
    let mut row = valid();
    row.generation = LIMIT + 1;
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn generation_at_i64_max_is_accepted() {
    // The bound itself is legal. Kills 53:32 `>` -> `==` and `>` -> `>=`.
    let mut row = valid();
    row.generation = LIMIT;
    assert_eq!(row.validate(&key_for(&row)).unwrap().to_string(), member());
    assert!(row.change().is_ok());
}

#[test]
fn bindings_past_128_are_rejected() {
    // Kills 54:13 and 55:13 `||` -> `&&`, and 54:36 `>` -> `==`.
    let mut row = valid();
    row.bindings = sorted_bindings(129);
    assert_eq!(row.bindings.len(), 129);
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn bindings_at_128_are_accepted() {
    // Kills 54:36 `>` -> `==` and `>` -> `>=`.
    let mut row = valid();
    row.bindings = sorted_bindings(128);
    assert!(row.change().is_ok());
}

#[test]
fn removed_past_256_are_rejected() {
    // Kills 55:13 and 56:13 `||` -> `&&`, and 55:35 `>` -> `==`.
    let mut row = valid();
    row.removed = (1..=257u32).map(key32).collect();
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn removed_at_256_are_accepted() {
    // Kills 55:35 `>` -> `==` and `>` -> `>=`.
    let mut row = valid();
    row.removed = (1..=256u32).map(key32).collect();
    assert!(row.change().is_ok());
}

#[test]
fn births_past_4_are_rejected() {
    // Kills 56:13 and 57:13 `||` -> `&&`, and 56:34 `>` -> `==`.
    let mut row = valid();
    row.births = vec![[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn births_at_4_are_accepted() {
    // Kills 56:34 `>` -> `==` and `>` -> `>=`.
    let mut row = valid();
    row.births = vec![[1; 32], [2; 32], [3; 32], [4; 32]];
    assert!(row.change().is_ok());
}

#[test]
fn duplicate_births_are_rejected() {
    // Same digest twice is not two statements. Kills 57:13 and 58:13
    // `||` -> `&&`.
    let mut row = valid();
    row.births = vec![[7; 32], [7; 32]];
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn empty_credential_is_rejected() {
    // Kills 58:13 `||` -> `&&` (dup-births/binding pair) and the inner
    // 60:21 `||` -> `&&` (empty/oversize pair).
    let mut row = valid();
    row.bindings = vec![binding(vec![], key32(1))];
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn credential_past_1024_is_rejected() {
    // Kills the inner 60:21 and 61:21 `||` -> `&&`, and 60:49 `>` -> `==`.
    let mut row = valid();
    row.bindings = vec![binding(vec![7; 1025], key32(1))];
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn credential_at_1024_is_accepted() {
    // Kills 60:49 `>` -> `==` and `>` -> `>=`.
    let mut row = valid();
    row.bindings = vec![binding(vec![7; 1024], key32(1))];
    assert!(row.change().is_ok());
}

#[test]
fn zero_device_key_is_rejected() {
    // Kills the inner 61:21 `||` -> `&&` (oversize/zero-key pair) and
    // 63:13 `||` -> `&&` (binding/order pair).
    let mut row = valid();
    row.bindings = vec![binding(vec![9], [0; 32])];
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn unsorted_bindings_are_rejected() {
    // Kills 63:13 `||` -> `&&`.
    let mut row = valid();
    row.bindings = vec![binding(vec![2], key32(1)), binding(vec![1], key32(1))];
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

#[test]
fn equal_adjacent_bindings_are_rejected() {
    // Equal neighbours are not strictly ordered. Kills 64:52 `>=` -> `<`,
    // which only flags strictly decreasing pairs.
    let mut row = valid();
    let same = binding(vec![9], key32(1));
    row.bindings = vec![same.clone(), same];
    assert!(is_encoding(&row.validate(&key_for(&row))));
}

// `decode` precheck and round trip.

#[test]
fn nonzero_deadline_is_rejected_before_parsing() {
    // A live protocol deadline is never a device row. Kills 88:37
    // `||` -> `&&` (deadline/size pair): the mutant parses the small valid
    // value and returns it instead of refusing.
    let row = valid();
    let key = key_for(&row);
    let read = ReadSet {
        revisions: Default::default(),
        records: [(
            key.clone(),
            Record {
                value: serde_json::to_vec(&row).unwrap(),
                deadline: 7,
            },
        )]
        .into_iter()
        .collect(),
    };
    assert!(matches!(decode(&read, &key), Err(crate::Error::Encoding)));
}

#[test]
fn valid_row_change_and_decode_roundtrip() {
    let row = valid();
    let change = row.change().unwrap();
    assert_eq!(change.key, key_for(&row));
    let stored = change.record.unwrap();
    assert_eq!(stored.deadline, 0);
    let key = key_for(&row);
    let read = ReadSet {
        revisions: Default::default(),
        records: [(key.clone(), stored)].into_iter().collect(),
    };
    let back = decode(&read, &key).unwrap().unwrap();
    assert_eq!(back.member, member());
}

#[test]
fn missing_record_decodes_to_none() {
    let row = valid();
    let key = key_for(&row);
    let read = ReadSet::default();
    assert!(decode(&read, &key).unwrap().is_none());
}
