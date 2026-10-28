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
