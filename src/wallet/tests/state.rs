//! Focused regression tests for [`super::State`], [`super::open`] and
//! [`super::max_stored_bytes`]: every rejection arm of `State::validate` and
//! both guards of `open` are exercised at (and just past) their boundaries, so
//! a weakened operator (`||` to `&&`, `>` to `==`/`>=`, `+` to `-`/`*`) turns
//! one of these tests red.
use super::*;
use crate::storage::{MemoryStore, Store};
use std::collections::{BTreeMap, BTreeSet};

const DAY: u64 = 86_400;
const LIMIT: u64 = i64::MAX as u64;

fn configuration() -> WalletPublicationConfig {
    configuration_with(0, 0)
}

fn configuration_with(padding_settings: usize, community_count: usize) -> WalletPublicationConfig {
    let mut book = crbk::Rulebook::default();
    let mut setting = |key: String| {
        book.define(
            key,
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
        .unwrap()
    };
    setting("quota".to_string());
    for index in 0..padding_settings {
        setting(format!("pad{index:05}/x"));
    }
    let schema = serde_json::from_value(serde_json::json!({
        "community":"wallet", "version":1,
        "public":[{"id":"consent","label":"Receive invitations?","kind":{"type":"yes_no"},
            "required":true,"filterable":false,"change_preset":"stable","no_contact_details":false}],
        "private":[]
    }))
    .unwrap();
    WalletPublicationConfig::new(
        "wallet.example.test",
        "https://vault.wallet.example.test",
        book,
        cplc::SchemaVersions {
            purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
            current: 1,
            versions: vec![cplc::SchemaVersion {
                schema,
                changes: None,
            }],
        },
        (0..community_count)
            .map(|index| format!("community-{index:03}"))
            .collect(),
        2 * DAY,
    )
    .unwrap()
}

fn ring_bytes(issuer: &str) -> Vec<u8> {
    let signer = csgn::Signer::new(
        issuer,
        csgn::SecretKey::from_seed(&mut [47; 32]),
        0,
        30 * DAY,
    )
    .unwrap();
    signer.key_ring().to_cbor()
}

/// A genuine wallet ring at the key-count bound: rotations never expire under
/// the wide validity, so every retired key is retained up to the ring limit.
fn big_ring_bytes() -> Vec<u8> {
    let mut signer = csgn::Signer::new(
        "wallet",
        csgn::SecretKey::from_seed(&mut [47; 32]),
        0,
        LIMIT,
    )
    .unwrap();
    for index in 1..csgn::MAX_RING_KEYS as u64 {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&index.to_le_bytes());
        signer
            .rotate(csgn::SecretKey::from_seed(&mut seed), index)
            .unwrap();
    }
    signer.key_ring().to_cbor()
}

fn valid_state() -> State {
    State {
        version: 1,
        revision: 1,
        epoch: 1,
        key_ring: ring_bytes("wallet"),
        config: configuration(),
        revocations: cplc::Revocations::default(),
        transitions: Vec::new(),
        documents: BTreeMap::new(),
        manifest: None,
        ended: Vec::new(),
    }
}

fn fingerprint(n: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&(n as u64).to_le_bytes());
    out
}

fn document(revision: u64, bytes: Vec<u8>) -> BTreeMap<cplc::SnapshotKind, Signed> {
    BTreeMap::from([(cplc::SnapshotKind::Settings, Signed { revision, bytes })])
}

#[test]
fn well_formed_state_passes() {
    valid_state().validate().unwrap();
}

#[test]
fn invalid_configuration_refuses() {
    let mut state = valid_state();
    let mut value = serde_json::to_value(state.config.clone()).unwrap();
    value["snapshot_seconds"] = serde_json::json!(1);
    state.config = serde_json::from_value(value).unwrap();
    assert!(state.validate().is_err());
}

#[test]
fn malformed_key_ring_refuses() {
    let mut state = valid_state();
    state.key_ring = b"not a key ring".to_vec();
    assert!(state.validate().is_err());
}

#[test]
fn foreign_ring_issuer_refuses() {
    let mut state = valid_state();
    state.key_ring = ring_bytes("other");
    assert!(state.validate().is_err());
}

#[test]
fn version_must_be_one() {
    for version in [0, 2, u8::MAX] {
        let mut state = valid_state();
        state.version = version;
        assert!(state.validate().is_err(), "version {version}");
    }
}

#[test]
fn zero_revision_refuses() {
    let mut state = valid_state();
    state.revision = 0;
    assert!(state.validate().is_err());
}

#[test]
fn revision_bound_is_inclusive() {
    let mut state = valid_state();
    state.revision = LIMIT;
    state.validate().unwrap();
    state.revision = LIMIT + 1;
    assert!(state.validate().is_err());
}

#[test]
fn zero_epoch_refuses() {
    let mut state = valid_state();
    state.epoch = 0;
    assert!(state.validate().is_err());
}

#[test]
fn epoch_bound_is_inclusive() {
    let mut state = valid_state();
    state.epoch = LIMIT;
    state.validate().unwrap();
    state.epoch = LIMIT + 1;
    assert!(state.validate().is_err());
}

#[test]
fn member_revocations_must_stay_empty() {
    let mut state = valid_state();
    state.revocations.members = BTreeSet::from(["member".to_string()]);
    assert!(state.validate().is_err());
}

fn ended(n: usize) -> Vec<super::EndedChain> {
    (0..n)
        .map(|index| super::EndedChain {
            fingerprint: fingerprint(index),
            reason_class: super::EndedReason::Banned,
            ended_at: 1,
        })
        .collect()
}

#[test]
fn ended_list_bound_is_inclusive() {
    let mut state = valid_state();
    state.ended = ended(super::MAX_ENDED);
    state.validate().unwrap();
    state.ended = ended(super::MAX_ENDED + 1);
    assert!(state.validate().is_err());
}

#[test]
fn duplicate_ended_fingerprint_refuses() {
    let mut state = valid_state();
    let chain = super::EndedChain {
        fingerprint: fingerprint(0),
        reason_class: super::EndedReason::Banned,
        ended_at: 1,
    };
    state.ended = vec![chain, chain];
    assert!(state.validate().is_err());
}

#[test]
fn device_revocation_bound_is_inclusive() {
    let mut state = valid_state();
    state.revocations.devices = (0..cplc::MAX_ENTRIES).map(fingerprint).collect();
    state.validate().unwrap();
    state.revocations.devices = (0..cplc::MAX_ENTRIES + 1).map(fingerprint).collect();
    assert!(state.validate().is_err());
}

#[test]
fn passkey_revocation_bound_is_inclusive() {
    let mut state = valid_state();
    state.revocations.passkeys = (0..cplc::MAX_ENTRIES)
        .map(|index| format!("passkey-{index:05}").into_bytes())
        .collect();
    state.validate().unwrap();
    state.revocations.passkeys = (0..cplc::MAX_ENTRIES + 1)
        .map(|index| format!("passkey-{index:05}").into_bytes())
        .collect();
    assert!(state.validate().is_err());
}

#[test]
fn empty_passkey_credential_id_refuses() {
    let mut state = valid_state();
    state.revocations.passkeys = BTreeSet::from([Vec::new()]);
    assert!(state.validate().is_err());
}

#[test]
fn passkey_credential_id_length_bound_is_inclusive() {
    let mut state = valid_state();
    state.revocations.passkeys = BTreeSet::from([vec![7u8; 1024]]);
    state.validate().unwrap();
    state.revocations.passkeys = BTreeSet::from([vec![7u8; 1025]]);
    assert!(state.validate().is_err());
}

#[test]
fn incoherent_transition_history_refuses() {
    let mut state = valid_state();
    state.transitions = vec![cbcn::KeyTransition {
        revision: 0,
        proof: vec![1],
    }];
    assert!(state.validate().is_err());
}

#[test]
fn zero_revision_document_refuses() {
    let mut state = valid_state();
    state.documents = document(0, vec![1]);
    assert!(state.validate().is_err());
}

#[test]
fn document_ahead_of_state_revision_refuses() {
    let mut state = valid_state();
    state.revision = 5;
    state.documents = document(6, vec![1]);
    assert!(state.validate().is_err());
}

#[test]
fn empty_document_bytes_refuse() {
    let mut state = valid_state();
    state.documents = document(1, Vec::new());
    assert!(state.validate().is_err());
}

#[test]
fn document_size_bound_is_inclusive() {
    let mut state = valid_state();
    state.documents = document(1, vec![1u8; cplc::MAX_DOCUMENT_BYTES + 8192]);
    state.validate().unwrap();
    state.documents = document(1, vec![1u8; cplc::MAX_DOCUMENT_BYTES + 8192 + 1]);
    assert!(state.validate().is_err());
}

#[test]
fn manifest_entry_validates_like_documents() {
    let mut state = valid_state();
    state.manifest = Some(Signed {
        revision: 0,
        bytes: vec![1],
    });
    assert!(state.validate().is_err());
}

#[test]
fn stored_capacity_is_the_documented_sum() {
    assert_eq!(
        max_stored_bytes(),
        cplc::MAX_DOCUMENT_BYTES
            + 6 * 4 * (cplc::MAX_DOCUMENT_BYTES + 8192)
            + 4 * cbcn::MAX_KEY_TRANSITION_BYTES
    );
}

async fn stored(value: Vec<u8>, deadline: u64) -> MemoryStore {
    let store = MemoryStore::new("wallet-state-test").unwrap();
    let key = Key::new("wallet", "publications");
    let read = store.read(std::slice::from_ref(&key)).await.unwrap();
    store
        .compare_exchange(
            &read,
            vec![Change {
                key: key.clone(),
                record: Some(Record { value, deadline }),
            }],
        )
        .await
        .unwrap();
    store
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_deadline_refuses_even_with_valid_bytes() {
    let state = valid_state();
    let value = serde_json::to_vec(&state).unwrap();
    let store = stored(value, 1).await;
    assert!(
        open(&store, state.config.clone(), ring_bytes("wallet"), 0)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_bytes_at_exact_capacity_open() {
    let capacity = max_stored_bytes();
    // A mutated capacity would demand an absurd allocation; refuse that before
    // resizing so the mutant fails fast instead of hanging the suite.
    assert!(capacity < 1 << 31, "capacity {capacity} beyond sane bound");
    let state = valid_state();
    let mut value = serde_json::to_vec(&state).unwrap();
    value.resize(capacity, b' ');
    assert_eq!(value.len(), capacity);
    let store = stored(value, 0).await;
    let retained = open(&store, state.config.clone(), ring_bytes("wallet"), 0)
        .await
        .unwrap();
    assert_eq!(retained.state.revision, state.revision);
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_bytes_over_capacity_refuse() {
    let capacity = max_stored_bytes();
    assert!(capacity < 1 << 31, "capacity {capacity} beyond sane bound");
    let state = valid_state();
    let mut value = serde_json::to_vec(&state).unwrap();
    value.resize(capacity + 1, b' ');
    let store = stored(value, 0).await;
    assert!(
        open(&store, state.config.clone(), ring_bytes("wallet"), 0)
            .await
            .is_err()
    );
}

/// A valid state serializing to exactly the stored capacity is accepted by
/// [`change`]: the capacity arm fires only past the bound, never at it.
#[test]
fn change_at_exact_capacity_is_accepted() {
    let mut state = valid_state();
    state.config = configuration_with(5000, cplc::MAX_ENTRIES);
    state.key_ring = big_ring_bytes();
    state.revision = LIMIT;
    state.epoch = LIMIT;
    // Every size-capped collection at its bound, filled with wide (3-digit)
    // values so the JSON form starts strictly above the capacity.
    let wide = vec![255u8; cplc::MAX_DOCUMENT_BYTES + 8192];
    state.documents = BTreeMap::from([
        (
            cplc::SnapshotKind::Settings,
            Signed {
                revision: LIMIT,
                bytes: wide.clone(),
            },
        ),
        (
            cplc::SnapshotKind::Schema,
            Signed {
                revision: LIMIT,
                bytes: wide.clone(),
            },
        ),
        (
            cplc::SnapshotKind::SchemaVersions,
            Signed {
                revision: LIMIT,
                bytes: wide.clone(),
            },
        ),
        (
            cplc::SnapshotKind::Communities,
            Signed {
                revision: LIMIT,
                bytes: wide.clone(),
            },
        ),
        (
            cplc::SnapshotKind::RevocationList,
            Signed {
                revision: LIMIT,
                bytes: wide.clone(),
            },
        ),
    ]);
    state.manifest = Some(Signed {
        revision: LIMIT,
        bytes: wide,
    });
    state.transitions = (1..=256u64)
        .map(|revision| cbcn::KeyTransition {
            revision,
            proof: vec![255u8; 4096],
        })
        .collect();
    state.revocations.devices = (0..cplc::MAX_ENTRIES).map(fingerprint).collect();
    state.revocations.passkeys = (0..cplc::MAX_ENTRIES).map(|_| vec![255u8; 1024]).collect();
    state.ended = ended(super::MAX_ENDED);
    for chain in state.ended.iter_mut() {
        chain.ended_at = LIMIT;
    }
    state.validate().unwrap();
    // Trim one document in whole (4-byte) elements, then narrow single digit
    // widths for the final 0-3 bytes, landing exactly on the capacity.
    let target = max_stored_bytes();
    let len = serde_json::to_vec(&state).unwrap().len();
    assert!(len >= target, "giant state {len} below capacity {target}");
    let mut rest = (len - target) % 4;
    {
        let (_, first) = state.documents.iter_mut().next().unwrap();
        let drop_elements = (len - target) / 4;
        assert!(drop_elements < first.bytes.len());
        first.bytes.truncate(first.bytes.len() - drop_elements);
        for byte in first.bytes.iter_mut() {
            if rest == 0 {
                break;
            }
            if rest >= 2 {
                *byte = 9;
                rest -= 2;
            } else {
                *byte = 99;
                rest -= 1;
            }
        }
    }
    assert_eq!(rest, 0);
    let value = serde_json::to_vec(&state).unwrap();
    assert_eq!(value.len(), target);
    change(&state).unwrap();
}
