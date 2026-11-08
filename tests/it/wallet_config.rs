//! Focused validation tests for [`cgbl::WalletPublicationConfig`] and the
//! `EndedChain` hex codec in `cgbl/src/wallet.rs`.
//!
//! Each invalid case isolates a single disjunct so that every `||` -> `&&`
//! mutant (and every boundary/comparison/arithmetic mutant) flips the verdict.

use cgbl::WalletPublicationConfig;
use std::collections::BTreeSet;

const RP: &str = "wallet.example.test";
const ORIGIN: &str = "https://vault.wallet.example.test/";
const DAY: u64 = 86_400;

fn rulebook() -> crbk::Rulebook {
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
    book
}

fn pad_rulebook(extra: usize, pad_len: usize) -> crbk::Rulebook {
    let mut book = rulebook();
    for index in 0..extra {
        book.define(
            format!("pad{index:05}"),
            crbk::Setting {
                value_type: crbk::SettingType::String,
                nullable: false,
                default: serde_json::Value::String("y".repeat(512)),
                bounds: crbk::Bounds::default(),
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    }
    book.define(
        "pad_tunable",
        crbk::Setting {
            value_type: crbk::SettingType::String,
            nullable: false,
            default: serde_json::Value::String("x".repeat(pad_len)),
            bounds: crbk::Bounds::default(),
            lowest_layer: crbk::Layer::Community,
            kind: crbk::SettingKind::Technical,
        },
    )
    .unwrap();
    book
}

fn field(id: String) -> cshm::Field {
    cshm::Field {
        id,
        label: "Receive invitations?".into(),
        kind: cshm::FieldType::YesNo,
        required: true,
        filterable: false,
        change_preset: cshm::ChangePreset::Stable,
        no_contact_details: false,
    }
}

fn schema(version: u32, community: &str, public: usize, private: usize) -> cshm::Schema {
    cshm::Schema {
        community: community.into(),
        version,
        public: (0..public).map(|i| field(format!("p{i:04}"))).collect(),
        private: (0..private).map(|i| field(format!("q{i:04}"))).collect(),
    }
}

fn single_schemas() -> cplc::SchemaVersions {
    cplc::SchemaVersions {
        purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
        current: 1,
        versions: vec![cplc::SchemaVersion {
            schema: schema(1, "wallet", 1, 0),
            changes: None,
        }],
    }
}

fn chained_schemas(count: u32) -> cplc::SchemaVersions {
    let mut versions = Vec::new();
    let mut previous: Option<cshm::Schema> = None;
    for version in 1..=count {
        let next = schema(version, "wallet", 1, 0);
        let changes = previous
            .as_ref()
            .map(|prior| cshm::classify_changes(prior, &next).unwrap());
        versions.push(cplc::SchemaVersion {
            schema: next.clone(),
            changes,
        });
        previous = Some(next);
    }
    cplc::SchemaVersions {
        purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
        current: count,
        versions,
    }
}

fn build(
    origin: &str,
    snapshot_seconds: u64,
    schemas: cplc::SchemaVersions,
    communities: BTreeSet<String>,
) -> Result<WalletPublicationConfig, cgbl::Error> {
    WalletPublicationConfig::new(
        RP,
        origin,
        rulebook(),
        schemas,
        communities,
        snapshot_seconds,
    )
}

fn build_with_book(
    book: crbk::Rulebook,
    snapshot_seconds: u64,
    schemas: cplc::SchemaVersions,
    communities: BTreeSet<String>,
) -> Result<WalletPublicationConfig, cgbl::Error> {
    WalletPublicationConfig::new(RP, ORIGIN, book, schemas, communities, snapshot_seconds)
}

fn valid() -> WalletPublicationConfig {
    build(ORIGIN, 2 * DAY, single_schemas(), BTreeSet::new()).unwrap()
}

#[test]
fn valid_configuration_is_accepted() {
    let config = valid();
    let bytes = serde_json::to_vec(&config).unwrap();
    assert!(!bytes.is_empty());
    assert!(bytes.len() < cplc::MAX_DOCUMENT_BYTES);
}

// ---- Origin disjuncts: each bad origin alone must be rejected. ----

#[test]
fn http_scheme_is_rejected() {
    assert!(
        build(
            "http://vault.wallet.example.test/",
            2 * DAY,
            single_schemas(),
            BTreeSet::new()
        )
        .is_err()
    );
}

#[test]
fn wrong_host_is_rejected() {
    assert!(
        build(
            "https://vault.other.example.test/",
            2 * DAY,
            single_schemas(),
            BTreeSet::new()
        )
        .is_err()
    );
}

#[test]
fn non_root_path_is_rejected() {
    assert!(
        build(
            "https://vault.wallet.example.test/extra",
            2 * DAY,
            single_schemas(),
            BTreeSet::new()
        )
        .is_err()
    );
}

#[test]
fn query_string_is_rejected() {
    assert!(
        build(
            "https://vault.wallet.example.test/?x=1",
            2 * DAY,
            single_schemas(),
            BTreeSet::new()
        )
        .is_err()
    );
}

#[test]
fn fragment_is_rejected() {
    assert!(
        build(
            "https://vault.wallet.example.test/#frag",
            2 * DAY,
            single_schemas(),
            BTreeSet::new()
        )
        .is_err()
    );
}

#[test]
fn username_is_rejected() {
    assert!(
        build(
            "https://user@vault.wallet.example.test/",
            2 * DAY,
            single_schemas(),
            BTreeSet::new()
        )
        .is_err()
    );
}

#[test]
fn password_without_username_is_rejected() {
    assert!(
        build(
            "https://:pass@vault.wallet.example.test/",
            2 * DAY,
            single_schemas(),
            BTreeSet::new()
        )
        .is_err()
    );
}

// ---- Snapshot / collection disjuncts. ----

#[test]
fn zero_snapshot_is_rejected() {
    assert!(build(ORIGIN, 0, single_schemas(), BTreeSet::new()).is_err());
}

#[test]
fn non_day_snapshot_is_rejected() {
    assert!(build(ORIGIN, 1, single_schemas(), BTreeSet::new()).is_err());
}

#[test]
fn snapshot_above_i64_max_is_rejected() {
    let huge = ((i64::MAX as u64) / DAY + 1) * DAY;
    assert!(huge > i64::MAX as u64);
    assert_eq!(huge % DAY, 0);
    assert!(build(ORIGIN, huge, single_schemas(), BTreeSet::new()).is_err());
}

#[test]
fn empty_schema_history_is_rejected() {
    let schemas = cplc::SchemaVersions {
        purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
        current: 0,
        versions: Vec::new(),
    };
    assert!(build(ORIGIN, 2 * DAY, schemas, BTreeSet::new()).is_err());
}

#[test]
fn schema_history_above_max_entries_is_rejected() {
    assert!(build(ORIGIN, 2 * DAY, chained_schemas(257), BTreeSet::new()).is_err());
}

#[test]
fn schema_history_at_max_entries_is_accepted() {
    build(ORIGIN, 2 * DAY, chained_schemas(256), BTreeSet::new()).unwrap();
}

#[test]
fn communities_above_max_entries_are_rejected() {
    let communities: BTreeSet<String> = (0..257).map(|i| format!("c{i:04}")).collect();
    assert!(build(ORIGIN, 2 * DAY, single_schemas(), communities).is_err());
}

#[test]
fn communities_at_max_entries_are_accepted() {
    let communities: BTreeSet<String> = (0..256).map(|i| format!("c{i:04}")).collect();
    build(ORIGIN, 2 * DAY, single_schemas(), communities).unwrap();
}

// ---- Per-schema disjuncts. ----

#[test]
fn foreign_schema_community_is_rejected() {
    let schemas = cplc::SchemaVersions {
        purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
        current: 1,
        versions: vec![cplc::SchemaVersion {
            schema: schema(1, "other", 1, 0),
            changes: None,
        }],
    };
    assert!(build(ORIGIN, 2 * DAY, schemas, BTreeSet::new()).is_err());
}

#[test]
fn schema_fields_above_max_entries_are_rejected() {
    let schemas = cplc::SchemaVersions {
        purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
        current: 1,
        versions: vec![cplc::SchemaVersion {
            schema: schema(1, "wallet", 257, 0),
            changes: None,
        }],
    };
    assert!(build(ORIGIN, 2 * DAY, schemas, BTreeSet::new()).is_err());
}

#[test]
fn schema_fields_at_max_entries_are_accepted() {
    let schemas = cplc::SchemaVersions {
        purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
        current: 1,
        versions: vec![cplc::SchemaVersion {
            schema: schema(1, "wallet", 200, 56),
            changes: None,
        }],
    };
    build(ORIGIN, 2 * DAY, schemas, BTreeSet::new()).unwrap();
}

#[test]
fn field_sum_uses_addition_not_subtraction() {
    // 200 + 100 = 300 > 256 rejects; 200 - 100 = 100 would wrongly accept.
    let schemas = cplc::SchemaVersions {
        purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
        current: 1,
        versions: vec![cplc::SchemaVersion {
            schema: schema(1, "wallet", 200, 100),
            changes: None,
        }],
    };
    assert!(build(ORIGIN, 2 * DAY, schemas, BTreeSet::new()).is_err());
}

#[test]
fn field_sum_uses_addition_not_multiplication() {
    // 200 + 2 = 202 <= 256 accepts; 200 * 2 = 400 would wrongly reject.
    let schemas = cplc::SchemaVersions {
        purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
        current: 1,
        versions: vec![cplc::SchemaVersion {
            schema: schema(1, "wallet", 200, 2),
            changes: None,
        }],
    };
    build(ORIGIN, 2 * DAY, schemas, BTreeSet::new()).unwrap();
}

#[test]
fn increasing_schema_history_is_accepted() {
    build(ORIGIN, 2 * DAY, chained_schemas(2), BTreeSet::new()).unwrap();
}

#[test]
fn non_increasing_schema_history_is_rejected() {
    let first = schema(1, "wallet", 1, 0);
    let repeat = schema(1, "wallet", 1, 0);
    let schemas = cplc::SchemaVersions {
        purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
        current: 1,
        versions: vec![
            cplc::SchemaVersion {
                schema: first,
                changes: None,
            },
            cplc::SchemaVersion {
                schema: repeat,
                changes: None,
            },
        ],
    };
    assert!(build(ORIGIN, 2 * DAY, schemas, BTreeSet::new()).is_err());
}

#[test]
fn oversized_second_version_is_rejected_before_classification() {
    // 257 fields with a strictly increasing version: the field-count check
    // must reject even though the version ordering is fine.
    let first = schema(1, "wallet", 1, 0);
    let big = schema(2, "wallet", 257, 0);
    let changes = cshm::classify_changes(&first, &big).unwrap();
    let schemas = cplc::SchemaVersions {
        purpose: cplc::SchemaVersionsPurpose::SchemaVersionsV1,
        current: 2,
        versions: vec![
            cplc::SchemaVersion {
                schema: first,
                changes: None,
            },
            cplc::SchemaVersion {
                schema: big,
                changes: Some(changes),
            },
        ],
    };
    assert!(build(ORIGIN, 2 * DAY, schemas, BTreeSet::new()).is_err());
}

// ---- Trailing current/document-size disjuncts. ----

#[test]
fn mismatched_current_version_is_rejected() {
    let mut schemas = single_schemas();
    schemas.current = 2;
    assert!(build(ORIGIN, 2 * DAY, schemas, BTreeSet::new()).is_err());
}

fn config_json_len(book: &crbk::Rulebook) -> usize {
    let value = serde_json::json!({
        "rp_id": RP,
        "passkey_origin": ORIGIN,
        "rulebook": book,
        "schemas": single_schemas(),
        "communities": BTreeSet::<String>::new(),
        "snapshot_seconds": 2 * DAY,
    });
    serde_json::to_vec(&value).unwrap().len()
}

#[test]
fn document_above_max_bytes_is_rejected() {
    let mut book = pad_rulebook(0, 512);
    while config_json_len(&book) <= cplc::MAX_DOCUMENT_BYTES {
        let mut grown = book.clone();
        grown
            .define(
                format!("padg{}", grown.catalog().len()),
                crbk::Setting {
                    value_type: crbk::SettingType::String,
                    nullable: false,
                    default: serde_json::Value::String("y".repeat(65536)),
                    bounds: crbk::Bounds::default(),
                    lowest_layer: crbk::Layer::Community,
                    kind: crbk::SettingKind::Technical,
                },
            )
            .unwrap();
        book = grown;
    }
    assert!(config_json_len(&book) > cplc::MAX_DOCUMENT_BYTES);
    assert!(build_with_book(book, 2 * DAY, single_schemas(), BTreeSet::new()).is_err());
}

#[test]
fn document_at_exact_max_bytes_is_accepted() {
    let mut pad_len = 512;
    let mut book = pad_rulebook(0, pad_len);
    while config_json_len(&book) > cplc::MAX_DOCUMENT_BYTES {
        pad_len /= 2;
        book = pad_rulebook(0, pad_len);
    }
    let deficit = cplc::MAX_DOCUMENT_BYTES - config_json_len(&book);
    book = pad_rulebook(0, pad_len + deficit);
    assert_eq!(config_json_len(&book), cplc::MAX_DOCUMENT_BYTES);
    build_with_book(book, 2 * DAY, single_schemas(), BTreeSet::new()).unwrap();
}

// ---- EndedChain hex codec. ----

fn ended_json(fingerprint_hex: &str) -> String {
    format!(r#"{{"fingerprint":"{fingerprint_hex}","reason_class":"banned","ended_at":100}}"#)
}

#[test]
fn ended_chain_hex_round_trips_distinct_bytes() {
    let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
    let chain = cgbl::EndedChain {
        fingerprint: bytes,
        reason_class: cgbl::EndedReason::Banned,
        ended_at: 100,
    };
    let text = serde_json::to_string(&chain).unwrap();
    assert!(text.contains("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    let back: cgbl::EndedChain = serde_json::from_str(&text).unwrap();
    assert_eq!(back.fingerprint, bytes);
    assert_eq!(back.reason_class, cgbl::EndedReason::Banned);
    assert_eq!(back.ended_at, 100);
}

#[test]
fn ended_chain_rejects_uppercase_hex() {
    assert!(serde_json::from_str::<cgbl::EndedChain>(&ended_json(&"AB".repeat(32))).is_err());
}

#[test]
fn ended_chain_rejects_wrong_length_hex() {
    assert!(serde_json::from_str::<cgbl::EndedChain>(&ended_json(&"ab".repeat(33))).is_err());
}

#[test]
fn ended_chain_rejects_short_hex() {
    assert!(serde_json::from_str::<cgbl::EndedChain>(&ended_json("ab")).is_err());
}
