//! Kill test for the wallet_passkey_certificate day-floor survivor in the
//! mut138 brief (certificate.rs:143:56 `*` -> `/`).
//!
//! The certificate's `issued` time must be the day floor of the final
//! observation (`observed_at / 86_400 * 86_400`). The `/` mutant passes
//! `observed_at / 86_400 / 86_400`, which is the epoch for any clock in the
//! second day, so `issued_at` is 0 instead of one day.

use crate::SoftwareToken;
use cgbl::{storage::MemoryStore, *};
use cpsd::rand::{SeedableRng, rngs::StdRng};
use std::{collections::BTreeSet, sync::Arc};

const DAY: u64 = 86_400;
const NOW: u64 = 100;
const COHORT: u64 = 5 * DAY;
const RP: &str = "wallet.example.test";
const ORIGIN: &str = "https://vault.wallet.example.test";

type Facade = Global<MemoryStore, csgn::MemoryStore, cpsd::MemoryStore>;
type WalletOwner = Wallet<MemoryStore, csgn::MemoryStore>;

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

async fn install(
    global: &Facade,
    revision: u64,
    epoch: u64,
    expiry: u64,
    now: u64,
    provider: &str,
) -> Result<()> {
    let mut authority = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "global-authority",
        csgn::SecretKey::from_seed(&mut [3; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    let policy = Policy {
        version: 1,
        scope: "global".into(),
        revision,
        epoch,
        shared_expiry: expiry,
        gates: vec![GatePolicy {
            gate: "phone".into(),
            provider: provider.into(),
            uniqueness: true,
        }],
    };
    let bytes = authority
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&policy).unwrap(),
            now / DAY * DAY,
            expiry + DAY,
        )
        .await
        .unwrap();
    global
        .install_policy(&bytes, authority.key_ring().unwrap(), now)
        .await
}

async fn open(
    store: MemoryStore,
    keys: csgn::MemoryStore,
    issuance: cpsd::MemoryStore,
    reopen: bool,
) -> Facade {
    let key = csgn::SecretKey::from_seed(&mut [2; 32]);
    let signer = if reopen {
        csgn::PersistentSigner::open(keys, "cgbl:global", key, 0)
            .await
            .unwrap()
    } else {
        csgn::PersistentSigner::create(keys, "cgbl:global", key, 0, 30 * DAY)
            .await
            .unwrap()
    };
    Global::open(
        store,
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
    .unwrap()
}

async fn make() -> (Facade, MemoryStore, csgn::MemoryStore, cpsd::MemoryStore) {
    let store = MemoryStore::new("global").unwrap();
    let keys = csgn::MemoryStore::default();
    let issuance = cpsd::MemoryStore::new(cpsd::CommunityId::new(b"global").unwrap(), 2).unwrap();
    let global = open(store.clone(), keys.clone(), issuance.clone(), false).await;
    install(&global, 1, 1, COHORT, 100, "sms").await.unwrap();
    (global, store, keys, issuance)
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
        2 * DAY,
    )
    .unwrap()
}

async fn enrolled() -> (
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
        let mut token = SoftwareToken::new(true).unwrap().0;
        let member = ckyh::Uuid::from_u128(27);
        let (mut challenge, pending) = owner.start_registration(member).unwrap();
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

async fn wallet(
    global: &Facade,
    keys: Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
    store: csgn::MemoryStore,
    reopen: bool,
) -> WalletOwner {
    let secret = csgn::SecretKey::from_seed(&mut [47; 32]);
    let signer = if reopen {
        csgn::PersistentSigner::open(store, "wallet", secret, 0)
            .await
            .unwrap()
    } else {
        csgn::PersistentSigner::create(store, "wallet", secret, 0, 30 * DAY)
            .await
            .unwrap()
    };
    global
        .open_wallet(signer, configuration(), keys, NOW)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn certificate_issued_time_is_the_day_floor_of_the_final_observation() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, authentication) = enrolled().await;
    let mut wallet = wallet(&global, keys, csgn::MemoryStore::default(), false).await;
    // Second day: the floor is DAY, while observed/86400/86400 is 0.
    let clock = DAY + 100;
    let issued = global
        .wallet_passkey_certificate(&mut wallet, &authentication, clock + 60, &|| clock)
        .await
        .unwrap();
    assert_eq!(issued.checked_at(), clock);
    let verified = ckyh::certificate::verify(
        wallet.key_ring().unwrap(),
        issued.bytes(),
        &authentication.member().to_string(),
        clock,
    )
    .unwrap();
    assert_eq!(verified.issued_at(), DAY);
}
