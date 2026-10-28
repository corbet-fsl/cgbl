//! Genuine Global/Keyhole/signing/Beacon owners, never a member Authority fixture.
use super::*;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};
#[path = "birth.rs"]
mod birth;

const RP: &str = "wallet.example.test";
const ORIGIN: &str = "https://vault.wallet.example.test";
const NOW: u64 = 100;
type WalletOwner = Wallet<MemoryStore, csgn::MemoryStore>;

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
    })).unwrap();
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
        let mut token = SoftToken::new(true).unwrap().0;
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
async fn original_wallet_feed_and_certificate_stay_separate_from_passport_and_community() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, authentication) = enrolled().await;
    let mut wallet = wallet(&global, keys, csgn::MemoryStore::default(), false).await;
    let ring = wallet.key_ring().unwrap().to_cbor();
    assert_eq!(wallet.key_ring().unwrap().issuer(), "wallet");
    assert_eq!(global.key_ring().unwrap().issuer(), "cgbl:global");
    let feed = wallet.trust_feed(NOW).await.unwrap();
    let mut charter = cchr::Charter::new(cchr::Configuration {
        origin: ORIGIN.into(),
        community: "wallet".into(),
        key_ring: ring,
        minimum_revision: 1,
        ring_revision: 0,
    })
    .unwrap();
    charter
        .install(&serde_json::to_vec(&feed).unwrap(), NOW)
        .unwrap();
    assert_eq!(
        charter.current(NOW).unwrap().settings(NOW).unwrap().content["quota"],
        17
    );
    let issued = global
        .wallet_passkey_certificate(&mut wallet, &authentication, NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert_eq!(issued.checked_at(), NOW);
    let certificate = ckyh::certificate::verify(
        wallet.key_ring().unwrap(),
        issued.bytes(),
        &authentication.member().to_string(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        certificate.credential_id(),
        authentication.credential_id().as_ref()
    );
    assert!(
        ckyh::certificate::verify(
            global.key_ring().unwrap(),
            issued.bytes(),
            &authentication.member().to_string(),
            NOW
        )
        .is_err()
    );
    let community_signer = csgn::Signer::new(
        "community",
        csgn::SecretKey::from_seed(&mut [48; 32]),
        0,
        30 * DAY,
    )
    .unwrap();
    let mut community = cchr::Charter::new(cchr::Configuration {
        origin: "https://community.example.test".into(),
        community: "community".into(),
        key_ring: community_signer.key_ring().to_cbor(),
        minimum_revision: 1,
        ring_revision: 0,
    })
    .unwrap();
    assert!(
        community
            .install(&serde_json::to_vec(&feed).unwrap(), NOW)
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_global_self_ban_and_key_tombstone_refuse_issuance_without_revival() {
    for revoke in [false, true] {
        let (global, _, _, _) = make().await;
        let (_directory, keys, authentication) = enrolled().await;
        let mut wallet = wallet(&global, keys.clone(), csgn::MemoryStore::default(), false).await;
        if revoke {
            let auth = authentication.clone();
            tokio::task::spawn_blocking(move || keys.revoke(auth.member(), auth.credential_id()))
                .await
                .unwrap()
                .unwrap();
        } else {
            global
                .burn(
                    &subject(&authentication.member().to_string()),
                    Burn::Permanent(PermanentReason::SelfBan),
                    NOW,
                )
                .await
                .unwrap();
        }
        assert!(
            global
                .wallet_passkey_certificate(&mut wallet, &authentication, NOW + 60, &|| NOW)
                .await
                .is_err()
        );
        assert!(wallet.key_ring().is_err());
        assert!(
            global
                .wallet_passkey_certificate(&mut wallet, &authentication, NOW + 60, &|| NOW)
                .await
                .is_err()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn device_binding_and_revocation_use_actual_original_rows_and_opaque_public_ids() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, authentication) = enrolled().await;
    let mut wallet = wallet(&global, keys.clone(), csgn::MemoryStore::default(), false).await;
    let observed = global
        .authorize_wallet_device(&mut wallet, &authentication, [49; 32], NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert_eq!(observed.devices(), &[[49; 32]]);
    assert_eq!(observed.member(), authentication.member().to_string());
    wallet.trust_feed(NOW).await.unwrap();
    let auth = authentication.clone();
    tokio::task::spawn_blocking(move || keys.revoke(auth.member(), auth.credential_id()))
        .await
        .unwrap()
        .unwrap();
    let feed = wallet.trust_feed(NOW).await.unwrap();
    let signed = wallet
        .key_ring()
        .unwrap()
        .verify(&feed.revocations, csgn::Kind::RevocationListSnapshot, NOW)
        .unwrap();
    let view: cplc::Snapshot<cplc::Revocations> = serde_json::from_slice(signed.payload()).unwrap();
    assert!(view.content.members.is_empty());
    assert!(view.content.devices.contains(&[49; 32]));
    assert!(
        view.content
            .passkeys
            .contains(authentication.credential_id().as_ref())
    );
    assert!(
        !String::from_utf8_lossy(signed.payload()).contains(&authentication.member().to_string())
    );
}

/// Only the transport timing is gated; all storage reads and CAS use the actual
/// original shared MemoryStore and owner-created signed material.
#[derive(Clone)]
struct GatedStore {
    inner: MemoryStore,
    mode: Arc<std::sync::atomic::AtomicU8>,
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
impl GatedStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new("global").unwrap(),
            mode: Arc::default(),
            reached: Arc::default(),
            release: Arc::default(),
        }
    }
}
impl Store for GatedStore {
    fn scope(&self) -> &str {
        self.inner.scope()
    }
    async fn read(&self, keys: &[storage::Key]) -> Result<storage::ReadSet> {
        self.inner.read(keys).await
    }
    async fn list(&self, bucket: &str, after: &str, limit: u32) -> Result<storage::ReadSet> {
        self.inner.list(bucket, after, limit).await
    }
    async fn expired(&self, now: u64, limit: u32) -> Result<storage::ReadSet> {
        self.inner.expired(now, limit).await
    }
    async fn compare_exchange(
        &self,
        read: &storage::ReadSet,
        changes: Vec<storage::Change>,
    ) -> Result<()> {
        let mode = if changes.iter().any(|change| change.key.bucket == "wallet") {
            self.mode.swap(0, Ordering::SeqCst)
        } else {
            0
        };
        if mode == 1 {
            self.reached.notify_one();
            self.release.notified().await;
        }
        self.inner.compare_exchange(read, changes).await?;
        if mode == 2 {
            self.reached.notify_one();
            self.release.notified().await;
        }
        if mode == 3 {
            return Err(Error::Storage);
        }
        Ok(())
    }
}
type GatedGlobal = Global<GatedStore, csgn::MemoryStore, cpsd::MemoryStore>;
async fn gated_global(store: GatedStore) -> GatedGlobal {
    Global::open(
        store,
        cpsd::MemoryStore::new(cpsd::CommunityId::new(b"global").unwrap(), 2).unwrap(),
        issuer(),
        csgn::PersistentSigner::create(
            csgn::MemoryStore::default(),
            "cgbl:global",
            csgn::SecretKey::from_seed(&mut [2; 32]),
            0,
            30 * DAY,
        )
        .await
        .unwrap(),
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
async fn gated_wallet(
    global: &GatedGlobal,
    keys: Arc<ckyh::Passkeys<ckyh::LibsqlStore>>,
    signer_store: csgn::MemoryStore,
    reopen: bool,
) -> Wallet<GatedStore, csgn::MemoryStore> {
    let secret = csgn::SecretKey::from_seed(&mut [47; 32]);
    let signer = if reopen {
        csgn::PersistentSigner::open(signer_store, "wallet", secret, 0)
            .await
            .unwrap()
    } else {
        csgn::PersistentSigner::create(signer_store, "wallet", secret, 0, 30 * DAY)
            .await
            .unwrap()
    };
    global
        .open_wallet(signer, configuration(), keys, NOW)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_cas_cancellation_and_unknown_require_reopening_the_same_durable_winner() {
    for mode in 1..=3 {
        let store = GatedStore::new();
        let global = gated_global(store.clone()).await;
        let (_directory, keys, auth) = enrolled().await;
        let signer_store = csgn::MemoryStore::default();
        let mut owner = gated_wallet(&global, keys.clone(), signer_store.clone(), false).await;
        store.mode.store(mode, Ordering::SeqCst);
        if mode == 3 {
            assert!(
                global
                    .authorize_wallet_device(&mut owner, &auth, [49; 32], NOW + 60, &|| NOW)
                    .await
                    .is_err()
            );
        } else {
            let mut attempt = Box::pin(global.authorize_wallet_device(
                &mut owner,
                &auth,
                [49; 32],
                NOW + 60,
                &|| NOW,
            ));
            tokio::select! {
                _ = store.reached.notified() => (),
                result = &mut attempt => panic!("CAS gate did not suspend: {}", result.is_err()),
            }
            drop(attempt);
        }
        assert!(owner.key_ring().is_err());
        drop(owner);
        let mut reopened = gated_wallet(&global, keys, signer_store, true).await;
        let current = global
            .wallet_devices(&mut reopened, &auth, NOW + 60, &|| NOW)
            .await
            .unwrap();
        assert_eq!(
            current.devices(),
            if mode == 1 { &[][..] } else { &[[49; 32]][..] }
        );
        global
            .authorize_wallet_device(&mut reopened, &auth, [49; 32], NOW + 60, &|| NOW)
            .await
            .unwrap();
        reopened.trust_feed(NOW).await.unwrap();
        let key = storage::Key::new("wallet-device", auth.member().to_string());
        let read = store.inner.read(std::slice::from_ref(&key)).await.unwrap();
        let row: serde_json::Value = serde_json::from_slice(&read.records[&key].value).unwrap();
        assert_eq!(row["pending"], false);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_actual_mutation_generation_cannot_acknowledge_or_return_the_older_feed() {
    let store = GatedStore::new();
    let global = gated_global(store.clone()).await;
    let (_directory, keys, auth) = enrolled().await;
    let signer_store = csgn::MemoryStore::default();
    let mut owner = gated_wallet(&global, keys.clone(), signer_store.clone(), false).await;
    global
        .authorize_wallet_device(&mut owner, &auth, [49; 32], NOW + 60, &|| NOW)
        .await
        .unwrap();
    let mut competing = gated_wallet(&global, keys.clone(), signer_store.clone(), true).await;
    let mutation = global.wallet_mutation(&mut competing).await.unwrap();
    global
        .signal_wallet_key_mutation(&mut competing, &auth, &mutation, NOW + 60, &|| NOW)
        .await
        .unwrap();
    let reached = Arc::new(tokio::sync::Notify::new());
    let entered = reached.clone();
    let (release, wait) = std::sync::mpsc::channel();
    let current = auth.clone();
    let mut worker = Box::pin(mutation.execute(move |keys| {
        entered.notify_one();
        wait.recv().unwrap();
        keys.revoke(current.member(), current.credential_id())
    }));
    tokio::select! {
        _ = reached.notified() => (),
        result = &mut worker => panic!("original worker did not suspend: {}", result.is_err()),
    }
    let mut older_feed = Box::pin(owner.trust_feed(NOW));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut older_feed)
            .await
            .is_err()
    );
    release.send(()).unwrap();
    worker.await.unwrap();
    assert!(older_feed.await.is_err());
    assert!(owner.key_ring().is_err());
    drop(owner);
    drop(competing);
    let mut reopened = gated_wallet(&global, keys, signer_store, true).await;
    let feed = reopened.trust_feed(NOW).await.unwrap();
    let signed = reopened
        .key_ring()
        .unwrap()
        .verify(&feed.revocations, csgn::Kind::RevocationListSnapshot, NOW)
        .unwrap();
    let view: cplc::Snapshot<cplc::Revocations> = serde_json::from_slice(signed.payload()).unwrap();
    assert!(view.content.devices.contains(&[49; 32]));
    assert!(
        view.content
            .passkeys
            .contains(auth.credential_id().as_ref())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn committed_binding_final_clock_refusal_is_terminal_and_preserves_the_winner() {
    for returned_at in [NOW - 1, NOW + 60] {
        let store = GatedStore::new();
        let global = gated_global(store.clone()).await;
        let (_directory, keys, auth) = enrolled().await;
        let signer_store = csgn::MemoryStore::default();
        let mut owner = gated_wallet(&global, keys.clone(), signer_store.clone(), false).await;
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(NOW));
        let sample = || clock.load(Ordering::SeqCst);
        store.mode.store(2, Ordering::SeqCst);
        let mut attempt = Box::pin(global.authorize_wallet_device(
            &mut owner,
            &auth,
            [49; 32],
            NOW + 60,
            &sample,
        ));
        tokio::select! {
            _ = store.reached.notified() => (),
            result = &mut attempt => panic!("post-CAS gate did not suspend: {}", result.is_err()),
        }
        clock.store(returned_at, Ordering::SeqCst);
        store.release.notify_one();
        assert!(matches!(attempt.await, Err(Error::Storage)));
        clock.store(NOW, Ordering::SeqCst);
        assert!(owner.key_ring().is_err());
        assert!(
            global
                .wallet_devices(&mut owner, &auth, NOW + 60, &sample)
                .await
                .is_err()
        );
        drop(owner);
        let mut reopened = gated_wallet(&global, keys, signer_store, true).await;
        let observation = global
            .wallet_devices(&mut reopened, &auth, NOW + 60, &|| NOW)
            .await
            .unwrap();
        assert_eq!(observation.devices(), &[[49; 32]]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn configured_origin_foreign_facade_and_exclusive_issuance_deadline_refuse() {
    let (global, _, _, _) = make().await;
    let (foreign, _, _, _) = make().await;
    let (_directory, keys, auth) = enrolled().await;
    let mut owner = wallet(&global, keys.clone(), csgn::MemoryStore::default(), false).await;
    assert!(
        foreign
            .wallet_passkey_certificate(&mut owner, &auth, NOW + 60, &|| NOW)
            .await
            .is_err()
    );
    // Foreign-owner refusal creates no certificate and does not counterfeit the
    // genuine owner's configuration or local lifetime.
    assert!(
        global
            .wallet_passkey_certificate(&mut owner, &auth, NOW, &|| NOW)
            .await
            .is_err()
    );
    assert!(owner.key_ring().is_err());
    // The bare wallet origin is no longer an accepted passkey origin.
    let mut bare: serde_json::Value = serde_json::to_value(configuration()).unwrap();
    bare["passkey_origin"] = "https://wallet.example.test/".into();
    let bare = serde_json::from_value(bare).unwrap();
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "wallet",
        csgn::SecretKey::from_seed(&mut [47; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    assert!(
        global
            .open_wallet(signer, bare, keys.clone(), NOW)
            .await
            .is_err()
    );
    let mut config: serde_json::Value = serde_json::to_value(configuration()).unwrap();
    config["rp_id"] = "wallet.other.example.test".into();
    config["passkey_origin"] = "https://vault.wallet.other.example.test/".into();
    let config = serde_json::from_value(config).unwrap();
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "wallet",
        csgn::SecretKey::from_seed(&mut [47; 32]),
        0,
        30 * DAY,
    )
    .await
    .unwrap();
    assert!(global.open_wallet(signer, config, keys, NOW).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_global_cannot_rotate_or_reconcile_and_mutate_the_original_stores() {
    for rotate in [false, true] {
        let (global, original, _, _) = make().await;
        let (_directory, keys, auth) = enrolled().await;
        let signer_store = csgn::MemoryStore::default();
        let mut owner = wallet(&global, keys.clone(), signer_store.clone(), false).await;
        global
            .authorize_wallet_device(&mut owner, &auth, [49; 32], NOW + 60, &|| NOW)
            .await
            .unwrap();
        let wallet_key = storage::Key::new("wallet", "publications");
        let before = original
            .read(std::slice::from_ref(&wallet_key))
            .await
            .unwrap();
        let signing_before = csgn::Store::load(&signer_store, "wallet").await.unwrap();
        drop(global);
        assert!(owner.key_ring().is_err());
        if rotate {
            assert!(
                owner
                    .rotate(csgn::SecretKey::from_seed(&mut [48; 32]), NOW)
                    .await
                    .is_err()
            );
        } else {
            let current = auth.clone();
            tokio::task::spawn_blocking(move || {
                keys.revoke(current.member(), current.credential_id())
            })
            .await
            .unwrap()
            .unwrap();
            assert!(owner.trust_feed(NOW).await.is_err());
        }
        let after = original
            .read(std::slice::from_ref(&wallet_key))
            .await
            .unwrap();
        assert_eq!(after.revisions, before.revisions);
        assert_eq!(
            after.records[&wallet_key].value,
            before.records[&wallet_key].value
        );
        assert_eq!(
            csgn::Store::load(&signer_store, "wallet").await.unwrap(),
            signing_before
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelled_sdk_waiter_cannot_release_the_worker_barrier_or_acknowledge_early() {
    for committed in [false, true] {
        let (global, original, _, _) = make().await;
        let (_directory, keys, auth) = enrolled().await;
        let mut owner = wallet(&global, keys.clone(), csgn::MemoryStore::default(), false).await;
        global
            .authorize_wallet_device(&mut owner, &auth, [49; 32], NOW + 60, &|| NOW)
            .await
            .unwrap();
        let mutation = global.wallet_mutation(&mut owner).await.unwrap();
        assert!(mutation.matches(&keys));
        global
            .signal_wallet_key_mutation(&mut owner, &auth, &mutation, NOW + 60, &|| NOW)
            .await
            .unwrap();
        let reached = Arc::new(tokio::sync::Notify::new());
        let entered = reached.clone();
        let (release, wait) = std::sync::mpsc::channel();
        let current = auth.clone();
        let mut worker = Box::pin(mutation.execute(move |keys| {
            if committed {
                keys.revoke(current.member(), current.credential_id())?;
            }
            entered.notify_one();
            wait.recv().unwrap();
            if !committed {
                keys.revoke(current.member(), current.credential_id())?;
            }
            Ok(())
        }));
        tokio::select! {
            _ = reached.notified() => (),
            result = &mut worker => panic!("SDK gate did not suspend: {}", result.is_err()),
        }
        drop(worker);
        let mut feed = Box::pin(owner.trust_feed(NOW));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut feed)
                .await
                .is_err()
        );
        let key = storage::Key::new("wallet-device", auth.member().to_string());
        let read = original.read(std::slice::from_ref(&key)).await.unwrap();
        let row: serde_json::Value = serde_json::from_slice(&read.records[&key].value).unwrap();
        assert_eq!(row["pending"], true);
        release.send(()).unwrap();
        let published = feed.await.unwrap();
        let signed = owner
            .key_ring()
            .unwrap()
            .verify(
                &published.revocations,
                csgn::Kind::RevocationListSnapshot,
                NOW,
            )
            .unwrap();
        let view: cplc::Snapshot<cplc::Revocations> =
            serde_json::from_slice(signed.payload()).unwrap();
        assert!(
            view.content
                .passkeys
                .contains(auth.credential_id().as_ref())
        );
        let read = original.read(std::slice::from_ref(&key)).await.unwrap();
        let row: serde_json::Value = serde_json::from_slice(&read.records[&key].value).unwrap();
        assert_eq!(row["pending"], false);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn before_spawn_cancellation_exact_sdk_identity_and_shutdown_join_are_original_owners() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, auth) = enrolled().await;
    let (_other_directory, other_keys, _) = enrolled().await;
    let mut owner = wallet(&global, keys.clone(), csgn::MemoryStore::default(), false).await;
    let mutation = global.wallet_mutation(&mut owner).await.unwrap();
    assert!(mutation.matches(&keys));
    assert!(!mutation.matches(&other_keys));
    drop(mutation); // No original SDK worker was started.
    global
        .wallet_devices(&mut owner, &auth, NOW + 60, &|| NOW)
        .await
        .unwrap();
    let mutation = global.wallet_mutation(&mut owner).await.unwrap();
    let shutdown = owner.shutdown_handle();
    let reached = Arc::new(tokio::sync::Notify::new());
    let entered = reached.clone();
    let (release, wait) = std::sync::mpsc::channel();
    let mut worker = Box::pin(mutation.execute(move |_| {
        entered.notify_one();
        wait.recv().unwrap();
        Ok(())
    }));
    tokio::select! {
        _ = reached.notified() => (),
        result = &mut worker => panic!("original worker gate did not suspend: {}", result.is_err()),
    }
    drop(worker);
    shutdown.begin_shutdown();
    assert!(owner.key_ring().is_err());
    assert!(global.wallet_mutation(&mut owner).await.is_err());
    let mut joined = Box::pin(shutdown.shutdown());
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut joined)
            .await
            .is_err()
    );
    release.send(()).unwrap();
    joined.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_or_global_drop_during_actual_sdk_work_refuses_its_durable_result() {
    for close_global in [false, true] {
        let (global, _, _, _) = make().await;
        let mut global = Some(global);
        let (_directory, keys, auth) = enrolled().await;
        let mut owner = wallet(
            global.as_ref().unwrap(),
            keys.clone(),
            csgn::MemoryStore::default(),
            false,
        )
        .await;
        let mutation = global
            .as_ref()
            .unwrap()
            .wallet_mutation(&mut owner)
            .await
            .unwrap();
        let shutdown = owner.shutdown_handle();
        let reached = Arc::new(tokio::sync::Notify::new());
        let entered = reached.clone();
        let (release, wait) = std::sync::mpsc::channel();
        let current = auth.clone();
        let mut work = Box::pin(mutation.execute(move |keys| {
            entered.notify_one();
            wait.recv().unwrap();
            keys.revoke(current.member(), current.credential_id())
        }));
        tokio::select! {
            _ = reached.notified() => (),
            result = &mut work => panic!("actual SDK worker did not suspend: {}", result.is_err()),
        }
        if close_global {
            drop(global.take());
        } else {
            shutdown.begin_shutdown();
        }
        release.send(()).unwrap();
        assert!(matches!(work.await, Err(ckyh::Error::Storage)));
        shutdown.shutdown().await;
        assert!(owner.key_ring().is_err());
        let member = auth.member();
        let credential = auth.credential_id().clone();
        let original = tokio::task::spawn_blocking(move || keys.list(member))
            .await
            .unwrap()
            .unwrap();
        assert!(
            original
                .iter()
                .any(|record| record.credential_id() == &credential && record.is_revoked())
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn published_feed_rechecks_only_the_already_retained_beacon_without_fresh_membership() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, _authentication) = enrolled().await;
    let mut wallet = wallet(&global, keys, csgn::MemoryStore::default(), false).await;
    let feed = wallet.trust_feed(NOW).await.unwrap();
    let again = wallet.published_feed(NOW).unwrap();
    assert_eq!(again.revision, feed.revision);
    assert_eq!(again.policy_epoch, feed.policy_epoch);
    // Past every retained deadline the recheck refuses and drops the retained view.
    assert!(wallet.published_feed(NOW + 10_000_000).is_err());
    assert!(wallet.published_feed(NOW).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ended_chain_is_published_once_in_the_communities_snapshot() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, _) = enrolled().await;
    let mut wallet = wallet(&global, keys, csgn::MemoryStore::default(), false).await;
    let ring = wallet.key_ring().unwrap().to_cbor();
    let chain = cgbl::EndedChain {
        fingerprint: [0xab; 32],
        reason_class: cgbl::EndedReason::Banned,
        ended_at: NOW,
    };
    wallet.record_ended(chain, NOW).await.unwrap();
    // A repeat for the same fingerprint changes nothing and is not an error.
    wallet.record_ended(chain, NOW).await.unwrap();
    let feed = wallet.trust_feed(NOW).await.unwrap();
    let mut charter = cchr::Charter::new(cchr::Configuration {
        origin: ORIGIN.into(),
        community: "wallet".into(),
        key_ring: ring,
        minimum_revision: 1,
        ring_revision: 0,
    })
    .unwrap();
    charter
        .install(&serde_json::to_vec(&feed).unwrap(), NOW)
        .unwrap();
    let ended = charter.current(NOW).unwrap().ended().to_vec();
    assert_eq!(ended.len(), 1);
    assert_eq!(ended[0].fingerprint, [0xab; 32]);
    assert_eq!(ended[0].ended_at, NOW);
}
#[tokio::test(flavor = "multi_thread")]
async fn device_observation_reports_the_actual_final_owner_clock() {
    let (global, _, _, _) = make().await;
    let (_directory, keys, auth) = enrolled().await;
    let mut owner = wallet(&global, keys.clone(), csgn::MemoryStore::default(), false).await;
    // The observation carries the actual final owner clock, never a zeroed or
    // unit placeholder (kills checked_at -> 0 and checked_at -> 1).
    let observed = global
        .authorize_wallet_device(&mut owner, &auth, [49; 32], NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert_eq!(observed.devices(), &[[49; 32]]);
    assert_eq!(observed.checked_at(), NOW);
    let current = global
        .wallet_devices(&mut owner, &auth, NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert_eq!(current.checked_at(), NOW);
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_facade_cannot_observe_authorize_or_signal_this_wallet() {
    let (global, _, _, _) = make().await;
    let (foreign, _, _, _) = make().await;
    let (_directory, keys, auth) = enrolled().await;
    let mut owner = wallet(&global, keys.clone(), csgn::MemoryStore::default(), false).await;
    // A facade that does not own the wallet instance is refused before any
    // read or write (kills owns_wallet -> Ok(()) and the || -> && weakening,
    // which accepts a foreign instance while the community still matches).
    assert!(matches!(
        foreign
            .wallet_devices(&mut owner, &auth, NOW + 60, &|| NOW)
            .await,
        Err(Error::KeyMismatch)
    ));
    assert!(matches!(
        foreign
            .authorize_wallet_device(&mut owner, &auth, [49; 32], NOW + 60, &|| NOW)
            .await,
        Err(Error::KeyMismatch)
    ));
    // Skipping the ownership gate must not silently succeed either
    // (kills signal_wallet_key_mutation -> Ok(())).
    let mutation = global.wallet_mutation(&mut owner).await.unwrap();
    assert!(matches!(
        foreign
            .signal_wallet_key_mutation(&mut owner, &auth, &mutation, NOW + 60, &|| NOW)
            .await,
        Err(Error::KeyMismatch)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn rebinding_the_same_credential_replaces_the_old_device_key() {
    let (global, store, _, _) = make().await;
    let (_directory, keys, auth) = enrolled().await;
    let mut owner = wallet(&global, keys.clone(), csgn::MemoryStore::default(), false).await;
    let key = storage::Key::new("wallet-device", auth.member().to_string());
    let credential = serde_json::to_value(auth.credential_id().as_ref().to_vec()).unwrap();
    let first = global
        .authorize_wallet_device(&mut owner, &auth, [49; 32], NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert_eq!(first.devices(), &[[49; 32]]);
    // Same credential with a new device: the old binding is retired and
    // replaced. A credential-or-key match must not count as already bound
    // (kills the && -> || at 310:61), a same-key binding of another
    // credential must not either (kills == -> != at 310:76), and the old
    // credential row must not survive the retain (kills != -> == at 320:54).
    let second = global
        .authorize_wallet_device(&mut owner, &auth, [50; 32], NOW + 60, &|| NOW)
        .await
        .unwrap();
    assert_eq!(second.devices(), &[[50; 32]]);
    let read = store.read(std::slice::from_ref(&key)).await.unwrap();
    let replaced: serde_json::Value = serde_json::from_slice(&read.records[&key].value).unwrap();
    assert_eq!(replaced["bindings"].as_array().unwrap().len(), 1);
    assert_eq!(replaced["bindings"][0]["credential"], credential);
    assert_eq!(
        replaced["bindings"][0]["key"],
        serde_json::to_value([50; 32]).unwrap()
    );
    assert!(
        replaced["removed"]
            .as_array()
            .unwrap()
            .contains(&serde_json::to_value([49; 32]).unwrap())
    );
    // Re-authorizing the exact same pair is a no-op: the generation does not
    // move (kills == -> != at 310:47, which would rewrite and bump it).
    let generation = replaced["generation"].as_u64().unwrap();
    global
        .authorize_wallet_device(&mut owner, &auth, [50; 32], NOW + 60, &|| NOW)
        .await
        .unwrap();
    let reread = store.read(std::slice::from_ref(&key)).await.unwrap();
    let again: serde_json::Value = serde_json::from_slice(&reread.records[&key].value).unwrap();
    assert_eq!(again["generation"].as_u64().unwrap(), generation);
}
