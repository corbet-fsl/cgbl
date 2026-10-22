//! Wallet birth items of the one-ceremony registration: the first device binding (C3) and the
//! wallet-signed birth genesis statement (C4). The host checks the birth grant (C2) and keeps
//! its Auth/Global guards across each call, exactly as for the step-up paths these replace.
use super::certificate::Timing;
use super::devices::{BUCKET, Binding, Devices, MAX_BIRTHS, decode};
use super::*;
use crate::{
    Subject,
    birth::{self, Item, Open},
    storage::Key,
};
use sha2::Digest as _;

/// The wallet-signed birth statement of an account (COSE bytes) and its statement time `at`,
/// as carried in `cchr::BirthGenesisEvidence`. It grants nothing by itself.
pub struct WalletBirthStatement {
    bytes: Vec<u8>,
    at: u64,
}
impl WalletBirthStatement {
    /// The signed statement bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// The day-rounded statement time.
    pub fn at(&self) -> u64 {
        self.at
    }
    fn output(&self) -> Vec<u8> {
        [&self.at.to_be_bytes()[..], &self.bytes].concat()
    }
    fn from_output(output: &[u8]) -> Result<Self> {
        let (at, bytes) = output.split_at_checked(8).ok_or(Error::Encoding)?;
        if bytes.is_empty() {
            return Err(Error::Encoding);
        }
        Ok(Self {
            at: u64::from_be_bytes(at.try_into().map_err(|_| Error::Encoding)?),
            bytes: bytes.to_vec(),
        })
    }
}
impl std::fmt::Debug for WalletBirthStatement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WalletBirthStatement([redacted])")
    }
}

/// What the wallet's passkey store says about the authenticated credential.
struct Sole {
    commitment: [u8; 32],
    credential_key: [u8; 32],
}

/// The authenticated credential is live, is the account's ONLY live credential, and carries
/// its creation commitment `c`.
fn sole_credential(
    keys: &ckyh::Passkeys<ckyh::LibsqlStore>,
    auth: &ckyh::Authentication,
) -> Result<Sole> {
    let public = keys.public_credential(auth).map_err(|_| Error::Signature)?;
    let live: Vec<_> = keys
        .list(auth.member())
        .map_err(|_| Error::Signature)?
        .into_iter()
        .filter(|key| !key.is_revoked())
        .collect();
    if live.len() != 1 || live[0].credential_id() != auth.credential_id() {
        // A second passkey ends the birth: later changes need their own step-up.
        return Err(Error::Duplicate);
    }
    let commitment = keys
        .initial_creation(auth)
        .map_err(|_| Error::Challenge)?
        .seed();
    Ok(Sole {
        commitment,
        credential_key: sha2::Sha256::digest(public.spki()).into(),
    })
}

/// The wallet origin as the device signs it: the configured passkey origin's ASCII origin
/// serialization (scheme and host, no path).
fn signed_origin(config: &WalletPublicationConfig) -> Result<String> {
    Ok(ckyh::Url::parse(&config.passkey_origin)
        .map_err(|_| Error::Policy)?
        .origin()
        .ascii_serialization())
}

impl<S: Store, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    /// Bind the account's FIRST wallet device `device` (= `K`) without a step-up, during the
    /// one-ceremony registration (C3). `signature` is `sig_K` over
    /// [`ckmg::DevicePurpose::WalletBirthDevice`] and [`ckmg::wallet_birth_device_payload`]
    /// of (wallet origin, account, credential id, `c`, `K`), where `c` is the creation
    /// commitment the wallet retained for this credential and the origin is the configured
    /// passkey origin's ASCII serialization. Refused unless the credential is the account's
    /// only live passkey and the account has no binding yet. The write is the one of
    /// [`Global::authorize_wallet_device`] plus the `device` birth item in the same commit;
    /// the same request again returns the current observation, another is
    /// [`Error::Duplicate`].
    pub async fn authorize_wallet_birth_device<W: csgn::Store>(
        &self,
        wallet: &mut Wallet<S, W>,
        auth: &ckyh::Authentication,
        device: [u8; 32],
        signature: &[u8; 64],
        expires: u64,
        clock: &impl Fn() -> u64,
    ) -> Result<WalletDeviceObservation> {
        self.owns_wallet(wallet, auth)?;
        let _sdk = wallet.capture_sdk().await?;
        if device == [0; 32] {
            return Err(Error::InvalidIdentifier);
        }
        let now = clock();
        wallet.sample(now)?;
        let mut timing = Timing::new(now, expires).inspect_err(|_| wallet.observed_at = None)?;
        let origin = signed_origin(&wallet.retained.as_ref().ok_or(Error::Storage)?.state.config)?;
        let subject = Subject::new(auth.member().to_string())?;
        let keys = wallet.passkeys.clone();
        let authentication = auth.clone();
        let sole = tokio::task::spawn_blocking(move || sole_credential(&keys, &authentication))
            .await
            .map_err(|_| Error::Storage)??;
        timing.sample(wallet, clock())?;
        // Every check of the request precedes the writer: a refused request leaves it usable.
        let credential = auth.credential_id().as_ref().to_vec();
        let payload = ckmg::wallet_birth_device_payload(
            &origin,
            subject.as_str(),
            &credential,
            &sole.commitment,
            &device,
        )
        .map_err(|_| Error::Encoding)?;
        let message = [ckmg::DevicePurpose::WalletBirthDevice.tag(), &payload[..]].concat();
        ckmg::verify_ed25519(&device, &message, signature).map_err(|_| Error::Signature)?;
        let input = Item::Device.input(&[&payload]);
        let retained = wallet.current().await?;
        timing.sample(wallet, clock())?;
        let account = self.wallet_account(&subject).await?;
        timing.sample(wallet, clock())?;
        let key = Key::new(BUCKET, subject.as_str());
        let item_key = Item::Device.key(&subject);
        let mut read = wallet.store.read(&[key.clone(), item_key.clone()]).await?;
        timing.sample(wallet, clock())?;
        let refuse = |wallet: &mut Wallet<S, W>, retained, error| {
            wallet.retained = Some(retained);
            Err(error)
        };
        match birth::check(&read, &item_key, &input) {
            Err(Error::Duplicate) => return refuse(wallet, retained, Error::Duplicate),
            Err(error) => return Err(error),
            Ok(Open::Done(_) | Open::Unfinished) => wallet.retained = Some(retained),
            Ok(Open::Fresh) => {
                let mut row = decode(&read, &key)?.unwrap_or(Devices::new(subject.as_str()));
                if !row.bindings.is_empty() || !row.removed.is_empty() {
                    // Not the account's first device: the step-up path binds it.
                    return refuse(wallet, retained, Error::Duplicate);
                }
                row.bindings.push(Binding {
                    credential,
                    key: device,
                });
                row.generation = state::next(row.generation)?;
                row.pending = true;
                let output = [&device[..], &sole.commitment[..]].concat();
                read.revisions.extend(account.revisions);
                read.revisions.extend(retained.read.revisions);
                let mut next = retained.state;
                next.epoch = state::next(next.epoch)?;
                next.manifest = None;
                wallet
                    .commit_with(
                        next,
                        read,
                        vec![row.change()?, birth::change(item_key, input, output)?],
                    )
                    .await?;
            }
        }
        // As for every binding: a post-write refusal is uncertainty, never a normal retry.
        match self.wallet_devices_held(wallet, auth, expires, clock).await {
            Ok(observed) => Ok(observed),
            Err(_) => {
                wallet.retained = None;
                wallet.observed_at = None;
                Err(Error::Storage)
            }
        }
    }

    /// Sign the account's birth genesis statement (C4) with the wallet's own signer (issuer
    /// `wallet`, the wallet key ring) for the genesis receipt's lineage challenge digest
    /// `digest` (= `D`). Requires the account's bound birth device; the statement names the
    /// credential, `H(credential public key)`, `K`, `c`, `D` and the day-rounded time. Its
    /// digest is appended to the account's wallet row (`births`) in the same commit as the
    /// `genesis` birth item. The same `D` again returns the stored statement; another `D` is
    /// [`Error::Duplicate`].
    pub async fn wallet_birth_genesis<W: csgn::Store>(
        &self,
        wallet: &mut Wallet<S, W>,
        auth: &ckyh::Authentication,
        digest: [u8; 32],
        expires: u64,
        clock: &impl Fn() -> u64,
    ) -> Result<WalletBirthStatement> {
        self.owns_wallet(wallet, auth)?;
        let now = clock();
        wallet.sample(now)?;
        let mut timing = Timing::new(now, expires).inspect_err(|_| wallet.observed_at = None)?;
        wallet.trust_feed(now).await?;
        timing.sample(wallet, clock())?;
        wallet.key_ring()?;
        let _sdk = wallet.capture_sdk().await?;
        timing.sample(wallet, clock())?;
        let subject = Subject::new(auth.member().to_string())?;
        let keys = wallet.passkeys.clone();
        let authentication = auth.clone();
        let sole = tokio::task::spawn_blocking(move || sole_credential(&keys, &authentication))
            .await
            .map_err(|_| Error::Storage)??;
        timing.sample(wallet, clock())?;
        let input = Item::Genesis.input(&[&digest]);
        let retained = wallet.current().await?;
        timing.sample(wallet, clock())?;
        let account = self.wallet_account(&subject).await?;
        timing.sample(wallet, clock())?;
        let key = Key::new(BUCKET, subject.as_str());
        let device_key = Item::Device.key(&subject);
        let item_key = Item::Genesis.key(&subject);
        let mut read = wallet
            .store
            .read(&[key.clone(), device_key.clone(), item_key.clone()])
            .await?;
        timing.sample(wallet, clock())?;
        let refuse = |wallet: &mut Wallet<S, W>, retained, error| {
            wallet.retained = Some(retained);
            Err(error)
        };
        match birth::check(&read, &item_key, &input) {
            Err(Error::Duplicate) => return refuse(wallet, retained, Error::Duplicate),
            Err(error) => return Err(error),
            Ok(Open::Done(stored)) => {
                wallet.retained = Some(retained);
                return WalletBirthStatement::from_output(&stored);
            }
            Ok(Open::Unfinished) => return Err(Error::Encoding),
            Ok(Open::Fresh) => {}
        }
        let credential = auth.credential_id().as_ref().to_vec();
        let Some(bound) = birth::completed(&read, &device_key)? else {
            return refuse(wallet, retained, Error::Challenge);
        };
        if bound.len() != 64 || bound[32..] != sole.commitment {
            return Err(Error::Encoding);
        }
        let device: [u8; 32] = bound[..32].try_into().map_err(|_| Error::Encoding)?;
        let mut row = decode(&read, &key)?.ok_or(Error::Encoding)?;
        if !row
            .bindings
            .iter()
            .any(|binding| binding.credential == credential && binding.key == device)
        {
            // The birth device was replaced or removed: the birth is over.
            return refuse(wallet, retained, Error::Duplicate);
        }
        if row.births.len() >= MAX_BIRTHS {
            return refuse(wallet, retained, Error::Capacity);
        }
        let at = timing.observed_at / 86_400 * 86_400;
        let statement = cchr::BirthStatement::new(
            cchr::wallet_fingerprint(None),
            subject.as_str(),
            &credential,
            sole.credential_key,
            device,
            sole.commitment,
            digest,
            at,
        )
        .map_err(|_| Error::Encoding)?
        .to_payload()
        .map_err(|_| Error::Encoding)?;
        // The writer is held (retained taken): read the ring from the signer itself.
        let lifetime = wallet
            .signer
            .key_ring()
            .map_err(|_| Error::Signature)?
            .max_validity();
        let bytes = wallet
            .signer
            .sign(
                csgn::Kind::Credential,
                &statement,
                at,
                at.checked_add(lifetime).ok_or(Error::InvalidTime)?,
            )
            .await
            .map_err(|_| Error::Signature)?;
        timing.sample(wallet, clock())?;
        let ring = wallet.signer.key_ring().map_err(|_| Error::Signature)?;
        if ring.to_cbor() != retained.state.key_ring {
            return Err(Error::KeyMismatch);
        }
        ring.verify(&bytes, csgn::Kind::Credential, at)
            .map_err(|_| Error::Signature)?;
        let signed = WalletBirthStatement { bytes, at };
        row.births.push(cchr::birth_statement_digest(&signed.bytes));
        read.revisions.extend(account.revisions);
        read.revisions.extend(retained.read.revisions);
        // The births list is wallet-local: no publication epoch or manifest changes.
        wallet
            .commit_with(
                retained.state,
                read,
                vec![
                    row.change()?,
                    birth::change(item_key, input, signed.output())?,
                ],
            )
            .await?;
        let completed = clock();
        timing
            .sample(wallet, completed)
            .map_err(|_| Error::Storage)?;
        wallet.observed_at = Some(completed);
        Ok(signed)
    }
}
