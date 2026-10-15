//! Confirmation stamps at the wallet (one-confirmation model).
//!
//! The wallet issues a stamp only to the member who just passed ONE fresh user verification of
//! the wallet passkey over the request's confirmation challenge, only for that member's own
//! passport secret (the request's issuer tag must equal the tag of the member's passport), and
//! at most `StampRate::limit` times per period. The stamp key is a NEW key, never the passport
//! key; its cohort is the rulebook's stamp cohort. The wallet sees no digest and no community.
use crate::{
    facade::{account, get, put},
    storage::{Key, Store},
    *,
};
use cpsd::{
    AuthenticatedStampIssuance, BlindStamp, IssuanceChallenge, StampIssuanceRequest,
    StampIssuerKey, StampPublicKey,
    rand::{CryptoRng, RngCore},
};
use serde::{Deserialize, Serialize};

/// Per-member stamp budget (rulebook setting): at most `limit` stamps per `period_seconds`,
/// counted in fixed UTC-aligned windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StampRate {
    /// Stamps per member and window.
    pub limit: u32,
    /// Window length in seconds.
    pub period_seconds: u64,
}

impl Default for StampRate {
    /// Twenty confirmations per UTC day: every join, pairing and revocation of a busy day.
    fn default() -> Self {
        Self {
            limit: 20,
            period_seconds: 86_400,
        }
    }
}

/// The wallet's stamp key and budget, attached after `Global::open`.
pub(crate) struct Stamps {
    key: StampIssuerKey,
    rate: StampRate,
}

impl Stamps {
    pub(crate) fn public_key_bytes(&self) -> Vec<u8> {
        self.key.public_key().to_bytes()
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Budget {
    window: u64,
    used: u32,
}

fn budget(subject: &Subject) -> Key {
    Key::new("stamps", subject.as_str())
}

fn stamp_error(error: cpsd::Error) -> Error {
    match error {
        cpsd::Error::IssuerTagMismatch | cpsd::Error::IssuerTagClaimed => Error::HolderChanged,
        cpsd::Error::InvalidChallenge | cpsd::Error::ChallengeConflict => Error::Challenge,
        cpsd::Error::UnconfirmedStampRequest => Error::Challenge,
        cpsd::Error::StorageCapacity => Error::Capacity,
        cpsd::Error::Storage => Error::Storage,
        _ => Error::Passport,
    }
}

impl<S, K, I> Global<S, K, I> {
    /// Attach the wallet's stamp issuer key and the per-member budget. The key must not be
    /// the passport key's material and its cohort is the rulebook's stamp cohort.
    pub fn attach_stamps(&mut self, key: StampIssuerKey, rate: StampRate) -> Result<()> {
        if rate.limit == 0 || rate.period_seconds == 0 || rate.period_seconds > 366 * 86_400 {
            return Err(Error::Capacity);
        }
        self.stamps = Some(Stamps { key, rate });
        Ok(())
    }

    /// The public stamp key communities verify against; `None` without stamps.
    pub fn stamp_public_key(&self) -> Option<&StampPublicKey> {
        self.stamps.as_ref().map(|stamps| stamps.key.public_key())
    }
}

impl<S: Store, K: csgn::Store, I> Global<S, K, I>
where
    I: cpsd::IssuanceStore + cpsd::StampIssuanceStore + cpsd::PassportTags,
{

    /// The authenticated issuance context: the member's person id, this session and the tag of
    /// the member's OWN passport, read from the passport issuer's registry.
    async fn stamp_holder(&self, session: &Session) -> Result<AuthenticatedStampIssuance> {
        let person = self.person_id(session);
        let tag = self
            .issuance
            .passport_tag(person)
            .await
            .map_err(stamp_error)?
            .ok_or(Error::UnknownSubject)?;
        Ok(AuthenticatedStampIssuance::new(person, session.id, tag))
    }

    /// Reserve a single-use stamp nonce for this wallet session. Refused for a suspended or
    /// unknown member, a member without a passport, and a member whose budget is spent.
    pub async fn stamp_challenge<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        session: &Session,
        now: u64,
    ) -> Result<(IssuanceChallenge, StampPublicKey)> {
        time(now)?;
        let stamps = self.stamps.as_ref().ok_or(Error::NoPolicy)?;
        let subject = &session.subject;
        let read = self.read(vec![account(subject), budget(subject)]).await?;
        self.state(&read, now)?;
        let person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        person.eligible()?;
        let used: Budget = get(&read, &budget(subject))?.unwrap_or_default();
        if used.window == window(now, stamps.rate) && used.used >= stamps.rate.limit {
            return Err(Error::Capacity);
        }
        let holder = self.stamp_holder(session).await?;
        let deadline = now
            .checked_add(self.limits.challenge_ttl)
            .ok_or(Error::InvalidTime)?;
        let challenge = cpsd::stamp_issuance_challenge(
            rng,
            &self.issuance,
            stamps.key.public_key(),
            &holder,
            deadline,
        )
        .await
        .map_err(stamp_error)?;
        Ok((challenge, stamps.key.public_key().clone()))
    }

    /// Issue one blind stamp. `verified_confirmation` is the challenge of the fresh
    /// user-verifying wallet-passkey assertion the HOST verified for this session's member;
    /// issuance refuses unless it is exactly the request's confirmation challenge. The budget
    /// is charged before signing, so a failed issuance never yields an extra stamp.
    pub async fn issue_stamp<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        session: &Session,
        request: &StampIssuanceRequest,
        challenge: &IssuanceChallenge,
        verified_confirmation: [u8; 32],
        now: u64,
    ) -> Result<BlindStamp> {
        time(now)?;
        let stamps = self.stamps.as_ref().ok_or(Error::NoPolicy)?;
        let subject = &session.subject;
        let read = self.read(vec![account(subject), budget(subject)]).await?;
        let state = self.state(&read, now)?;
        let person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        person.eligible()?;
        let current = window(now, stamps.rate);
        let mut used: Budget = get(&read, &budget(subject))?.unwrap_or_default();
        if used.window != current {
            used = Budget {
                window: current,
                used: 0,
            };
        }
        if used.used >= stamps.rate.limit {
            return Err(Error::Capacity);
        }
        used.used += 1;
        self.store
            .compare_exchange(&read, vec![put(budget(subject), &used)?])
            .await?;
        let holder = self
            .stamp_holder(session)
            .await?
            .with_user_verification(verified_confirmation);
        cpsd::issue_stamp_once(
            rng,
            &self.issuance,
            &stamps.key,
            &holder,
            request,
            challenge,
            state.epoch()?,
            now,
        )
        .await
        .map_err(stamp_error)
    }

    /// The stamp epoch communities verify against: the global epoch of the signed status.
    pub async fn stamp_epoch(&self, now: u64) -> Result<u64> {
        let read = self.read(vec![]).await?;
        self.state(&read, now)?.epoch()
    }
}

fn window(now: u64, rate: StampRate) -> u64 {
    now / rate.period_seconds * rate.period_seconds
}
