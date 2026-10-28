//! Confirmation stamps at the wallet (one-confirmation model).
//!
//! The wallet issues a stamp only to the member who just passed ONE fresh user verification of
//! the wallet passkey over the request's confirmation challenge, only for that member's own
//! passport secret (the request's issuer tag must equal the tag of the member's passport), and
//! at most `STAMP_MAX_PER_DAY` times per UTC day. The stamp key is a NEW key, never the passport
//! key; its cohort is the rulebook's stamp cohort. The wallet sees no digest and no community.
use crate::{
    birth::{Item, Open},
    facade::{account, get, meta, put},
    storage::{Key, ReadSet, Store},
    *,
};
use cpsd::{
    AuthenticatedStampIssuance, BlindStamp, IssuanceChallenge, StampIssuanceRequest,
    StampIssuerKey, StampPublicKey,
    rand::{CryptoRng, RngCore},
};
use serde::{Deserialize, Serialize};

/// Invisible technical brake: at most this many stamps per member and UTC day,
/// counted in fixed UTC-aligned windows. Each stamp already needs a fresh
/// passkey UP+UV; the ceiling only stops a runaway device, and honest flows
/// never reach it.
pub const STAMP_MAX_PER_DAY: u32 = 4096;

/// How long the wallet answers the SAME stamp request again with the SAME stamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StampRate {
    /// How long the wallet answers the SAME stamp request again with the SAME stamp, without
    /// a new user verification and without another budget charge (a device that was killed
    /// after the wallet replied and before it stored the stamp). 0 disables the replay.
    pub replay_seconds: u64,
}

impl Default for StampRate {
    /// Ten minutes: a device killed after the reply and before it stored the stamp.
    fn default() -> Self {
        Self {
            replay_seconds: 600,
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

/// The member's last issued stamp, kept for an exact replay of its request.
#[derive(Serialize, Deserialize)]
struct Reply {
    /// SHA-256 of the issued request's bytes.
    request: [u8; 32],
    /// The blind stamp the wallet answered.
    stamp: Vec<u8>,
    /// Replays end here.
    until: u64,
}

fn reply(subject: &Subject) -> Key {
    Key::new("stamp-reply", subject.as_str())
}

fn request_digest(request: &StampIssuanceRequest) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(request.to_bytes()).into()
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
    /// Attach the wallet's stamp issuer key and replay window. The key must not be
    /// the passport key's material and its cohort is the rulebook's stamp cohort.
    pub fn attach_stamps(&mut self, key: StampIssuerKey, rate: StampRate) -> Result<()> {
        if rate.replay_seconds > 86_400 {
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
        if used.window == window(now) && used.used >= STAMP_MAX_PER_DAY {
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

    /// The stamp this member was already issued for exactly `request` (same bytes) within the
    /// replay window, or `None`. The host asks this BEFORE it verifies a user verification:
    /// the same request gets the same answer with no new verification and no budget charge;
    /// any other request needs its own confirmation.
    pub async fn replay_stamp(
        &self,
        session: &Session,
        request: &StampIssuanceRequest,
        now: u64,
    ) -> Result<Option<BlindStamp>> {
        time(now)?;
        let stamps = self.stamps.as_ref().ok_or(Error::NoPolicy)?;
        if stamps.rate.replay_seconds == 0 {
            return Ok(None);
        }
        let subject = &session.subject;
        let read = self.read(vec![account(subject), reply(subject)]).await?;
        self.state(&read, now)?;
        let person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        person.eligible()?;
        match get::<Reply>(&read, &reply(subject))? {
            Some(kept) if kept.request == request_digest(request) && now < kept.until => {
                BlindStamp::from_bytes(&kept.stamp)
                    .map(Some)
                    .map_err(|_| Error::Encoding)
            }
            _ => Ok(None),
        }
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
        self.issue_stamp_with(
            rng,
            session,
            request,
            challenge,
            verified_confirmation,
            false,
            now,
        )
        .await
    }

    /// Issue the account's FIRST stamp without a passkey assertion, under the host-checked
    /// birth grant of the one-ceremony registration (C5). The stamp is byte-identical to any
    /// other: the confirmation is the request's own confirmation challenge, and budget, nonce
    /// and holder binding are unchanged. The `stamp` birth item is written in the same
    /// compare-and-swap as the budget charge; the same request returns the same stamp, another
    /// request is [`Error::Duplicate`].
    pub async fn issue_birth_stamp<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        session: &Session,
        request: &StampIssuanceRequest,
        challenge: &IssuanceChallenge,
        now: u64,
    ) -> Result<BlindStamp> {
        let confirmation = request.confirmation_challenge(challenge);
        self.issue_stamp_with(rng, session, request, challenge, confirmation, true, now)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn issue_stamp_with<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        session: &Session,
        request: &StampIssuanceRequest,
        challenge: &IssuanceChallenge,
        verified_confirmation: [u8; 32],
        birth: bool,
        now: u64,
    ) -> Result<BlindStamp> {
        time(now)?;
        let stamps = self.stamps.as_ref().ok_or(Error::NoPolicy)?;
        let subject = &session.subject;
        let birth_key = Item::Stamp.key(subject);
        let birth_input = Item::Stamp.input(&[&request_digest(request)]);
        // The birth item is read on EVERY path: a normal stamp closes it in its own
        // compare-and-swap, so no assertion-free stamp follows any stamp of the account.
        let keys = vec![
            account(subject),
            budget(subject),
            ring_key(),
            birth_key.clone(),
        ];
        let read = self.read(keys).await?;
        let state = self.state(&read, now)?;
        if birth {
            if let Open::Done(stored) = crate::birth::check(&read, &birth_key, &birth_input)? {
                return BlindStamp::from_bytes(&stored).map_err(|_| Error::Encoding);
            }
        }
        let person: Account = get(&read, &account(subject))?.ok_or(Error::UnknownSubject)?;
        person.eligible()?;
        let current = window(now);
        let mut used: Budget = get(&read, &budget(subject))?.unwrap_or_default();
        if used.window != current {
            used = Budget {
                window: current,
                used: 0,
            };
        }
        if used.used >= STAMP_MAX_PER_DAY {
            return Err(Error::Capacity);
        }
        used.used += 1;
        let mut changes = vec![put(budget(subject), &used)?];
        // The first-only marker commits with the budget charge, or not at all.
        if birth {
            changes.push(crate::birth::change(
                birth_key.clone(),
                birth_input,
                vec![],
            )?);
        } else if let Some(closed) = crate::birth::close(&read, Item::Stamp, &birth_key)? {
            changes.push(closed);
        }
        // The key that signs is recorded as open no later than its first stamp.
        if let Some(ring) = advance(recorded_ring(&read)?, Some(stamps.public_key_bytes()), now) {
            changes.push(put(ring_key(), &ring)?);
        }
        self.store.compare_exchange(&read, changes).await?;
        let holder = self
            .stamp_holder(session)
            .await?
            .with_user_verification(verified_confirmation);
        let stamp = cpsd::issue_stamp_once(
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
        .map_err(stamp_error)?;
        // Kept before it is answered: a device killed after this reply and before it stored
        // the stamp asks again with the same request and gets this same stamp.
        if stamps.rate.replay_seconds > 0 {
            let kept = Reply {
                request: request_digest(request),
                stamp: stamp.to_bytes(),
                until: now.saturating_add(stamps.rate.replay_seconds),
            };
            let read = self.read(vec![reply(subject)]).await?;
            self.store
                .compare_exchange(&read, vec![put(reply(subject), &kept)?])
                .await?;
        }
        if birth {
            crate::birth::finish(&self.store, birth_key, birth_input, stamp.to_bytes()).await?;
        }
        Ok(stamp)
    }

    /// The stamp epoch communities verify against: the global epoch of the signed status.
    pub async fn stamp_epoch(&self, now: u64) -> Result<u64> {
        let read = self.read(vec![]).await?;
        self.state(&read, now)?.epoch()
    }
}

/// Store key of the recorded stamp key ring.
pub(crate) fn ring_key() -> Key {
    meta("stamp-keys")
}

/// The recorded ring in `read` (empty before the first stamp key).
pub(crate) fn recorded_ring(read: &ReadSet) -> Result<Vec<StampKeyPeriod>> {
    Ok(get(read, &ring_key())?.unwrap_or_default())
}

/// The ring after making `current` the open period at `now`: the previous open period is
/// retired at `now` (or one second after its start), a new key opens at `now`. `None` when the
/// ring already records `current` as open. Retired keys are never removed.
pub(crate) fn advance(
    mut ring: Vec<StampKeyPeriod>,
    current: Option<Vec<u8>>,
    now: u64,
) -> Option<Vec<StampKeyPeriod>> {
    let open = ring.iter().position(|period| period.valid_until.is_none());
    if open.map(|i| Some(&ring[i].public_key)) == Some(current.as_ref())
        || (open.is_none() && current.is_none())
    {
        return None;
    }
    if let Some(i) = open {
        let from = ring[i].valid_from;
        ring[i].valid_until = Some(now.max(from.saturating_add(1)));
    }
    if let Some(public_key) = current {
        ring.push(StampKeyPeriod {
            public_key,
            valid_from: now,
            valid_until: None,
        });
    }
    Some(ring)
}

/// Publication rule: every key decodes, every period is non-empty, at most one is open and it
/// is exactly `current`; without a current key no period is open.
pub(crate) fn validate_ring(current: Option<&[u8]>, ring: &[StampKeyPeriod]) -> Result<()> {
    let mut open = None;
    for period in ring {
        StampPublicKey::from_bytes(&period.public_key).map_err(|_| Error::Encoding)?;
        match period.valid_until {
            Some(until) if until <= period.valid_from => return Err(Error::Policy),
            Some(_) => {}
            None if open.is_some() => return Err(Error::Policy),
            None => open = Some(period.public_key.as_slice()),
        }
    }
    if open != current && !(open.is_none() && current.is_some() && ring.is_empty()) {
        return Err(Error::Policy);
    }
    Ok(())
}

impl<S: Store, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    /// Record the attached stamp key as the ring's open period (retiring the previous one).
    pub(crate) async fn record_stamp_key(&self, now: u64) -> Result<()> {
        time(now)?;
        let read = self.read(vec![ring_key()]).await?;
        let ring = recorded_ring(&read)?;
        if let Some(ring) = advance(
            ring,
            self.stamps.as_ref().map(Stamps::public_key_bytes),
            now,
        ) {
            self.store
                .compare_exchange(&read, vec![put(ring_key(), &ring)?])
                .await?;
        }
        Ok(())
    }
}

fn window(now: u64) -> u64 {
    now / 86_400 * 86_400
}

#[cfg(test)]
mod tests {
    use super::*;
    use cpsd::{KeyId, StampIssuerKey, StampParams, rand::rngs::OsRng};

    fn key(name: &str) -> Vec<u8> {
        StampIssuerKey::generate(
            &mut OsRng,
            KeyId::new(name).unwrap(),
            &StampParams::new(86_400).unwrap(),
        )
        .unwrap()
        .public_key()
        .to_bytes()
    }

    fn period(key: &[u8], from: u64, until: Option<u64>) -> StampKeyPeriod {
        StampKeyPeriod {
            public_key: key.to_vec(),
            valid_from: from,
            valid_until: until,
        }
    }

    #[test]
    fn rotation_retires_the_open_key_and_keeps_every_retired_key() {
        let (a, b) = (key("a"), key("b"));
        assert_eq!(advance(vec![], None, 10), None);
        let one = advance(vec![], Some(a.clone()), 10).unwrap();
        assert_eq!(one, vec![period(&a, 10, None)]);
        assert_eq!(advance(one.clone(), Some(a.clone()), 99), None);
        let two = advance(one, Some(b.clone()), 50).unwrap();
        assert_eq!(two, vec![period(&a, 10, Some(50)), period(&b, 50, None)]);
        validate_ring(Some(&b), &two).unwrap();
        // Rotating back to an old key opens a NEW period; the old one stays retired.
        let three = advance(two, Some(a.clone()), 50).unwrap();
        assert_eq!(
            three,
            vec![
                period(&a, 10, Some(50)),
                period(&b, 50, Some(51)),
                period(&a, 50, None)
            ]
        );
        validate_ring(Some(&a), &three).unwrap();
        // Detaching stamps retires the open key.
        let closed = advance(three, None, 60).unwrap();
        assert!(closed.iter().all(|p| p.valid_until.is_some()));
        validate_ring(None, &closed).unwrap();
    }

    #[test]
    fn a_published_ring_has_one_open_period_equal_to_the_current_key() {
        let (a, b) = (key("a"), key("b"));
        validate_ring(None, &[]).unwrap();
        // A status without a ring (no stamps recorded yet) stays valid.
        validate_ring(Some(&a), &[]).unwrap();
        for (current, ring) in [
            (Some(&b), vec![period(&a, 1, None)]),
            (None, vec![period(&a, 1, None)]),
            (Some(&a), vec![period(&a, 1, Some(5))]),
            (Some(&a), vec![period(&a, 1, None), period(&b, 2, None)]),
            (Some(&a), vec![period(&b, 5, Some(5)), period(&a, 5, None)]),
            (
                Some(&a),
                vec![period(&[1, 2, 3], 1, Some(2)), period(&a, 5, None)],
            ),
        ] {
            assert!(validate_ring(current.map(Vec::as_slice), &ring).is_err());
        }
    }

    #[test]
    fn public_key_bytes_are_the_key_bytes() {
        let params = StampParams::new(86_400).unwrap();
        let key =
            StampIssuerKey::generate(&mut OsRng, KeyId::new("edge").unwrap(), &params).unwrap();
        let expected = key.public_key().to_bytes();
        assert!(!expected.is_empty());
        let stamps = Stamps {
            key,
            rate: StampRate::default(),
        };
        assert_eq!(stamps.public_key_bytes(), expected);
    }

    #[test]
    fn stamp_error_maps_each_cpsd_failure_to_its_privacy_preserving_error() {
        assert!(matches!(
            stamp_error(cpsd::Error::IssuerTagMismatch),
            Error::HolderChanged
        ));
        assert!(matches!(
            stamp_error(cpsd::Error::IssuerTagClaimed),
            Error::HolderChanged
        ));
        assert!(matches!(
            stamp_error(cpsd::Error::InvalidChallenge),
            Error::Challenge
        ));
        assert!(matches!(
            stamp_error(cpsd::Error::ChallengeConflict),
            Error::Challenge
        ));
        assert!(matches!(
            stamp_error(cpsd::Error::UnconfirmedStampRequest),
            Error::Challenge
        ));
        assert!(matches!(
            stamp_error(cpsd::Error::StorageCapacity),
            Error::Capacity
        ));
        assert!(matches!(stamp_error(cpsd::Error::Storage), Error::Storage));
    }

    #[test]
    fn window_cuts_utc_days() {
        assert_eq!(window(1), 0);
        assert_eq!(window(86_399), 0);
        assert_eq!(window(86_400), 86_400);
        assert_eq!(window(172_799), 86_400);
        assert_eq!(window(172_800), 172_800);
    }

    #[test]
    fn a_second_open_period_is_refused_even_when_the_last_open_matches() {
        let (a, b) = (key("a"), key("b"));
        // Two open periods: the ring is invalid no matter which key is current.
        assert!(validate_ring(Some(&b), &[period(&a, 1, None), period(&b, 2, None)]).is_err());
        assert!(validate_ring(Some(&a), &[period(&a, 1, None), period(&b, 2, None)]).is_err());
        assert!(validate_ring(None, &[period(&a, 1, None), period(&b, 2, None)]).is_err());
    }
}
