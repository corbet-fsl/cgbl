//! Birth items of the one-ceremony registration: the first wallet device binding, the first
//! wallet birth genesis statement, the first stamp and the birth passport of an account.
//!
//! Each item is first-only and idempotent. It is written in the SAME compare-and-swap as the
//! action it records, keyed by the account, and holds the digest of the exact input that
//! opened it. The same input returns the stored output; any other input is refused with
//! [`Error::Duplicate`]. An item whose output is still empty is unfinished (its action failed
//! or was cut off after the item became durable): only the same input may finish it.
use crate::{
    Error, Global, Result, Session, Subject,
    facade::{get, put},
    storage::{Change, Key, ReadSet, Store},
};
use cpsd::{
    BlindPassport, IssuanceChallenge, IssuanceRequest,
    rand::{CryptoRng, RngCore},
};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

const VERSION: u8 = 1;
/// Upper bound of a stored output (a signed statement or issued credential).
const MAX_OUTPUT_BYTES: usize = cplc::MAX_DOCUMENT_BYTES + 8192;

/// The closed set of birth items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Item {
    /// The first wallet device binding; output `K ‖ c`.
    Device,
    /// The wallet-signed birth genesis statement; output `at (u64 BE) ‖ statement`.
    Genesis,
    /// The first stamp; output the blind stamp bytes.
    Stamp,
    /// The birth passport bound to `K`; output the blind passport bytes.
    Passport,
}
impl Item {
    fn bucket(self) -> &'static str {
        match self {
            Self::Device => "birth-device",
            Self::Genesis => "birth-genesis",
            Self::Stamp => "birth-stamp",
            Self::Passport => "birth-passport",
        }
    }
    /// The item's storage key for `subject`.
    pub(crate) fn key(self, subject: &Subject) -> Key {
        Key::new(self.bucket(), subject.as_str())
    }
    /// The digest of the exact input: a domain tag, the item and every field length-prefixed.
    pub(crate) fn input(self, fields: &[&[u8]]) -> [u8; 32] {
        let mut hash = sha2::Sha256::new();
        hash.update(b"cgbl.birth-input.v1\0");
        for field in std::iter::once(self.bucket().as_bytes()).chain(fields.iter().copied()) {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field);
        }
        hash.finalize().into()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BirthItem {
    version: u8,
    input: [u8; 32],
    output: Vec<u8>,
}

/// The state of one birth item for one exact input.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Open {
    /// Never written: this input opens it.
    Fresh,
    /// Written for this input, the action has not completed.
    Unfinished,
    /// Completed for this input; the stored output.
    Done(Vec<u8>),
}

/// Classify `key` in `read` for `input`; another input is [`Error::Duplicate`].
pub(crate) fn check(read: &ReadSet, key: &Key, input: &[u8; 32]) -> Result<Open> {
    if !read.revisions.contains_key(key) {
        return Err(Error::Storage);
    }
    if read
        .records
        .get(key)
        .is_some_and(|record| record.deadline != 0)
    {
        return Err(Error::Encoding);
    }
    let Some(item) = get::<BirthItem>(read, key)? else {
        return Ok(Open::Fresh);
    };
    if item.version != VERSION || item.output.len() > MAX_OUTPUT_BYTES {
        return Err(Error::Encoding);
    }
    if &item.input != input {
        return Err(Error::Duplicate);
    }
    Ok(if item.output.is_empty() {
        Open::Unfinished
    } else {
        Open::Done(item.output)
    })
}

/// The stored output of a completed item, whatever its input.
pub(crate) fn completed(read: &ReadSet, key: &Key) -> Result<Option<Vec<u8>>> {
    Ok(get::<BirthItem>(read, key)?
        .filter(|item| item.version == VERSION && !item.output.is_empty())
        .map(|item| item.output))
}

/// The change writing `key` for `input` with `output` (empty while unfinished).
pub(crate) fn change(key: Key, input: [u8; 32], output: Vec<u8>) -> Result<Change> {
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(Error::Capacity);
    }
    put(
        key,
        &BirthItem {
            version: VERSION,
            input,
            output,
        },
    )
}

/// Record the output of an unfinished item, only while it still holds exactly `input`.
pub(crate) async fn finish(
    store: &impl Store,
    key: Key,
    input: [u8; 32],
    output: Vec<u8>,
) -> Result<()> {
    let read = store.read(std::slice::from_ref(&key)).await?;
    match check(&read, &key, &input)? {
        Open::Unfinished => {
            store
                .compare_exchange(&read, vec![change(key, input, output)?])
                .await
        }
        Open::Done(stored) if stored == output => Ok(()),
        _ => Err(Error::Conflict),
    }
}

impl<S: Store, K: csgn::Store, I: cpsd::IssuanceStore> Global<S, K, I> {
    /// Issue the account's birth passport during the one-ceremony registration (Q5). Exactly
    /// like [`Global::issue`], and additionally bound to the account's birth device `K`:
    /// `signature` is `sig_K` over [`ckmg::DevicePurpose::WalletBirthPassport`] and
    /// [`ckmg::wallet_birth_passport_payload`] of `request`. The birth item is written before
    /// the issue; the same request returns the same passport, another request is
    /// [`Error::Duplicate`]. Without a bound birth device this refuses with
    /// [`Error::Challenge`].
    pub async fn issue_birth_passport<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        session: &Session,
        challenge: &IssuanceChallenge,
        request: &IssuanceRequest,
        signature: &[u8; 64],
        now: u64,
    ) -> Result<BlindPassport> {
        let subject = &session.subject;
        let device_key = Item::Device.key(subject);
        let item_key = Item::Passport.key(subject);
        let read = self
            .store
            .read(&[device_key.clone(), item_key.clone()])
            .await?;
        let bound = completed(&read, &device_key)?.ok_or(Error::Challenge)?;
        let device: [u8; 32] = bound
            .get(..32)
            .and_then(|key| key.try_into().ok())
            .ok_or(Error::Encoding)?;
        let payload = ckmg::wallet_birth_passport_payload(&request.to_bytes());
        let message = [ckmg::DevicePurpose::WalletBirthPassport.tag(), &payload[..]].concat();
        ckmg::verify_ed25519(&device, &message, signature).map_err(|_| Error::Signature)?;
        let input = Item::Passport.input(&[&payload]);
        match check(&read, &item_key, &input)? {
            Open::Done(stored) => {
                return BlindPassport::from_bytes(&stored).map_err(|_| Error::Encoding);
            }
            Open::Unfinished => {}
            Open::Fresh => {
                self.store
                    .compare_exchange(&read, vec![change(item_key.clone(), input, vec![])?])
                    .await?;
            }
        }
        let passport = self.issue(rng, session, challenge, request, now).await?;
        finish(&self.store, item_key, input, passport.to_bytes()).await?;
        Ok(passport)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStore;

    fn subject() -> Subject {
        Subject::new("00000000-0000-0000-0000-00000000001b".to_string()).unwrap()
    }

    #[tokio::test]
    async fn an_item_is_first_only_and_idempotent_for_its_exact_input() {
        let store = MemoryStore::new("global").unwrap();
        let key = Item::Stamp.key(&subject());
        let first = Item::Stamp.input(&[b"request one"]);
        let other = Item::Stamp.input(&[b"request two"]);
        let read = store.read(std::slice::from_ref(&key)).await.unwrap();
        assert_eq!(check(&read, &key, &first).unwrap(), Open::Fresh);
        store
            .compare_exchange(&read, vec![change(key.clone(), first, vec![]).unwrap()])
            .await
            .unwrap();
        let read = store.read(std::slice::from_ref(&key)).await.unwrap();
        assert_eq!(check(&read, &key, &first).unwrap(), Open::Unfinished);
        assert!(matches!(check(&read, &key, &other), Err(Error::Duplicate)));
        // Only the same input finishes it; a finished item keeps its output.
        assert!(matches!(
            finish(&store, key.clone(), other, vec![1]).await,
            Err(Error::Duplicate)
        ));
        finish(&store, key.clone(), first, vec![7, 7])
            .await
            .unwrap();
        finish(&store, key.clone(), first, vec![7, 7])
            .await
            .unwrap();
        assert!(matches!(
            finish(&store, key.clone(), first, vec![8]).await,
            Err(Error::Conflict)
        ));
        let read = store.read(std::slice::from_ref(&key)).await.unwrap();
        assert_eq!(check(&read, &key, &first).unwrap(), Open::Done(vec![7, 7]));
        assert!(matches!(check(&read, &key, &other), Err(Error::Duplicate)));
        assert_eq!(completed(&read, &key).unwrap(), Some(vec![7, 7]));
    }

    #[test]
    fn inputs_are_bound_to_the_item_and_the_field_boundaries() {
        assert_ne!(Item::Stamp.input(&[b"x"]), Item::Passport.input(&[b"x"]));
        assert_ne!(
            Item::Device.input(&[b"ab", b"c"]),
            Item::Device.input(&[b"a", b"bc"])
        );
        assert_eq!(Item::Genesis.input(&[b"d"]), Item::Genesis.input(&[b"d"]));
    }

    #[tokio::test]
    async fn an_unread_key_is_not_classified() {
        let store = MemoryStore::new("global").unwrap();
        let read = store.read(&[] as &[Key]).await.unwrap();
        let key = Item::Device.key(&subject());
        assert!(matches!(check(&read, &key, &[0; 32]), Err(Error::Storage)));
    }
}
