# cgbl contract

cgbl is cvld's separate global issuer. Its authenticated service owns global
person IDs, session IDs, provider selection, authority trust, legal/self-ban
permission, secrets, clocks and transport limits. Community pseudonyms, community
policies and community databases never enter this facade. No login dates, raw
provider evidence, proof payloads or issued passports are stored.

## One owner per operation

`Global<S,K,I>` composes a cgbl store, csgn durable signer and cpsd IssuanceStore.
`Session::authenticated` imports a stable opaque person and nonzero session ID
from the service authentication layer; it is not a client-deserializable receipt.
The facade checks eligibility and policy. cpsd alone generates/reserves issuance
nonces, verifies blind issuance, atomically consumes the nonce and enforces both
directions of permanent person/holder-tag continuity. cgbl keeps no issuer tags,
implements no continuity check and exports only issuer protocol messages, never
holder APIs. Wallet origin authentication and unsigned-request compile failures
remain cpsd's responsibility; tests exercise real signed requests and wrong origins.

The service appends `SCHEMAS` to its complete migration history for a NEW global
database: cgbl rows, csgn state, cpsd challenges, cpsd issuer tags and their unique
owner index. All SQL uses crlt with scope keys and index checks. A version-two
binding refuses old layouts. Existing installations require an explicit upgrade
preserving every burned fingerprint and moving holder bindings into cpsd; never
reset the database or silently discard an old tag. Global BBS and HMAC keys remain
immutable; only the COSE key can rotate through csgn.

## Provider checks and concurrency

`run_gate` requires a fresh `CheckId` for a new check. Keep that ID unchanged for
all retries, including after disconnects, cancellation, restarts or uncertain
commits. The facade derives a stable provider idempotency key bound to scope,
person, gate and provider. A provider leaf MUST use the provider's idempotent API:
repeated delivery must return the same outcome without charging again, and reuse
with a different input must be refused. Providers without this guarantee cannot
implement the paid gate contract. cgbl does not claim exactly-once network delivery.

Only the latest check ID/input commitment accompanies each current gate result;
there is no check history. Exact completed retries use the retained result.
After a slow provider returns, the facade rereads current eligibility and policy,
then retries only the atomic storage commit. It never calls the provider again
because of a CAS conflict. Unrelated people cannot invalidate the check.
Cancellation before persistence is retried through the same provider key.

Each cgbl record has an independent increasing revision. CAS validates only the
observed keys, including missing keys; every changed key must have been observed.
Deletion retains the key revision to prevent ABA. Read-only operations take no
write transaction. Composite indexes cover lookups, pages and challenge expiry.
The global pending count coordinates only short challenge-capacity transactions;
it is not a revision counter for identity operations.

## Gates, time and no return

Provider leaves must authenticate evidence to the person/session and normalize
uniqueness inputs identically across providers, such as canonical E.164 for a
phone gate. Canonicalization precedes the shared HMAC; the transient canonical
bytes are zeroized. Tests show equivalent provider spellings reserve one identity.
Real phone/other providers remain separate integrations; no normalization is
inferred from raw client input by the facade.

**NO RETURN:** uniqueness fingerprints are burned forever. Gate expiry,
registration expiry, holder-secret loss, passkey loss and a block never release
one. A person cannot switch an established uniqueness value. A holder who loses
the secret cannot obtain a replacement identity or community pseudonym. There is
no release, recovery or tombstone-reset API. cpsd also prevents the same holder
secret from binding to a second person and bypassing a block.

Retained gate expiries round DOWN to UTC days; rounding never extends evidence.
Shared passport cohort expiry must be a day boundary. Eligibility requires every
configured gate to reach that cohort. csgn key activation/rotation, signed status issuance and status expiry
use days. The signer must have been created with day-aligned activation.

Issuance challenges retain seconds: their short deadline bounds proof replay and
resource use. This is a transient protocol slot, not an activity timestamp. One
person may hold at most one pending slot, across sessions, within the global
capacity. The slot is reserved before cpsd is called, so cancellation cannot
allocate unlimited orphan nonces. Issuance removes it; expiry/pruning frees it.
A lost or uncertain response may require waiting for that short deadline before
a new challenge. Pruning never touches permanent uniqueness or holder bindings.

`issue_with_deadline_guard` supplies a nonserializable
`PendingIssuanceDeadline` only after authenticating the pending epoch, session,
nonce and current gate eligibility. It observes the same record whose revisions
fence issuance; there is no separate deadline lookup. The deadline is inclusive,
matching CPSD. A host's exclusive output guard may use checked addition of one.
Callback refusal happens before proof work, nonce consumption or first holder
binding. The original `issue` delegates with a no-op callback. This seam bounds
host output only when that host supplies a live guard; it does not enforce fresh
time inside CPSD's atomic storage operation or undo a completed issuance.

## Policy, blocks and publications

A separate authenticated global authority signs the typed `Policy` JSON as a
csgn SettingsSnapshot; the service supplies its pinned ring. A community cplc
signer never signs global policy. Revision increases and authority epoch advances
by exactly one, starting at one. Effective passport epoch is authority epoch plus
a separate local block counter. Policy acceptance never depends on the
authority knowing that counter. Invalid large jumps cannot exhaust revocation.

Only a verified legal order or the holder's self-ban blocks a person, permanently,
with no reversal API. A block atomically updates private state and the effective
epoch. cpsd cannot privately prove individual nonrevocation, so the new epoch
invalidates the old global cohort once verifiers adopt it. Eligible people renew;
blocked people cannot. cmty requires a fresh presentation at credential renewal,
against the current authenticated global epoch. Offline credentials retain their
bounded lifetime; this is not an offline revocation accumulator.

Public `Status` is a version-two SettingsSnapshot with exact purpose
`global-passport-status`, effective epoch, authority revision, shared cohort expiry
and BBS public key. It contains no person or revocation list. Verification requires
the authenticated `cgbl:<scope>` ring and consumer-maintained epoch/revision floors.
The private revocation list stays administrative. Status publication rechecks its
observed state after signing. One csgn writer owns COSE signing/key rotation.

## Development boundary and validation

There is one synthetic global gate: `development::DevelopmentGate`. It needs the
`development-gate` Cargo feature AND a development build. build.rs omits it from
release profiles even when debug assertions and every feature are enabled.
`Mode::Production` additionally refuses synthetic issuer catalogues, policies and
providers at runtime. Feature unification cannot enable it in production. cgts
contains no development gate implementation.

GitHub Actions runs format, Clippy, real memory/libSQL/crypto tests, release tests,
a hardened-release negative compilation probe, dependency-license review and the
shared duplicate/floating-revision check. Every first-party dependency follows main and must resolve
once at a full revision in the shared lock snapshot.

## Shared Beacon cache

After the existing post-signing state recheck, `signed_status` installs original
COSE bytes in `cbcn::document::Cache<Status>`. Existing Status payload validation
is shared by the consumer verifier and the typed Beacon port. No community feed
shape or private block list is published. The cache is volatile: durable
policy floors and block epochs remain in the global store.

The cached path rechecks the durable state fence and requires the exact current
policy revision, epoch, cohort and issuer key. It never accepts a deadline that
is already expired after day rounding. Beacon supplies no durable storage or
member authority. A backward observed clock fails closed.

## Phone and mailbox handoff

`Global::contact_binding` derives the sealed expected scope, gate/provider,
authenticated subject and retained check identity before a leaf ceremony.
Its context builders fix the leaf binding and scope and request minimal output.
The trusted host must use that context with the selected real adapter and a
stable comparison key: phone/mailbox facts retain an opaque binding, not
independently inspectable provider/scope provenance. Never reconstruct expected
context from a returned fact or deserialize a member-supplied verified result.
`contacts::PhoneGate` and `MailboxGate` consume the real opaque leaf fact and
recheck the exact correlation and expiry without I/O or a second registration
claim. Identifier control establishes comparison in that domain, not unique
human identity. Global policy and the existing atomic fingerprint owner decide
how that supported guarantee may be used.

## Payment handoff

Construct `payments::PaymentGate` with in-process `cpmt::payments::Evidence` from
the authenticated payment boundary, then pass `gate.input()` to `run_gate`.
Scope, member, action, provider and expiry are checked again. No provider calls
occur in this adapter; the payment executor owns payment idempotency and binds
receipts to their authenticated context. Global check retries remain idempotent.
Do not classify payment receipts as person-uniqueness evidence. The adapter emits
`uniqueness: None`, so a policy that demands uniqueness from it fails closed.


For level-and-period access, `payments::PaidAccessGate` accepts the protected
`cpmt::access::PaidAccess` result. The payment library verifies the configured
financial terms and transforms them before this boundary. The gate checks the
exact requested level (no implicit ranking), current period and existing context
and provider binding. It receives no amount, currency, payment instrument or
provider response. `PaymentGate` remains available for other explicitly selected
financial facts. Production dispatch, cost authorization and local simulation
remain inside cpmt/crpt; these gate adapters never contact payment providers.

## Isolated wallet certificate and trust publisher

The optional wallet publisher uses the original Keyhole registration certificate
and the original csgn/CBCN five-document trust format. It does not reuse the
`cgbl:global` passport issuer, community pseudonyms or a community policy. Wallet
member IDs are the UUIDs from the actual literal-wallet authentication. Public
revocation snapshots contain opaque passkey IDs and device keys, never those UUIDs.

The host must explicitly provision a separate csgn signer with issuer `wallet`,
its persistent signer store and secret key, and a `WalletPublicationConfig` with
all of these fields: the actual wallet RP ID, its one exact HTTPS passkey origin,
validated original rulebook, original wallet schema and complete schema history,
an explicit public community directory, and a positive whole-day snapshot
lifetime within that signer's validity limit. The Keyhole instance passed to
`Global::open_wallet` must retain exactly that literal-wallet RP/origin. There is
no discovered policy, key, origin or accepting unconfigured fallback. A private
instance relation also prevents passing this publisher to another Global facade.
Existing passport `GlobalPublic` and signed passport status remain separate.

All signed documents, effective revocations and ring-transition proofs are
retained through the original Store CAS before publication or transition
acknowledgment. Document revisions survive key rotations. Device bindings join
actual Account revisions and wallet publication state in the same CAS. The host
must call `signal_wallet_key_mutation` before an additional-key, revoke or self-ban
mutation, retain its original Auth/Global locks across that mutation, and publish
before acknowledging it. Publication acknowledges only the exact observed
pending generations and Account/device revisions; another generation refuses the
old result. Reconciliation reads actual original Keyhole tombstones and Account
eligibility. These local fences do not freeze independent remote writers.

Certificate and device operations require the actual authenticated current key
and that original grant's exclusive expiry. Each await is followed by a fresh
clock check bounded by the original elapsed lifetime. Refusal, cancellation or
uncertain CAS completion fences the live publisher; reopen the original stores
to reconcile the durable winner. A host must still retain the exact original
session, recheck the same grant/current key after awaits, and perform its final
live-clock/ring check before returning HTTP bytes. A signed certificate or a
device observation alone grants neither Create nor Use. Wallet custody requires
the same original certified-lineage, forced network read and current HTTPS owner
protocol as community custody. No initialized account, prover, G3 or Tor runtime
acceptance is established by this producer.

The exact live Global/Wallet/SDK instance also owns one mutation barrier. A
private `WalletMutation` carries its original owned guard into the SAME blocking
Keyhole worker. Cancelling the HTTP waiter cannot release that guard before the
SDK work definitively finishes. Publication captures this barrier before its
actual inventory and retains it through the original Beacon collect and
publication acknowledgment; certificate/device reads use the same owner.
`signal_wallet_key_mutation` requires that matching held permit and does not
re-lock it. Pending outbox state is not evidence that SDK work completed.

`WalletShutdown` synchronously fences new work, then waits for the original
worker-held barrier. The host must invoke it after stopping request intake and
await it within the original total shutdown budget before closing the database
runtime. A timed-out or cancelled wait is not a joined worker. Across restart,
a new live owner re-reads actual SDK rows and the durable generation rather than
reconstructing the old worker or accepting a pending boolean.
