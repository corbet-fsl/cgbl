# cgbl agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cgbl` — native suite, green
  (lib `13`, security `41`, storage `9`, contacts `5`, contact_auth `4`,
  doc `4` passed; dev-gated `global` `18` pass under `--all-features`,
  also green), exit 0; long, background it
- `~/agents/scratch/cbuild <lane> fmt -p cgbl -- --check` — must be clean
- Full gate (clippy `--locked` incl. `--all-features`, dev-gated `global`
  suite, release dev-gate negative probe, 100% coverage, pin/license
  checks) runs in CI only: `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- `development-gate` synthetic action never ships in release
  -> `src/tests/build_policy.rs::release_profile_emits_no_development_cfg` (+ CI probe)
- Uniqueness reservations and holder bindings are permanent: NO RETURN
  -> `tests/global.rs::durable_renewal_after_reopen_keeps_identity_and_rejects_new_secret`
- Blocks (legal order or self-ban) are terminal and bump the epoch
  -> `tests/security.rs::permanent_self_ban_before_any_gate_creates_only_terminal_state_and_survives_reopening`
- Storage only through `crlt`, per-key CAS, no ABA
  -> `tests/storage.rs::sql_rows_persist_with_indexed_reads_and_no_aba`
- Policy snapshots authenticated, scoped, strictly monotonic
  -> `tests/global.rs::policies_are_authenticated_scoped_monotonic_and_bounded`
- One pending issuance slot per person; inclusive deadline guard
  -> `tests/global.rs::guarded_issuance_observes_the_inclusive_deadline_and_refuses_the_following_tick`
- Paid gates idempotent; provider never rebilled on retry/CAS conflict
  -> `tests/security.rs::slow_paid_check_survives_unrelated_writes_and_cancelled_delivery_without_rebilling`
- `forbid(unsafe_code)`; no request logging; redacted diagnostics
  -> `tests/security.rs::authenticated_identifiers_enforce_bounds_and_redact_debug_output`

Pointers: `src/facade.rs`, `src/storage.rs`, `src/payments.rs`,
`docs/CONTRACT.md`, `docs/COVERAGE.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; FSL-1.1-ALv2; no GPL/AGPL-only deps; never publish to a registry.
