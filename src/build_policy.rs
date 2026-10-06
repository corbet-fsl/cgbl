//! Build-profile policy for the development gate.
//! Shared by `build.rs` (which compiles this file unconditionally) and the
//! library test build (which gates it with `#[cfg(test)]`, so no production
//! library code ships). `PROFILE` stays `release` even when
//! `CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true`, so release builds never
//! enable the gate. Enforced in CI by the debug integration suite (which
//! requires the cfg) and the release probe; unit tests below pin both arms.
pub(crate) fn development_cfg_line(profile: Result<String, std::env::VarError>) -> &'static str {
    if profile.as_deref() == Ok("debug") {
        "cargo:rustc-cfg=cgbl_development\n"
    } else {
        ""
    }
}

#[cfg(test)]
#[path = "tests/build_policy.rs"]
mod tests;
