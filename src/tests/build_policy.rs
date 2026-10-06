use super::*;
use std::env::VarError;

#[test]
fn debug_profile_emits_the_development_cfg() {
    assert_eq!(
        development_cfg_line(Ok("debug".to_owned())),
        "cargo:rustc-cfg=cgbl_development\n"
    );
}

#[test]
fn release_profile_emits_no_development_cfg() {
    // PROFILE stays "release" when CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=true
    // (proven by the release probe in .ci/verify.sh); the policy must read
    // PROFILE, not debug_assertions, so a cfg(debug_assertions) regression
    // fails the debug case above under the debug test profile.
    assert_eq!(development_cfg_line(Ok("release".to_owned())), "");
    assert_eq!(development_cfg_line(Err(VarError::NotPresent)), "");
    assert_eq!(development_cfg_line(Ok(String::new())), "");
}
