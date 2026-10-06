//! Keep the development gate out of every release profile.
#[path = "src/build_policy.rs"]
mod build_policy;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(cgbl_development)");
    // PROFILE distinguishes release even when debug assertions are enabled.
    print!(
        "{}",
        build_policy::development_cfg_line(std::env::var("PROFILE"))
    );
}
