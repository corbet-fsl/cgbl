//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`); `src/tests` still holds the library's `#[path]` unit tests.
pub mod softtoken;
pub use softtoken::SoftwareToken;

mod contact_authorization;
mod contacts;
mod facade_kills;
mod global;
mod mut138;
mod security;
mod stamp_budget;
mod stamp_edge;
mod storage;
mod wallet_config;
mod wallet_open;
mod wallet_publication;
