//! # muspell-core
//!
//! Production-grade library providing:
//! * KNS (Kaspa Name Service) discovery for Iroh node IDs
//! * EigenMead-pattern data mirroring across discovered peers
//! * Cryptographic ownership validation to prevent node spoofing
//!
//! ## Architecture overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                     muspell-core                         │
//! │                                                          │
//! │  ┌───────────────┐    ┌───────────────────────────────┐  │
//! │  │  KnsResolver  │───▶│     DiscoveryProvider         │  │
//! │  │  (RPC client) │    │  (Iroh Discovery trait impl)  │  │
//! │  └───────────────┘    └───────────────────────────────┘  │
//! │          │                         │                     │
//! │          ▼                         ▼                     │
//! │  ┌───────────────┐    ┌───────────────────────────────┐  │
//! │  │  OwnershipVal │    │     MirrorEngine (EigenMead)  │  │
//! │  │  (ed25519)    │    │    blob-sync + gossip fanout  │  │
//! │  └───────────────┘    └───────────────────────────────┘  │
//! └─────────────────────────────────────────────────────────┘
//! ```

#![forbid(unsafe_code)]
#![warn(
    clippy::pedantic,
    clippy::cargo,
    missing_docs,
    rustdoc::broken_intra_doc_links
)]
#![allow(clippy::module_name_repetitions)]

pub mod config;
pub mod discovery;
pub mod error;
pub mod kns;
pub mod mirror;
pub mod node;
pub mod security;

// Convenient top-level re-exports consumed by daemon / CLI
pub use config::MuspellConfig;
pub use discovery::KnsDiscoveryProvider;
pub use error::{MuspellError, Result};
pub use kns::{KnsClient, KnsRecord};
pub use mirror::{MirrorEngine, MirrorStats};
pub use node::MuspellNode;
pub use security::OwnershipValidator;
