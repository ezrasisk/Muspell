//! KNS-backed discovery helper for Iroh.
//!
//! ## Pattern (iroh 0.35)
//!
//! iroh 0.35 provides `iroh::discovery::StaticDiscovery` — a simple in-memory
//! map from `NodeId` → `NodeAddr` that you populate from any side channel.
//! When Iroh needs to connect to a `NodeId` it doesn't have an address for,
//! it calls every registered discovery service; `StaticDiscovery` returns the
//! most recently stored `NodeAddr` for that id.
//!
//! We populate it from KNS:
//!
//! ```text
//! KnsClient::resolve(name)
//!   → OwnershipValidator::verify_ownership_proof()
//!   → parse NodeAddr from record
//!   → StaticDiscovery::add_node_addr()
//!   → Iroh can now dial the peer
//! ```
//!
//! The builder method in 0.35 is `Endpoint::builder().add_discovery(svc)`.
//! A single `StaticDiscovery` instance is shared via `Arc` between this
//! provider and the endpoint builder.

use std::{collections::HashMap, sync::Arc};

use iroh::{
    discovery::StaticDiscovery,
    NodeAddr, NodeId, RelayUrl,
};
use parking_lot::RwLock;
use tracing::{debug, info, instrument, warn};

use crate::{
    error::{MuspellError, Result},
    kns::{KnsRecord, KnsResolver},
    security::OwnershipValidator,
};

// ── Registry ──────────────────────────────────────────────────────────────────

/// Bidirectional mapping: KNS name ↔ NodeId (hex).
#[derive(Debug, Default)]
struct Registry {
    /// hex(node_id) → kns_name
    by_node_id: HashMap<String, String>,
    /// kns_name → hex(node_id)
    by_name: HashMap<String, String>,
}

// ── Provider ──────────────────────────────────────────────────────────────────

/// KNS-backed discovery helper.
///
/// Wraps an `Arc<StaticDiscovery>` that must be the **same instance** given to
/// `Endpoint::builder().add_discovery(Arc::clone(&static_disc))`.  When a name
/// is resolved and validated, the resulting `NodeAddr` is injected into
/// `StaticDiscovery` so iroh can dial the peer by `NodeId`.
pub struct KnsDiscoveryProvider<R: KnsResolver> {
    resolver: Arc<R>,
    /// Shared with the Iroh endpoint.
    pub static_discovery: Arc<StaticDiscovery>,
    registry: Arc<RwLock<Registry>>,
}

impl<R: KnsResolver> KnsDiscoveryProvider<R> {
    /// Create a new provider.
    ///
    /// `static_discovery` must be the same `Arc<StaticDiscovery>` that is
    /// (or will be) registered with the `Endpoint` builder via `add_discovery`.
    pub fn new(resolver: Arc<R>, static_discovery: Arc<StaticDiscovery>) -> Self {
        Self {
            resolver,
            static_discovery,
            registry: Arc::new(RwLock::new(Registry::default())),
        }
    }

    // ── Registration ──────────────────────────────────────────────────────

    /// Associate a `NodeId` (hex) with a KNS name.
    ///
    /// This does **not** resolve the name immediately; call
    /// [`resolve_and_register`] to push actual addressing info to
    /// `StaticDiscovery`.
    pub fn register(&self, node_id_hex: impl Into<String>, kns_name: impl Into<String>) {
        let node_id = node_id_hex.into();
        let name    = kns_name.into();
        let mut reg = self.registry.write();
        reg.by_name.insert(name.clone(), node_id.clone());
        reg.by_node_id.insert(node_id.clone(), name.clone());
        info!(node_id, name, "registered KNS ↔ NodeId mapping");
    }

    /// Remove a KNS mapping (e.g. after ownership transfer).
    pub fn deregister(&self, kns_name: &str) {
        let mut reg = self.registry.write();
        if let Some(node_id) = reg.by_name.remove(kns_name) {
            reg.by_node_id.remove(&node_id);
        }
    }

    // ── Resolution ────────────────────────────────────────────────────────

    /// Resolve `name` via KNS, validate the ownership proof, and inject the
    /// resulting [`NodeAddr`] into `StaticDiscovery`.
    ///
    /// After this returns `Ok`, iroh can connect to the peer by `NodeId`
    /// without any further intervention.
    ///
    /// # Errors
    ///
    /// * [`MuspellError::KnsNotFound`] / [`MuspellError::KnsTransport`] on
    ///   resolution failure.
    /// * [`MuspellError::InvalidOwnershipProof`] if the signature is bad.
    /// * [`MuspellError::NodeKeyMismatch`] if the hex is malformed.
    #[instrument(skip(self))]
    pub async fn resolve_and_register(&self, name: &str) -> Result<KnsRecord> {
        let record = self.resolver.resolve(name).await?;

        // Security: validate before trusting any address information.
        OwnershipValidator::verify_ownership_proof(
            &record.iroh_node_id,
            &record.ownership_proof,
        )?;

        let node_id = self.parse_node_id(&record.iroh_node_id)?;

        // Use the first relay hint if present.
        let relay_url: Option<RelayUrl> = record
            .relay_hints
            .first()
            .and_then(|h| h.parse().ok());

        // In iroh 0.35, NodeAddr { node_id, info: AddrInfo { relay_url,
        // direct_addresses } } is the correct struct layout.
        let node_addr = NodeAddr::from_parts(
            node_id,
            relay_url,
            [],  // no direct addresses from KNS records
        );

        self.static_discovery.add_node_addr(node_addr)
            .map_err(MuspellError::iroh)?;

        debug!(name, node_id = %record.iroh_node_id, "NodeAddr injected into StaticDiscovery");
        Ok(record)
    }

    /// Refresh all registered KNS names. Called by the daemon's periodic loop.
    pub async fn refresh_all(&self) {
        let names: Vec<String> = {
            let reg = self.registry.read();
            reg.by_name.keys().cloned().collect()
        };

        for name in names {
            match self.resolve_and_register(&name).await {
                Ok(_)  => debug!(name, "KNS record refreshed"),
                Err(e) => warn!(name, error = %e, "KNS refresh failed"),
            }
        }
    }

    // ── Private ───────────────────────────────────────────────────────────

    fn parse_node_id(&self, hex_str: &str) -> Result<NodeId> {
        let bytes = hex::decode(hex_str).map_err(|_| MuspellError::NodeKeyMismatch {
            kns_owner: hex_str.to_string(),
            presented: "(hex decode failed)".to_string(),
        })?;

        let arr: [u8; 32] = bytes.try_into().map_err(|_| MuspellError::NodeKeyMismatch {
            kns_owner: hex_str.to_string(),
            presented: "expected 32 bytes for NodeId".to_string(),
        })?;

        NodeId::from_bytes(&arr).map_err(MuspellError::iroh)
    }
}
