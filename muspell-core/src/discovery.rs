//! Iroh `Discovery` provider that resolves node addresses via KNS.
//!
//! When Iroh tries to connect to a `NodeId` it doesn't have an address for,
//! it calls every registered `Discovery` implementation.  `KnsDiscoveryProvider`
//! fulfils that role by:
//!
//! 1. Looking up the node ID in a reverse-index (node_id → kns_name).
//! 2. Resolving the KNS name via [`KnsClient`].
//! 3. Validating the returned record with [`OwnershipValidator`].
//! 4. Converting relay hints into Iroh `AddrInfo`.
//!
//! The reverse index is populated out-of-band (e.g. by the daemon) via
//! [`KnsDiscoveryProvider::register`].

use std::{collections::HashMap, sync::Arc};

use iroh::{
    discovery::{Discovery, DiscoveryItem},
    NodeId,
};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, instrument, warn};

use crate::{
    error::{MuspellError, Result},
    kns::{KnsRecord, KnsResolver},
    security::OwnershipValidator,
};

// ── Registration state ────────────────────────────────────────────────────────

/// Mapping maintained by the daemon: Iroh NodeId ↔ KNS name.
#[derive(Debug, Default)]
struct Registry {
    /// node_id (hex) → kns_name
    by_node_id: HashMap<String, String>,
    /// kns_name → node_id (hex)
    by_name: HashMap<String, String>,
}

// ── Provider ──────────────────────────────────────────────────────────────────

/// Iroh `Discovery` implementation backed by the Kaspa Name Service.
pub struct KnsDiscoveryProvider<R: KnsResolver> {
    resolver: Arc<R>,
    registry: Arc<RwLock<Registry>>,
}

impl<R: KnsResolver> KnsDiscoveryProvider<R> {
    /// Create a new provider wrapping `resolver`.
    pub fn new(resolver: Arc<R>) -> Self {
        Self {
            resolver,
            registry: Arc::new(RwLock::new(Registry::default())),
        }
    }

    /// Register a (node_id, kns_name) mapping so that `resolve` can look up
    /// the right KNS name when Iroh asks for a given `NodeId`.
    pub fn register(&self, node_id_hex: impl Into<String>, kns_name: impl Into<String>) {
        let node_id = node_id_hex.into();
        let name    = kns_name.into();
        let mut reg = self.registry.write();
        reg.by_name.insert(name.clone(), node_id.clone());
        reg.by_node_id.insert(node_id, name);
        info!("registered KNS mapping");
    }

    /// Remove a mapping (e.g. when a name is transferred to another owner).
    pub fn deregister(&self, kns_name: &str) {
        let mut reg = self.registry.write();
        if let Some(node_id) = reg.by_name.remove(kns_name) {
            reg.by_node_id.remove(&node_id);
        }
    }

    /// Resolve a KNS name and return the validated [`KnsRecord`].
    #[instrument(skip(self))]
    pub async fn resolve_name(&self, name: &str) -> Result<KnsRecord> {
        let record = self.resolver.resolve(name).await?;
        OwnershipValidator::verify_ownership_proof(
            &record.iroh_node_id,
            &record.ownership_proof,
        )?;
        Ok(record)
    }

    /// Internal: given a node ID, find its KNS name and resolve it.
    async fn resolve_node_id(&self, node_id_hex: &str) -> Result<KnsRecord> {
        let name = {
            let reg = self.registry.read();
            reg.by_node_id.get(node_id_hex).cloned()
        };

        let name = name.ok_or_else(|| MuspellError::KnsNotFound {
            name: node_id_hex.to_string(),
            attempts: 0,
        })?;

        self.resolve_name(&name).await
    }

    /// Convert a [`KnsRecord`]'s relay hints into Iroh [`DiscoveryItem`]s.
    fn record_to_discovery_items(record: &KnsRecord) -> Vec<DiscoveryItem> {
        record
            .relay_hints
            .iter()
            .filter_map(|hint| {
                hint.parse::<iroh::RelayUrl>()
                    .ok()
                    .map(|relay_url| {
                        let node_id = record
                            .iroh_node_id
                            .parse::<NodeId>()
                            .expect("validated before this call");

                        DiscoveryItem {
                            node_id,
                            provenance: "kns",
                            last_updated: None,
                            addr_info: iroh::NodeAddr {
                                node_id,
                                relay_url: Some(relay_url),
                                direct_addresses: Default::default(),
                            },
                        }
                    })
            })
            .collect()
    }
}

// ── Iroh Discovery trait implementation ───────────────────────────────────────

impl<R: KnsResolver + 'static> Discovery for KnsDiscoveryProvider<R> {
    fn resolve(
        &self,
        _endpoint: iroh::Endpoint,
        node_id: NodeId,
    ) -> Option<iroh::discovery::BoxedFuture<iroh::discovery::BoxedStream<DiscoveryItem>>> {
        let node_id_hex = hex::encode(node_id.as_bytes());
        let resolver    = Arc::clone(&self.resolver);
        let registry    = Arc::clone(&self.registry);

        let fut = async move {
            let name = {
                let reg = registry.read();
                reg.by_node_id.get(&node_id_hex).cloned()
            };

            let name = match name {
                Some(n) => n,
                None => {
                    debug!(node_id = %node_id_hex, "no KNS mapping, skipping");
                    // Return an empty stream rather than an error
                    let (tx, rx) = mpsc::channel::<DiscoveryItem>(1);
                    drop(tx);
                    return Box::pin(ReceiverStream::new(rx))
                        as iroh::discovery::BoxedStream<DiscoveryItem>;
                }
            };

            match resolver.resolve(&name).await {
                Ok(record) => {
                    // Security: validate the proof before handing addresses to Iroh
                    if let Err(e) = OwnershipValidator::verify_ownership_proof(
                        &record.iroh_node_id,
                        &record.ownership_proof,
                    ) {
                        error!(name = %name, error = %e, "ownership proof failed, dropping record");
                        let (tx, rx) = mpsc::channel::<DiscoveryItem>(1);
                        drop(tx);
                        return Box::pin(ReceiverStream::new(rx))
                            as iroh::discovery::BoxedStream<DiscoveryItem>;
                    }

                    let items = Self::record_to_discovery_items(&record);
                    let (tx, rx) = mpsc::channel::<DiscoveryItem>(items.len().max(1));
                    for item in items {
                        let _ = tx.send(item).await;
                    }
                    Box::pin(ReceiverStream::new(rx)) as iroh::discovery::BoxedStream<DiscoveryItem>
                }
                Err(e) => {
                    warn!(name = %name, error = %e, "KNS resolution failed");
                    let (tx, rx) = mpsc::channel::<DiscoveryItem>(1);
                    drop(tx);
                    Box::pin(ReceiverStream::new(rx)) as iroh::discovery::BoxedStream<DiscoveryItem>
                }
            }
        };

        Some(Box::pin(fut))
    }
}
