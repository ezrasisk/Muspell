//! [`MuspellNode`] — top-level assembly wiring Iroh, KNS discovery, and the
//! mirror engine together.
//!
//! ## Iroh 0.35 API notes
//!
//! * `Endpoint::builder()` returns a `Builder`.
//! * `.add_discovery(svc)` — registers a discovery service (correct method name;
//!   `.discovery()` does not exist in 0.35).
//! * `.bind().await?` — finalises the endpoint.
//! * `SecretKey::generate(rng)` — correct constructor.
//! * `SecretKey::to_bytes() -> [u8; 32]` and `SecretKey::from([u8; 32])` —
//!   correct persistence; there is no `to_openssh` / `try_from_openssh`.
//! * `Router::builder(endpoint).accept(ALPN, handler).spawn()` — protocol stack.
//! * `Blobs::memory().build(&endpoint)` — correct iroh-blobs 0.35 init.
//! * `Gossip::builder().spawn(endpoint.clone())` — correct iroh-gossip 0.35 init.

use std::{sync::Arc, time::Duration};

use iroh::{
    discovery::StaticDiscovery,
    protocol::Router,
    Endpoint, NodeId, SecretKey,
};
use iroh_blobs::net_protocol::Blobs;
use iroh_gossip::{Gossip, TopicId};
use tracing::{info, instrument};

use crate::{
    config::MuspellConfig,
    discovery::KnsDiscoveryProvider,
    error::{MuspellError, Result},
    kns::KnsClient,
    mirror::{MirrorEngine, MirrorStats},
    security::OwnershipValidator,
};

// ── Mirror gossip topic ───────────────────────────────────────────────────────

/// Well-known gossip topic ID for the Muspell eigen-set.
/// All nodes sharing a mirror set must use the same 32-byte value.
const MIRROR_TOPIC: TopicId = TopicId::from_bytes([
    b'm', b'u', b's', b'p', b'e', b'l', b'l', b'-',
    b'm', b'i', b'r', b'r', b'o', b'r', b'-', b'v',
    b'1', 0,   0,   0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,
]);

// ── MuspellNode ───────────────────────────────────────────────────────────────

/// The fully-assembled Muspell node.
pub struct MuspellNode {
    /// Underlying Iroh endpoint.
    pub endpoint: Endpoint,

    /// KNS-backed discovery helper (owns the `StaticDiscovery`).
    pub discovery: Arc<KnsDiscoveryProvider<KnsClient>>,

    /// Iroh protocol router — keeps blob and gossip handlers alive.
    /// Must not be dropped until shutdown.
    router: Router,

    /// EigenMead mirror engine.
    pub mirror: MirrorEngine,

    config: MuspellConfig,
}

impl MuspellNode {
    /// Build and start a node from the provided configuration.
    ///
    /// # Errors
    ///
    /// Returns `MuspellError` on key loading failure, KNS validation failure,
    /// or Iroh endpoint bind failure.
    #[instrument(skip(config))]
    pub async fn start(config: MuspellConfig) -> Result<Self> {
        // ── 1. Load / generate secret key ─────────────────────────────────
        let secret_key = Self::load_or_create_key(&config).await?;
        let node_id_hex = hex::encode(secret_key.public().as_bytes());
        info!(node_id = %node_id_hex, "node identity loaded");

        // ── 2. KNS client + StaticDiscovery ───────────────────────────────
        let kns_client = Arc::new(KnsClient::new(config.kns.clone())?);
        // This Arc is shared between the discovery provider and the endpoint
        // builder — both must point to the same allocation.
        let static_disc = Arc::new(StaticDiscovery::default());
        let discovery = Arc::new(KnsDiscoveryProvider::new(
            Arc::clone(&kns_client),
            Arc::clone(&static_disc),
        ));

        // ── 3. Validate owned names (anti-spoofing) ───────────────────────
        for name in &config.node.owned_names {
            info!(name, "validating owned KNS name on startup");
            let record = kns_client.resolve(name).await?;
            OwnershipValidator::validate(&record, &node_id_hex)?;
            discovery.register(node_id_hex.clone(), name.clone());
            info!(name, "KNS ownership confirmed");
        }

        // ── 4. Build Iroh endpoint ────────────────────────────────────────
        // Correct iroh 0.35 builder API:
        //   .add_discovery(svc)  → registers a discovery service
        //   .bind().await?       → creates the endpoint
        //
        // We clone the Arc out of static_disc so the endpoint owns one ref
        // while KnsDiscoveryProvider keeps the other.
        let static_disc_clone: StaticDiscovery = (*static_disc).clone();
        let endpoint = Endpoint::builder()
            .secret_key(secret_key)
            // Our KNS side-channel discovery (populated by the provider).
            .add_discovery(static_disc_clone)
            // N0's public DNS/pkarr discovery for general connectivity.
            .discovery_n0()
            .bind()
            .await
            .map_err(MuspellError::iroh)?;

        info!(node_id = %endpoint.node_id(), "Iroh endpoint bound");

        // ── 5. Protocol stack ─────────────────────────────────────────────
        // iroh-blobs 0.35: Blobs::memory().build(&endpoint)
        // iroh-gossip 0.35: Gossip::builder().spawn(endpoint.clone())
        let blobs  = Blobs::memory().build(&endpoint);
        let gossip = Gossip::builder().spawn(endpoint.clone());

        let router = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs.clone())
            .accept(iroh_gossip::ALPN, gossip.clone())
            .spawn();

        // ── 6. Mirror engine ──────────────────────────────────────────────
        let sync_interval = Duration::from_secs(config.mirror.sync_interval_s);
        let mirror = MirrorEngine::spawn(
            Arc::new(blobs),
            Arc::new(gossip),
            MIRROR_TOPIC,
            config.mirror.quorum,
            sync_interval,
            config.mirror.max_concurrent_syncs,
        );

        Ok(Self { endpoint, discovery, router, mirror, config })
    }

    // ── Public helpers ────────────────────────────────────────────────────

    /// The local Iroh `NodeId` (Ed25519 public key).
    pub fn node_id(&self) -> NodeId {
        self.endpoint.node_id()
    }

    /// Current mirror engine statistics.
    pub fn mirror_stats(&self) -> MirrorStats {
        self.mirror.stats()
    }

    /// Gracefully stop the node.
    pub async fn shutdown(self) {
        info!("shutting down MuspellNode");
        self.mirror.shutdown().await;
        // Router::shutdown() also closes the underlying endpoint cleanly.
        if let Err(e) = self.router.shutdown().await {
            tracing::warn!(error = %e, "router shutdown error (non-fatal)");
        }
    }

    // ── Private ───────────────────────────────────────────────────────────

    /// Load secret key from disk (raw 32 bytes), or generate and save a new one.
    ///
    /// In iroh 0.35:
    ///   `SecretKey::generate(rng)` — correct constructor.
    ///   `key.to_bytes() -> [u8; 32]` — correct serialisation.
    ///   `SecretKey::from([u8; 32])` — correct deserialisation.
    ///
    ///   There is NO `to_openssh()` / `try_from_openssh()` — those were
    ///   invented in the original buggy code.
    async fn load_or_create_key(config: &MuspellConfig) -> Result<SecretKey> {
        let path = &config.node.key_path;

        if path.exists() {
            let bytes = tokio::fs::read(path).await?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                MuspellError::Config(format!(
                    "key file at '{}' has wrong length (expected 32 bytes)",
                    path.display()
                ))
            })?;
            let key = SecretKey::from(arr);
            info!(path = %path.display(), "loaded existing node key");
            return Ok(key);
        }

        // Generate a fresh key and persist raw bytes.
        let key = SecretKey::generate(rand::rngs::OsRng);
        let raw: [u8; 32] = key.to_bytes();

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        #[cfg(unix)]
        {
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(&raw)?;
        }
        #[cfg(not(unix))]
        tokio::fs::write(path, &raw).await?;

        info!(path = %path.display(), "generated and saved new node key");
        Ok(key)
    }
}
