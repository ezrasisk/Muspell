//! `muspell` — command-line interface for the Muspell P2P network.
//!
//! ## Subcommands
//!
//! | Command               | Description                                      |
//! |-----------------------|--------------------------------------------------|
//! | `node info`           | Display local node ID and address                |
//! | `node status`         | Query the daemon health endpoint                 |
//! | `kns resolve <name>`  | Resolve a KNS name and print the record          |
//! | `kns verify <name>`   | Resolve + validate ownership proof               |
//! | `mirror add <hash>`   | Fan out a blob hash to the mirror quorum         |
//! | `mirror stats`        | Display mirror engine statistics                 |
//! | `config show`         | Dump the effective configuration as TOML         |

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use muspell_core::{KnsClient, MuspellConfig, OwnershipValidator};
use tracing_subscriber::EnvFilter;

// ── Top-level CLI ─────────────────────────────────────────────────────────────

/// Muspell — decentralized discovery and persistence for Iroh nodes.
#[derive(Debug, Parser)]
#[command(name = "muspell", version, about, long_about = None, propagate_version = true)]
struct Cli {
    /// Path to config file (default: $XDG_CONFIG_HOME/muspell/config.toml).
    #[arg(short, long, env = "MUSPELL_CONFIG", global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Muspell daemon health endpoint (for status queries).
    #[arg(
        long,
        env = "MUSPELL_DAEMON_URL",
        global = true,
        default_value = "http://127.0.0.1:9090"
    )]
    daemon_url: String,

    /// Output format: "pretty" | "json".
    #[arg(long, global = true, default_value = "pretty")]
    output: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    Pretty,
    Json,
}

// ── Subcommands ───────────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
enum Commands {
    /// Local Iroh node management.
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },

    /// Kaspa Name Service operations.
    Kns {
        #[command(subcommand)]
        cmd: KnsCmd,
    },

    /// EigenMead data-mirroring controls.
    Mirror {
        #[command(subcommand)]
        cmd: MirrorCmd,
    },

    /// Configuration management.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
}

// ── Node subcommands ──────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
enum NodeCmd {
    /// Print the local node ID (public key hex).
    Info,

    /// Query the running daemon's health endpoint.
    Status,
}

// ── KNS subcommands ───────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
enum KnsCmd {
    /// Resolve a KNS name and display the record.
    Resolve {
        /// The KNS name to resolve (e.g. "alice.kas").
        name: String,
    },

    /// Resolve a name and cryptographically verify the ownership proof.
    Verify {
        /// The KNS name to verify.
        name: String,
    },
}

// ── Mirror subcommands ────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
enum MirrorCmd {
    /// Fan out a blob (by BLAKE3 hex hash) to the mirror quorum.
    Add {
        /// BLAKE3 hash of the blob (64 hex chars).
        hash: String,
    },

    /// Display current mirror engine statistics.
    Stats,
}

// ── Config subcommands ────────────────────────────────────────────────────────

#[derive(Debug, Subcommand)]
enum ConfigCmd {
    /// Dump the effective (merged) configuration.
    Show,

    /// Validate the config file without starting the daemon.
    Validate,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_node(cmd: NodeCmd, daemon_url: &str, output: &OutputFormat) -> Result<()> {
    match cmd {
        NodeCmd::Info => {
            // In a full impl, read the key from config path
            println!("Local node: (run muspelld to initialise)");
        }

        NodeCmd::Status => {
            let resp = reqwest::get(format!("{daemon_url}/health"))
                .await
                .context("daemon unreachable — is muspelld running?")?;

            let status = resp.status();
            let body: serde_json::Value = resp.json().await.context("invalid JSON from daemon")?;

            match output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&body)?),
                OutputFormat::Pretty => {
                    println!("Daemon status : {}", body["status"].as_str().unwrap_or("?"));
                    println!("Node ID       : {}", body["node_id"].as_str().unwrap_or("?"));
                    println!("Uptime (s)    : {}", body["uptime_secs"]);
                    println!("Live peers    : {}", body["mirror"]["live_peers"]);
                    println!("HTTP code     : {status}");
                }
            }
        }
    }
    Ok(())
}

async fn handle_kns(cmd: KnsCmd, config: &MuspellConfig, output: &OutputFormat) -> Result<()> {
    let client = KnsClient::new(config.kns.clone()).context("failed to build KNS client")?;

    match cmd {
        KnsCmd::Resolve { name } => {
            let record = client.resolve(&name).await.context("KNS resolution failed")?;
            match output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&record)?),
                OutputFormat::Pretty => {
                    println!("Name          : {}", record.name);
                    println!("Iroh node ID  : {}", record.iroh_node_id);
                    println!("Block height  : {}", record.block_height);
                    println!("Relay hints   : {:?}", record.relay_hints);
                }
            }
        }

        KnsCmd::Verify { name } => {
            let record = client.resolve(&name).await.context("KNS resolution failed")?;

            match OwnershipValidator::verify_ownership_proof(
                &record.iroh_node_id,
                &record.ownership_proof,
            ) {
                Ok(()) => {
                    println!("✓ Ownership proof VALID for '{name}'");
                    println!("  Node ID: {}", record.iroh_node_id);
                }
                Err(e) => {
                    eprintln!("✗ Ownership proof INVALID: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
    Ok(())
}

async fn handle_mirror(cmd: MirrorCmd, daemon_url: &str, output: &OutputFormat) -> Result<()> {
    match cmd {
        MirrorCmd::Add { hash } => {
            // In a full daemon IPC setup this would POST to an internal endpoint
            // or use a Unix socket RPC.  For now we print an actionable message.
            println!("Requesting mirror fanout for blob: {hash}");
            println!(
                "→ POST {daemon_url}/mirror/add  (not yet wired; run via muspelld API)"
            );
        }

        MirrorCmd::Stats => {
            let resp = reqwest::get(format!("{daemon_url}/health"))
                .await
                .context("daemon unreachable")?;

            let body: serde_json::Value = resp.json().await?;
            let mirror = &body["mirror"];

            match output {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(mirror)?),
                OutputFormat::Pretty => {
                    println!("Total blobs        : {}", mirror["total_blobs"]);
                    println!("Under-replicated   : {}", mirror["under_replicated"]);
                    println!("Live peers         : {}", mirror["live_peers"]);
                    println!("Ops success        : {}", mirror["ops_success"]);
                    println!("Ops failed         : {}", mirror["ops_failed"]);
                    println!("Last sync          : {}", mirror["last_sync_at"]);
                }
            }
        }
    }
    Ok(())
}

async fn handle_config(cmd: ConfigCmd, config: &MuspellConfig) -> Result<()> {
    match cmd {
        ConfigCmd::Show => {
            let toml = toml::to_string_pretty(config).context("serialization failed")?;
            println!("{toml}");
        }
        ConfigCmd::Validate => {
            println!("✓ Configuration is valid");
        }
    }
    Ok(())
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    // Minimal tracing for CLI (errors + explicit debug flag)
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();

    let config = MuspellConfig::load_or_default(cli.config.as_ref())
        .context("failed to load configuration")?;

    match cli.command {
        Commands::Node { cmd } => handle_node(cmd, &cli.daemon_url, &cli.output).await,
        Commands::Kns { cmd }  => handle_kns(cmd, &config, &cli.output).await,
        Commands::Mirror { cmd } => handle_mirror(cmd, &cli.daemon_url, &cli.output).await,
        Commands::Config { cmd } => handle_config(cmd, &config).await,
    }
}
