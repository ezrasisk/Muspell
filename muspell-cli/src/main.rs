//! `muspell` — command-line interface for the Muspell P2P network.
//!
//! ## Subcommands
//!
//! ```text
//! muspell node info              → local node key path and config
//! muspell node status            → GET /health from the running daemon
//! muspell kns resolve <name>     → resolve a KNS name and print the record
//! muspell kns verify  <name>     → resolve + validate ownership proof
//! muspell mirror stats           → mirror engine metrics from the daemon
//! muspell config show            → dump effective merged configuration as TOML
//! muspell config validate        → parse-only check (no daemon required)
//! ```

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use muspell_core::{KnsClient, MuspellConfig, OwnershipValidator};
use tracing_subscriber::EnvFilter;

// ── Top-level CLI ─────────────────────────────────────────────────────────────

/// Muspell — decentralized discovery and persistence for Iroh nodes.
#[derive(Debug, Parser)]
#[command(name = "muspell", version, about, propagate_version = true)]
struct Cli {
    /// Path to config file.
    /// Default: $XDG_CONFIG_HOME/muspell/config.toml
    #[arg(short, long, env = "MUSPELL_CONFIG", global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Base URL of the running muspelld health endpoint.
    #[arg(
        long,
        env = "MUSPELL_DAEMON_URL",
        global = true,
        default_value = "http://127.0.0.1:9090"
    )]
    daemon_url: String,

    /// Output format.
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
    /// Local Iroh node information.
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

#[derive(Debug, Subcommand)]
enum NodeCmd {
    /// Show the local node key path and identity info.
    Info,
    /// Query the running daemon's health endpoint.
    Status,
}

#[derive(Debug, Subcommand)]
enum KnsCmd {
    /// Resolve a KNS name and display the raw record.
    Resolve {
        /// KNS name to resolve, e.g. "alice.kas".
        name: String,
    },
    /// Resolve a KNS name and cryptographically verify the ownership proof.
    Verify {
        /// KNS name to verify.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
enum MirrorCmd {
    /// Display mirror engine statistics from the running daemon.
    Stats,
}

#[derive(Debug, Subcommand)]
enum ConfigCmd {
    /// Dump the effective (merged) configuration as TOML.
    Show,
    /// Validate the config file without starting the daemon.
    Validate,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_node(cmd: NodeCmd, config: &MuspellConfig, daemon_url: &str, output: &OutputFormat) -> Result<()> {
    match cmd {
        NodeCmd::Info => {
            match output {
                OutputFormat::Json => {
                    let v = serde_json::json!({
                        "key_path": config.node.key_path.display().to_string(),
                        "owned_names": config.node.owned_names,
                    });
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
                OutputFormat::Pretty => {
                    println!("Key path     : {}", config.node.key_path.display());
                    println!("Owned names  : {:?}", config.node.owned_names);
                    println!("(start muspelld to see the live NodeId)");
                }
            }
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
                    println!("HTTP status   : {status}");
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
        MirrorCmd::Stats => {
            let resp = reqwest::get(format!("{daemon_url}/health"))
                .await
                .context("daemon unreachable — is muspelld running?")?;
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
            // `toml` is declared in muspell-cli's Cargo.toml (it was missing originally).
            let toml_str = toml::to_string_pretty(config)
                .context("failed to serialise config to TOML")?;
            print!("{toml_str}");
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
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();

    let config = MuspellConfig::load_or_default(cli.config.as_ref())
        .context("failed to load configuration")?;

    match cli.command {
        Commands::Node   { cmd } => handle_node(cmd, &config, &cli.daemon_url, &cli.output).await,
        Commands::Kns    { cmd } => handle_kns(cmd, &config, &cli.output).await,
        Commands::Mirror { cmd } => handle_mirror(cmd, &cli.daemon_url, &cli.output).await,
        Commands::Config { cmd } => handle_config(cmd, &config).await,
    }
}
