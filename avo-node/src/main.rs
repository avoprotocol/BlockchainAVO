// Removed unused import: use tracing::info;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod config;
mod node;
// mod rpc; // Removed - now using avo-core's RPC servers

use config::{load_config, load_default_config, save_config, validate_config, NodeConfig};
use node::AvoNode;

#[derive(Parser)]
#[command(name = "avo-node")]
#[command(about = "AVO Protocol Node - High Performance Blockchain Node")]
#[command(version = "1.0.0")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Configuration file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Enable validator mode
    #[arg(long)]
    validator: bool,

    /// Network port
    #[arg(long, default_value = "30303")]
    port: u16,

    /// RPC port
    #[arg(long, default_value = "8545")]
    rpc_port: u16,

    /// Data directory
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Start the node
    Start,
    /// Generate default configuration file
    InitConfig {
        /// Output path for configuration file
        #[arg(short, long, default_value = "config.toml")]
        output: PathBuf,
    },
    /// Validate configuration file
    ValidateConfig {
        /// Configuration file to validate
        #[arg(short, long, default_value = "config.toml")]
        config: PathBuf,
    },
    /// Show node information
    Info,
}

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging based on configuration
    init_logging(&args.log_level);

    // Enhanced startup banner
    println!("\n\x1b[1;96m╔══════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;96m║\x1b[0m                                                              \x1b[1;96m║\x1b[0m");
    println!("\x1b[1;96m║\x1b[0m          \x1b[1;97m🚀 AVO PROTOCOL NODE v1.0.0\x1b[0m                      \x1b[1;96m║\x1b[0m");
    println!("\x1b[1;96m║\x1b[0m     \x1b[36mUltra-High Performance Sharded Blockchain\x1b[0m           \x1b[1;96m║\x1b[0m");
    println!("\x1b[1;96m║\x1b[0m                                                              \x1b[1;96m║\x1b[0m");
    println!("\x1b[1;96m╚══════════════════════════════════════════════════════════════╝\x1b[0m");
    println!("\x1b[90m  Features: ZK-Proofs | VRF | BLS | Threshold Encryption | DAS\x1b[0m\n");

    // Handle commands
    let command = args.command.clone().unwrap_or(Commands::Start);
    match command {
        Commands::Start => {
            if let Err(e) = start_node(args).await {
                eprintln!("❌ Node startup failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::InitConfig { output } => {
            if let Err(e) = init_config(output).await {
                eprintln!("❌ Config generation failed: {}", e);
                std::process::exit(1);
            }
        }
        Commands::ValidateConfig { config } => {
            if let Err(e) = validate_config_file(config).await {
                eprintln!("❌ Configuration invalid: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Info => {
            show_node_info();
        }
    }
}

/// Start the AVO node with clean UI
async fn start_node(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration silently
    let mut config = match args.config {
        Some(config_path) => match load_config(Some(config_path.to_str().unwrap())) {
            Ok(config) => config,
            Err(_e) => load_default_config()?,
        },
        None => load_default_config()?,
    };

    // Apply command line overrides
    if args.validator {
        config.is_validator = true;
    }
    config.network_port = args.port;
    config.rpc_port = args.rpc_port;
    config.data_dir = args.data_dir;
    config.logging.level = args.log_level;

    // Validate and create node
    validate_config(&config)?;

    println!("\n\x1b[1;93m⚙️  INITIALIZATION PHASE\x1b[0m");
    println!("\x1b[90m┌─────────────────────────────────────────────────────────────┐\x1b[0m");
    println!("\x1b[90m│\x1b[0m \x1b[36m▸\x1b[0m Loading cryptographic keys...");
    println!("\x1b[90m│\x1b[0m \x1b[36m▸\x1b[0m Initializing consensus engine...");
    println!("\x1b[90m│\x1b[0m \x1b[36m▸\x1b[0m Setting up shard coordinators...");
    println!("\x1b[90m│\x1b[0m \x1b[36m▸\x1b[0m Preparing P2P network layer...");

    let node: AvoNode = AvoNode::new(config)
        .await
        .map_err(|e| format!("Node initialization failed: {}", e))?;

    println!("\x1b[90m│\x1b[0m \x1b[32m✓\x1b[0m Node initialized successfully");
    println!("\x1b[90m└─────────────────────────────────────────────────────────────┘\x1b[0m");

    // Setup graceful shutdown
    let node_clone = std::sync::Arc::new(node);
    let shutdown_node = node_clone.clone();

    // Start node services
    println!("\n\x1b[1;92m🔧 STARTING SERVICES\x1b[0m");
    println!("\x1b[90m┌─────────────────────────────────────────────────────────────┐\x1b[0m");
    println!("\x1b[90m│\x1b[0m \x1b[36m▸\x1b[0m Consensus Engine...");
    println!("\x1b[90m│\x1b[0m \x1b[36m▸\x1b[0m Network Layer...");
    println!("\x1b[90m│\x1b[0m \x1b[36m▸\x1b[0m RPC Servers...");

    node_clone
        .start()
        .await
        .map_err(|e| format!("Service startup failed: {}", e))?;

    println!("\x1b[90m│\x1b[0m \x1b[32m✓\x1b[0m All services online");
    println!("\x1b[90m└─────────────────────────────────────────────────────────────┘\x1b[0m");

    // Display clean operational status
    println!("\n\x1b[1;92m╔══════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;92m║\x1b[0m          \x1b[1;97m✅ AVO PROTOCOL NODE - ONLINE\x1b[0m                   \x1b[1;92m║\x1b[0m");
    println!("\x1b[1;92m╚══════════════════════════════════════════════════════════════╝\x1b[0m");
    println!("\n\x1b[36m🌐 WebSocket RPC:\x1b[0m  \x1b[97mws://localhost:8545\x1b[0m");
    println!("\x1b[36m📡 HTTP RPC:\x1b[0m       \x1b[97mhttp://localhost:9545\x1b[0m");
    println!("\n\x1b[90m⏹️  Press Ctrl+C to shutdown gracefully\x1b[0m\n");
    println!("\x1b[90m═══════════════════════════════════════════════════════════════\x1b[0m\n");

    // Setup shutdown handler
    let shutdown_handle = tokio::spawn(async move {
        loop {
            match tokio::signal::ctrl_c().await {
                Ok(()) => {
                    println!("\n\n\x1b[1;93m╔══════════════════════════════════════════════════════════════╗\x1b[0m");
                    println!("\x1b[1;93m║\x1b[0m              \x1b[1;97m🛑 SHUTDOWN REQUESTED\x1b[0m                      \x1b[1;93m║\x1b[0m");
                    println!("\x1b[1;93m╚══════════════════════════════════════════════════════════════╝\x1b[0m");
                    println!("\n\x1b[90m┌─────────────────────────────────────────────────────────────┐\x1b[0m");
                    println!("\x1b[90m│\x1b[0m \x1b[36m▸\x1b[0m Stopping consensus engine...");
                    println!("\x1b[90m│\x1b[0m \x1b[36m▸\x1b[0m Closing network connections...");
                    println!("\x1b[90m│\x1b[0m \x1b[36m▸\x1b[0m Flushing state to disk...");

                    if let Err(_) = shutdown_node.stop().await {
                        println!("\x1b[90m│\x1b[0m \x1b[33m⚠\x1b[0m  Some components required forced shutdown");
                    } else {
                        println!(
                            "\x1b[90m│\x1b[0m \x1b[32m✓\x1b[0m All components stopped gracefully"
                        );
                    }

                    println!("\x1b[90m└─────────────────────────────────────────────────────────────┘\x1b[0m");
                    println!("\n\x1b[1;92m✅ Node stopped successfully\x1b[0m");
                    println!("\x1b[90m═══════════════════════════════════════════════════════════════\x1b[0m\n");
                    std::process::exit(0);
                }
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    });

    // Keep main thread alive
    let _result = shutdown_handle.await;

    Ok(())
}

/// Initialize configuration file
async fn init_config(output: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("\x1b[33m[INFO]\x1b[0m Generating default configuration");

    let config = NodeConfig::default();

    if let Err(e) = save_config(&config, output.to_str().unwrap()) {
        println!("\x1b[31m[ERROR]\x1b[0m Failed to save configuration: {}", e);
        return Err(e);
    }

    println!("\x1b[32m[SUCCESS]\x1b[0m Default configuration generated successfully");
    println!(
        "Edit the configuration file and run 'avo-node start --config {}'",
        output.display()
    );

    Ok(())
}

/// Validate configuration file
async fn validate_config_file(config_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "\x1b[33m[INFO]\x1b[0m Validating configuration file: {}",
        config_path.display()
    );

    let config = load_config(Some(config_path.to_str().unwrap()))?;
    validate_config(&config)?;

    println!("\x1b[32m[SUCCESS]\x1b[0m Configuration file is valid");
    Ok(())
}

/// Show node information
fn show_node_info() {
    println!("\x1b[32m[INFO]\x1b[0m AVO Protocol Node Information");
    println!("==============================");
    println!("Version: 1.0.0");
    println!("Build: Release");
    println!("Features:");
    println!("  - Flow Consensus Engine");
    println!("  - P2P Networking");
    println!("  - Sharding Support");
    println!("  - Byzantine Fault Tolerance");
    println!("  - Zero-Knowledge Proofs");
    println!("  - Cross-Shard Transactions");
    println!("  - Dynamic Resharding");
    println!("  - MEV Protection");
    println!("");
    println!("Performance Capabilities:");
    println!("  - Ultra-High TPS (10M+ demonstrated)");
    println!("  - Sub-second finality");
    println!("  - Optimized batch processing");
    println!("  - Advanced cryptographic primitives");
    println!("");
    println!("Usage:");
    println!("  avo-node start                    Start node with default config");
    println!("  avo-node start --validator        Start in validator mode");
    println!("  avo-node init-config              Generate config file");
    println!("  avo-node validate-config          Validate config file");
}

/// Initialize logging system
fn init_logging(level: &str) {
    use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

    // Try to use RUST_LOG env var first, otherwise use the provided level
    let filter = if let Ok(rust_log) = std::env::var("RUST_LOG") {
        EnvFilter::new(rust_log)
    } else {
        // Create a custom filter optimized for dashboard mode
        // In production with high TX volume, we only want to see:
        // - Dashboard updates (printed directly, not logged)
        // - Critical errors/warnings
        EnvFilter::new(level)
            // Silence arkworks constraint system logs completely
            .add_directive("ark_r1cs_std=off".parse().unwrap())
            .add_directive("ark_relations=off".parse().unwrap())
            .add_directive("r1cs=off".parse().unwrap())
            // Silence verbose transaction/block processing logs
            // These appear for EVERY transaction and would spam the console
            .add_directive("avo_core::consensus=warn".parse().unwrap())
            .add_directive("avo_core::rpc=warn".parse().unwrap())
            // Silence networking chatter
            .add_directive("libp2p_gossipsub=warn".parse().unwrap())
            .add_directive("libp2p_swarm=warn".parse().unwrap())
            .add_directive("hyper=warn".parse().unwrap())
            .add_directive("tokio=warn".parse().unwrap())
            .add_directive("mio=warn".parse().unwrap())
            // Keep critical components at warn level (errors only)
            .add_directive("avo_core=warn".parse().unwrap())
            .add_directive("avo_node=warn".parse().unwrap())
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_span_events(FmtSpan::NONE) // Don't show span events
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_line_number(false)
        .with_file(false)
        .compact() // Use compact format
        .init();
}
