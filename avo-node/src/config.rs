use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Node configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Unique node identifier
    pub node_id: String,
    /// Network port for P2P communication
    pub network_port: u16,
    /// Consensus port for consensus messages
    pub consensus_port: u16,
    /// RPC server port
    pub rpc_port: u16,
    /// Enable RPC server
    pub rpc_enabled: bool,
    /// Data directory for blockchain data
    pub data_dir: PathBuf,
    /// Validator private key file path
    pub validator_key_path: Option<PathBuf>,
    /// Whether this node acts as a validator
    pub is_validator: bool,
    /// Maximum number of connected peers
    pub max_peers: usize,
    /// Network discovery settings
    pub discovery: DiscoveryConfig,
    /// Consensus settings
    pub consensus: ConsensusConfig,
    /// Development settings
    pub dev: DevConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Network discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable peer discovery
    pub enabled: bool,
    /// Bootstrap nodes to connect to
    pub bootstrap_nodes: Vec<String>,
    /// Discovery interval in seconds
    pub discovery_interval: u64,
}

/// Consensus configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Block time in milliseconds
    pub block_time_ms: u64,
    /// Epoch duration in milliseconds
    pub epoch_duration_ms: u64,
    /// Finality threshold (0.0 to 1.0)
    pub finality_threshold: f64,
    /// Number of shards
    pub shard_count: u32,
    /// Validators per shard
    pub validators_per_shard: u32,
}

/// Development configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevConfig {
    /// Enable automatic vote generation for finality
    pub auto_vote_enabled: bool,
    /// Generate real block hashes instead of dummy zeros
    pub generate_real_blocks: bool,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (error, warn, info, debug, trace)
    pub level: String,
    /// Log to file
    pub log_to_file: bool,
    /// Log file path
    pub log_file: Option<PathBuf>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: generate_node_id(),
            network_port: 30303,
            consensus_port: 30304,
            rpc_port: 8545,
            rpc_enabled: true,
            data_dir: PathBuf::from("./data"),
            validator_key_path: None,
            is_validator: false,
            max_peers: 50,
            discovery: DiscoveryConfig::default(),
            consensus: ConsensusConfig::default(),
            dev: DevConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl NodeConfig {
    /// Create testnet validator configuration
    #[allow(dead_code)]
    pub fn testnet_validator(node_number: u16) -> Self {
        let mut config = Self::default();
        config.node_id = format!("testnet-validator-{:03}", node_number);
        config.network_port = 30303 + node_number;
        config.consensus_port = 30404 + node_number;
        config.rpc_port = 8545 + node_number;
        config.is_validator = true;
        config.max_peers = 25; // More peers for testnet
        config.discovery = DiscoveryConfig::testnet();
        config.data_dir = PathBuf::from(format!("./data/validator-{}", node_number));
        config
    }

    /// Create testnet full node configuration
    #[allow(dead_code)]
    pub fn testnet_fullnode(node_number: u16) -> Self {
        let mut config = Self::default();
        config.node_id = format!("testnet-fullnode-{:03}", node_number);
        config.network_port = 30403 + node_number;
        config.consensus_port = 30504 + node_number;
        config.rpc_port = 8645 + node_number;
        config.is_validator = false;
        config.max_peers = 50;
        config.discovery = DiscoveryConfig::testnet();
        config.data_dir = PathBuf::from(format!("./data/fullnode-{}", node_number));
        config
    }

    /// Create bootstrap node configuration
    #[allow(dead_code)]
    pub fn testnet_bootstrap(node_number: u16) -> Self {
        let mut config = Self::default();
        config.node_id = format!("testnet-bootstrap-{:03}", node_number);
        config.network_port = 30303 + node_number;
        config.consensus_port = 30304 + node_number;
        config.rpc_port = 8545 + node_number;
        config.is_validator = false;
        config.max_peers = 100; // Bootstrap nodes need more connections
        config.discovery = DiscoveryConfig {
            enabled: true,
            bootstrap_nodes: vec![], // Bootstrap nodes don't need other bootstrap nodes
            discovery_interval: 5,   // Very frequent discovery
        };
        config.data_dir = PathBuf::from(format!("./data/bootstrap-{}", node_number));
        config
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bootstrap_nodes: vec![],
            discovery_interval: 30,
        }
    }
}

impl DiscoveryConfig {
    /// Create testnet discovery config with bootstrap nodes
    #[allow(dead_code)]
    pub fn testnet() -> Self {
        Self {
            enabled: true,
            bootstrap_nodes: vec![
                "127.0.0.1:30303".to_string(), // Bootstrap node 1
                "127.0.0.1:30304".to_string(), // Bootstrap node 2
                "127.0.0.1:30305".to_string(), // Bootstrap node 3
            ],
            discovery_interval: 10, // More frequent discovery for testnet
        }
    }

    /// Create mainnet discovery config
    #[allow(dead_code)]
    pub fn mainnet() -> Self {
        Self {
            enabled: true,
            bootstrap_nodes: vec![
                // TODO: Add real mainnet bootstrap nodes
                "seed1.avo-protocol.network:30303".to_string(),
                "seed2.avo-protocol.network:30303".to_string(),
                "seed3.avo-protocol.network:30303".to_string(),
            ],
            discovery_interval: 60,
        }
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            block_time_ms: 1000,
            epoch_duration_ms: 30000,
            finality_threshold: 0.67,
            shard_count: 4,
            validators_per_shard: 8,
        }
    }
}

impl Default for DevConfig {
    fn default() -> Self {
        Self {
            auto_vote_enabled: true,
            generate_real_blocks: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            log_to_file: false,
            log_file: None,
        }
    }
}

/// Load configuration from file or return default with auto-initialization
pub fn load_config(config_path: Option<&str>) -> Result<NodeConfig, Box<dyn std::error::Error>> {
    let config = match config_path {
        Some(path) => {
            let config_content = std::fs::read_to_string(path)?;
            toml::from_str(&config_content)?
        }
        None => NodeConfig::default(),
    };

    // Auto-create config file if it doesn't exist
    auto_create_config_if_missing(&config)?;

    Ok(config)
}

/// Load default configuration with auto-initialization
pub fn load_default_config() -> Result<NodeConfig, Box<dyn std::error::Error>> {
    let config = NodeConfig::default();

    // Auto-create config file if it doesn't exist
    auto_create_config_if_missing(&config)?;

    Ok(config)
}

/// Generate a unique node ID
fn generate_node_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("avo-node-{}", timestamp)
}

/// Save configuration to file
pub fn save_config(config: &NodeConfig, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config_toml = toml::to_string_pretty(config)?;
    std::fs::write(path, config_toml)?;
    // Configuration saved
    Ok(())
}

/// Validate configuration
pub fn validate_config(config: &NodeConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Check port ranges
    if config.network_port < 1024 {
        // Check network port privileges
    }

    if config.rpc_port < 1024 {
        // Check RPC port privileges
    }

    // Check data directory
    if !config.data_dir.exists() {
        println!(
            "\x1b[33m[INFO]\x1b[0m Creating data directory: {:?}",
            config.data_dir
        );
        std::fs::create_dir_all(&config.data_dir)?;
    }

    // Validate validator configuration
    if config.is_validator && config.validator_key_path.is_none() {
        // Validator mode without key path
    }

    // Validate consensus parameters
    if config.consensus.finality_threshold < 0.5 || config.consensus.finality_threshold > 1.0 {
        return Err("Finality threshold must be between 0.5 and 1.0".into());
    }

    if config.consensus.shard_count == 0 {
        return Err("Shard count must be greater than 0".into());
    }

    // Configuration validated
    Ok(())
}

/// Automatically create configuration file if it doesn't exist
fn auto_create_config_if_missing(config: &NodeConfig) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = std::path::Path::new("config.toml");

    if !config_path.exists() {
        println!("\x1b[36m[AUTO-INIT]\x1b[0m Creating default configuration file...");

        // Create optimal configuration based on system capabilities
        let optimized_config = create_optimized_config_for_system(config);

        // Save configuration
        save_config(&optimized_config, "config.toml")?;

        println!("\x1b[32m[SUCCESS]\x1b[0m Configuration file created: config.toml");
        println!("\x1b[36m[INFO]\x1b[0m You can customize this file for your needs");

        // Create additional helpful files
        create_helpful_files()?;
    }

    Ok(())
}

/// Create optimized configuration based on system capabilities
fn create_optimized_config_for_system(base_config: &NodeConfig) -> NodeConfig {
    use std::thread;

    // Detect system capabilities
    let cpu_count = thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    let is_high_spec = cpu_count >= 8;

    let mut config = base_config.clone();

    // Optimize based on system specs
    if is_high_spec {
        // High-performance configuration
        config.max_peers = 100;
        config.consensus.shard_count = 8;
        config.consensus.validators_per_shard = 21;
        config.consensus.block_time_ms = 200;
    } else {
        // Resource-conservative configuration
        config.max_peers = 50;
        config.consensus.shard_count = 4;
        config.consensus.validators_per_shard = 8;
        config.consensus.block_time_ms = 500;
    }

    // Set intelligent data directory based on OS
    if cfg!(windows) {
        config.data_dir = std::path::PathBuf::from("./avo_data");
    } else if cfg!(target_os = "macos") {
        config.data_dir = std::path::PathBuf::from("./avo_data");
    } else {
        config.data_dir = std::path::PathBuf::from("./data");
    }

    println!(
        "\x1b[36m[AUTO-INIT]\x1b[0m Optimized for {} CPU cores",
        cpu_count
    );
    println!(
        "\x1b[36m[AUTO-INIT]\x1b[0m Configuration: {} shards, {} max peers",
        config.consensus.shard_count, config.max_peers
    );

    config
}

/// Create helpful files for users
fn create_helpful_files() -> Result<(), Box<dyn std::error::Error>> {
    // Create README for first-time users
    let readme_path = "GETTING_STARTED.md";
    if !std::path::Path::new(readme_path).exists() {
        let readme_content = r#"# AVO Protocol - Getting Started

Welcome to AVO Protocol! 🚀

## Quick Start

1. **Start the node:**
   ```bash
   avo-node start
   ```

2. **Check status:**
   ```bash
   avo-cli network status
   ```

3. **Create a wallet:**
   ```bash
   avo-cli wallet create --name my-wallet
   ```

## Configuration

Your node is automatically configured in `config.toml`.
Data is stored in the `./data/` directory.

## Support

- Documentation: docs/
- CLI Help: `avo-cli --help`
- Node Help: `avo-node --help`

Happy blockchain building! 🎉
"#;

        std::fs::write(readme_path, readme_content)?;
        println!(
            "\x1b[32m[SUCCESS]\x1b[0m Created getting started guide: {}",
            readme_path
        );
    }

    // Create start script for Windows
    if cfg!(windows) {
        let script_path = "start_avo.bat";
        if !std::path::Path::new(script_path).exists() {
            let script_content = r#"@echo off
echo Starting AVO Protocol Node...
echo.
avo-node.exe start
pause
"#;
            std::fs::write(script_path, script_content)?;
            println!(
                "\x1b[32m[SUCCESS]\x1b[0m Created start script: {}",
                script_path
            );
        }
    }

    // Create start script for Unix systems
    if cfg!(unix) {
        let script_path = "start_avo.sh";
        if !std::path::Path::new(script_path).exists() {
            let script_content = r#"#!/bin/bash
echo "Starting AVO Protocol Node..."
echo
./avo-node start
"#;
            std::fs::write(script_path, script_content)?;

            // Make script executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(script_path)?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(script_path, perms)?;
            }

            println!(
                "\x1b[32m[SUCCESS]\x1b[0m Created start script: {}",
                script_path
            );
        }
    }

    Ok(())
}
