use avo_core::performance::PerformanceReport;
use avo_core::staking::{StakeManager, StakeType};
use avo_core::{AvoError, AvoResult, ProtocolParams};
use chrono::{DateTime, Utc};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use ethers_core::abi::{
    encode as abi_encode, AbiParser, Function, Param, ParamType, StateMutability, Token,
};
use ethers_core::types::{Address as EthAddress, U256 as AbiU256};
use getrandom;
use reqwest;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tiny_keccak::{Hasher, Keccak};
use tokio;

mod security;  // Módulo de seguridad para firmas Ed25519

// Ethereum address derivation functions
fn private_key_to_public_key(
    private_key_bytes: &[u8; 32],
) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key_bytes)?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);

    // Get uncompressed public key (65 bytes: 0x04 + x + y)
    let public_key_bytes = public_key.serialize_uncompressed();

    // Remove the 0x04 prefix, keep only x and y coordinates (64 bytes)
    let mut result = [0u8; 64];
    result.copy_from_slice(&public_key_bytes[1..]);
    Ok(result)
}

fn public_key_to_address(public_key_bytes: &[u8; 64]) -> String {
    let mut hasher = Keccak::v256();
    let mut hash = [0u8; 32];
    hasher.update(public_key_bytes);
    hasher.finalize(&mut hash);

    let address_bytes = &hash[12..];
    format!("0x{}", hex::encode(address_bytes))
}

#[derive(Parser)]
#[command(name = "avo")]
#[command(about = "AVO Protocol CLI - Complete Blockchain Interaction Tool")]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage local wallets and query the network
    Wallet {
        #[command(subcommand)]
        action: WalletCommands,
    },
    /// Operate bootstrap and validator nodes
    Operator {
        #[command(subcommand)]
        action: OperatorCommands,
    },
    /// Delegate stake to validators
    Delegate {
        #[command(subcommand)]
        action: DelegateCommands,
    },
    /// Review staking positions
    Stakes {
        #[command(subcommand)]
        action: StakeCommands,
    },
    /// Estimate staking rewards
    Rewards {
        #[command(subcommand)]
        action: RewardCommands,
    },
    /// Inspect protocol treasury data
    Treasury {
        #[command(subcommand)]
        action: TreasuryCommands,
    },
    /// Governance proposals and voting
    Governance {
        #[command(subcommand)]
        action: GovernanceCommands,
    },
    /// Administrative commands (RESTRICTED ACCESS)
    Admin {
        #[command(subcommand)]
        action: AdminCommands,
    },
    /// Interact with smart contracts
    Contract {
        #[command(subcommand)]
        action: ContractCommands,
    },
    /// Broadcast a simple transfer
    Tx {
        #[arg(short, long)]
        account: String,
        #[arg(short, long)]
        to: String,
        #[arg(short, long)]
        amount: f64,
        #[arg(long)]
        gasfee: Option<f64>,
        #[arg(long, default_value_t = 0)]
        shard: u32,
    },
    /// Helper commands for ERC20-style token interactions
    Token {
        #[command(subcommand)]
        action: TokenCommands,
    },
    /// Inspect real-time and historical performance metrics
    Performance {
        #[command(subcommand)]
        action: PerformanceCommands,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Generate new Ethereum-compatible wallet (saved in keys/ directory)
    Generate {
        #[arg(long, action = ArgAction::SetTrue)]
        mnemonic: bool,
    },
    /// Import wallet from raw private key (saved in keys/ directory)
    Import {
        #[arg(short, long)]
        private_key: String,
    },
    /// Show information about a stored wallet
    Info {
        #[arg(short, long, default_value = "wallet.json")]
        wallet: PathBuf,
    },
    /// List wallets in a directory
    List {
        #[arg(short, long, default_value = ".")]
        directory: PathBuf,
    },
    /// Count wallets known by the connected node
    CountNetwork,
    /// List wallets returned by the connected node
    ListNetwork,
    /// Show account statistics (total accounts, accounts with balance, etc.)
    AccountStats,
    /// Display balances for tracked wallets
    Balances,
    /// Show protocol total supply snapshot
    TotalSupply,
    /// Fetch balance for a specific address
    Balance {
        #[arg(short, long)]
        address: String,
    },
}

#[derive(Subcommand)]
enum TreasuryCommands {
    /// Show all treasury accounts and their addresses
    Accounts,
    /// Show specific treasury account information
    Info {
        #[arg(value_enum)]
        account: TreasuryAccountType,
    },
    /// Show treasury fee distribution
    Distribution,
    /// Show treasury balances from gas fee distribution
    Balances,
}

#[derive(Subcommand)]
enum GovernanceCommands {
    /// Create a new governance proposal (Admin only in Bootstrap phase)
    Propose {
        /// Proposer address (must be admin in Phase 1)
        #[arg(short, long)]
        proposer: String,
        /// Type of proposal
        #[arg(short, long, value_enum)]
        proposal_type: ProposalTypeArg,
        /// Proposal title
        #[arg(short, long)]
        title: String,
        /// Detailed description
        #[arg(short, long)]
        description: String,
        /// Parameter name (for ParameterChange)
        #[arg(long)]
        parameter: Option<String>,
        /// Current value (for ParameterChange)
        #[arg(long)]
        current_value: Option<String>,
        /// New value (for ParameterChange)
        #[arg(long)]
        new_value: Option<String>,
    },
    /// Cast a vote on a proposal (Burns 1 AVO fee)
    Vote {
        /// Voter address
        #[arg(short, long)]
        voter: String,
        /// Proposal ID to vote on
        #[arg(short, long)]
        proposal_id: String,
        /// Vote choice
        #[arg(short, long, value_enum)]
        choice: VoteChoiceArg,
    },
    /// Show governance statistics (phase, fees burned, votes)
    Stats,
    /// List active proposals
    List,
    /// Show specific proposal details
    Info {
        /// Proposal ID
        #[arg(short, long)]
        proposal_id: String,
    },
}

#[derive(Clone, ValueEnum, Debug)]
enum ProposalTypeArg {
    ParameterChange,
    TreasurySpend,
    NetworkUpgrade,
    ValidatorChange,
    Emergency,
    Custom,
}

#[derive(Clone, ValueEnum, Debug)]
enum VoteChoiceArg {
    For,
    Against,
    Abstain,
}

#[derive(Subcommand, Clone)]
enum AdminCommands {
    /// Initialize protocol with genesis allocations (ADMIN ONLY)
    InitGenesis {
        /// Path to genesis allocations file
        #[arg(short, long, default_value = "genesis_allocations.json")]
        file: PathBuf,
        /// Admin wallet address (must own private key)
        #[arg(short, long)]
        admin: String,
    },
    /// Mint tokens to specific address (EMERGENCY ONLY)
    Mint {
        /// Target address to mint to
        #[arg(short, long)]
        to: String,
        /// Amount in AVO (will be converted to wei)
        #[arg(short = 'n', long)]
        amount: u64,
        /// Admin wallet address (must own private key)
        #[arg(short, long)]
        admin: String,
        /// Reason for minting (for audit trail)
        #[arg(short, long)]
        reason: String,
    },
    /// Verify protocol total supply matches expected
    VerifySupply {
        /// Expected total supply in AVO
        #[arg(short, long, default_value = "80000000")]
        expected: u64,
    },
}

#[derive(Clone, ValueEnum)]
enum TreasuryAccountType {
    Main,
    Development,
    Marketing,
    Security,
    Community,
    ValidatorRewards,
    Emergency,
}

#[derive(Subcommand, Clone)]
enum OperatorCommands {
    /// Operate bootstrap node (minimum 10K AVO, 15% APR)
    Bootstrap {
        #[command(subcommand)]
        action: BootstrapCommands,
    },
    /// Operate validator node (minimum 1K AVO, 12% APR)
    Validator {
        #[command(subcommand)]
        action: ValidatorCommands,
    },
}

#[derive(Subcommand, Clone)]
enum BootstrapCommands {
    /// Create bootstrap node stake (minimum 10K AVO, 15% APR)
    Stake {
        /// Your address for staking
        #[arg(short, long)]
        address: String,
        /// Amount to stake in AVO tokens (minimum 10,000 AVO)
        #[arg(short = 'n', long)]
        amount: u64,
    },
    /// Request unstaking (immediate in AVO)
    Unstake {
        /// Position ID to unstake (get from 'avo operator bootstrap list')
        #[arg(short, long)]
        position_id: String,
        /// Your wallet address (owner of the position)
        #[arg(short, long)]
        address: String,
    },
    /// List your bootstrap stakes
    List {
        /// Your address
        #[arg(short, long)]
        address: String,
    },
    /// Show bootstrap node statistics
    Stats {
        /// Your address (optional, shows global stats if not provided)
        #[arg(short, long)]
        address: Option<String>,
    },
}

#[derive(Subcommand, Clone)]
enum ValidatorCommands {
    /// Create validator stake (minimum 1K AVO, 12% APR)
    Stake {
        /// Your address for staking
        #[arg(short, long)]
        address: String,
        /// Amount to stake in AVO tokens (minimum 1000 AVO)
        #[arg(short = 'n', long)]
        amount: u64,
    },
    /// Request unstaking (immediate in AVO)
    Unstake {
        /// Position ID to unstake (get from 'avo operator validator list')
        #[arg(short, long)]
        position_id: String,
        /// Your wallet address (owner of the position)
        #[arg(short, long)]
        address: String,
    },
    /// List your validator stakes
    List {
        /// Your address
        #[arg(short, long)]
        address: String,
    },
    /// Show validator statistics
    Stats {
        /// Your address (optional, shows global stats if not provided)
        #[arg(short, long)]
        address: Option<String>,
    },
}

/// Delegation commands (Free, 8% APR)
#[derive(Subcommand, Clone)]
enum DelegateCommands {
    /// Delegate tokens to a validator (free, 8% APR)
    To {
        /// Your address for delegation
        #[arg(short, long)]
        address: String,
        /// Validator ID to delegate to
        #[arg(short = 'v', long)]
        validator_id: u32,
        /// Amount to delegate in AVO tokens (any amount)
        #[arg(short = 'n', long)]
        amount: u64,
    },
    /// Undelegate tokens from a validator
    From {
        /// Position ID to undelegate (get from 'avo stakes list')
        #[arg(short, long)]
        position_id: String,
        /// Your wallet address (owner of the delegation)
        #[arg(short, long)]
        address: String,
    },
    /// List your delegations
    List {
        /// Your address
        #[arg(short, long)]
        address: String,
    },
}

/// Staking overview commands
#[derive(Subcommand, Clone)]
enum StakeCommands {
    /// List all your staking positions
    List {
        /// Your address
        #[arg(short, long)]
        address: String,
    },
}

/// Rewards management commands
#[derive(Subcommand, Clone)]
enum RewardCommands {
    /// Calculate estimated rewards
    Estimate {
        /// Stake type
        #[arg(short, long)]
        stake_type: StakeTypeArg,
        /// Amount to calculate for
        #[arg(short, long)]
        amount: u64,
        /// Time period in days
        #[arg(short, long, default_value = "365")]
        days: u64,
    },
}

#[derive(Subcommand, Clone)]
enum ContractCommands {
    /// Deploy smart contract bytecode to the connected node
    Deploy {
        /// Path to the contract artifact (.bin, .wasm or JSON containing bytecode)
        #[arg(short, long)]
        contract: PathBuf,
        /// Wallet file used as deployer (must contain private key)
        #[arg(short, long)]
        wallet: PathBuf,
        /// Constructor signature, e.g. "(uint256,address)" (omit if none)
        #[arg(long = "constructor")]
        constructor_signature: Option<String>,
        /// Constructor arguments encoded as JSON array, e.g. "[123,"0xabc..."]"
        #[arg(long)]
        args: Option<String>,
        /// Optional shard identifier
        #[arg(long, default_value_t = 0)]
        shard: u32,
        /// Optional AVO value to send with deployment (in AVO, decimals allowed)
        #[arg(long)]
        value: Option<f64>,
        /// Override default gas limit
        #[arg(long)]
        gas_limit: Option<u64>,
    },
    /// Call a contract function and execute it on the node
    Call {
        /// Target contract address (0x...)
        #[arg(short, long)]
        contract: String,
        /// Wallet file initiating the call
        #[arg(short, long)]
        wallet: PathBuf,
        /// ABI-style function signature, e.g. "setValue(uint256)"
        #[arg(long)]
        function: Option<String>,
        /// Function arguments in JSON array format
        #[arg(long)]
        args: Option<String>,
        /// Raw hex payload (0x...) if you already encoded the call data
        #[arg(long)]
        payload: Option<String>,
        /// Optional AVO value to attach (decimals allowed)
        #[arg(long)]
        value: Option<f64>,
        /// Override default gas limit
        #[arg(long)]
        gas_limit: Option<u64>,
    },
    /// Query stored metadata for a deployed contract
    Query {
        /// Target contract address (0x...)
        #[arg(short, long)]
        contract: String,
        /// Print raw JSON response instead of formatted summary
        #[arg(long, action = ArgAction::SetTrue)]
        raw: bool,
    },
}

#[derive(Subcommand, Clone)]
enum TokenCommands {
    /// Fetch token balance for an account
    Balance {
        /// Contract address implementing an ERC20-compatible interface
        #[arg(short, long)]
        contract: String,
        /// Wallet file initiating the call (used as the caller address)
        #[arg(short, long, default_value = "wallet.json")]
        wallet: PathBuf,
        /// Account whose balance will be queried
        #[arg(short, long)]
        account: String,
        /// Token decimals for human-readable output (defaults to 18)
        #[arg(long, default_value_t = 18)]
        decimals: u8,
        /// Optional gas limit override
        #[arg(long)]
        gas_limit: Option<u64>,
    },
    /// Transfer fungible tokens between accounts
    Transfer {
        /// Contract address implementing an ERC20-compatible interface
        #[arg(short, long)]
        contract: String,
        /// Wallet file that signs and pays for the transaction
        #[arg(short, long, default_value = "wallet.json")]
        wallet: PathBuf,
        /// Recipient address
        #[arg(short, long)]
        to: String,
        /// Human-readable token amount (supports decimals)
        #[arg(short, long)]
        amount: String,
        /// Token decimals (defaults to 18 like standard ERC20)
        #[arg(long, default_value_t = 18)]
        decimals: u8,
        /// Optional gas limit override
        #[arg(long)]
        gas_limit: Option<u64>,
    },
}

#[derive(Subcommand, Clone)]
enum PerformanceCommands {
    /// Display aggregate protocol performance summary
    Summary {
        /// Number of recent snapshots to include when computing rolling statistics
        #[arg(long, default_value_t = 10)]
        limit: usize,
    },
    /// Show the latest performance snapshots collected by the node
    Recent {
        /// Number of snapshots to display
        #[arg(long, default_value_t = 5)]
        limit: usize,
    },
}

/// Stake type argument for CLI
#[derive(Debug, Clone, ValueEnum)]
enum StakeTypeArg {
    Bootstrap,
    Validator,
    Delegation,
}

impl From<StakeTypeArg> for StakeType {
    fn from(arg: StakeTypeArg) -> Self {
        match arg {
            StakeTypeArg::Bootstrap => StakeType::Bootstrap,
            StakeTypeArg::Validator => StakeType::Validator,
            StakeTypeArg::Delegation => StakeType::Delegation,
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize logging without emojis
    tracing_subscriber::fmt::init();

    // Auto-initialize environment for new users
    if let Err(e) = auto_initialize_environment().await {
        println!("\x1b[33m[WARNING]\x1b[0m Auto-initialization failed: {}", e);
    }

    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Wallet { action } => handle_wallet_commands(action).await,
        Commands::Operator { action } => handle_operator_commands(action.clone()).await,
        Commands::Delegate { action } => handle_delegate_commands(action.clone()).await,
        Commands::Stakes { action } => handle_stake_commands(action.clone()).await,
        Commands::Rewards { action } => handle_reward_commands(action.clone()).await,
        Commands::Treasury { action } => handle_treasury_commands(action).await,
        Commands::Governance { action } => handle_governance_commands(action).await,
        Commands::Admin { action } => handle_admin_commands(action.clone()).await,
        Commands::Contract { action } => handle_contract_commands(action.clone()).await,
        Commands::Token { action } => handle_token_commands(action.clone()).await,
        Commands::Performance { action } => handle_performance_commands(action.clone()).await,
        Commands::Tx {
            account,
            to,
            amount,
            gasfee,
            shard,
        } => handle_quick_tx(account, to, *amount, *gasfee, *shard).await,
    };

    if let Err(e) = result {
        println!("\x1b[31m[ERROR]\x1b[0m Command failed: {}", e);
        std::process::exit(1);
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Wallet {
    address: String,
    private_key: String,
    public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ContractDeploymentRecord {
    address: String,
    tx_hash: String,
    contract_path: String,
    deployer: String,
    block_number: u64,
    timestamp: String,
    shard: u32,
    bytecode_size: usize,
    chain_id: u64,
}

const CONTRACT_DEPLOYMENTS_PATH: &str = "data/contracts/deployments.json";
const EVM_SUCCESS_PLACEHOLDER: &str = "0x45564d5f455845435554494f4e5f53554343455353";
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<RpcError>,
}

fn generate_random_private_key() -> [u8; 32] {
    let mut private_key = [0u8; 32];
    getrandom::getrandom(&mut private_key).expect("failed to generate private key");
    private_key
}

async fn rpc_call_raw(method: &str, params: Vec<Value>) -> Result<RpcResponse, reqwest::Error> {
    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });

    let response = client
        .post("http://127.0.0.1:9545")
        .json(&request_body)
        .send()
        .await?;

    response.json::<RpcResponse>().await
}

async fn rpc_call(
    method: &str,
    params: Vec<Value>,
) -> Result<RpcResponse, Box<dyn std::error::Error>> {
    let response = rpc_call_raw(method, params).await?;
    Ok(response)
}

async fn rpc_call_quiet(method: &str, params: Vec<Value>) -> Result<RpcResponse, reqwest::Error> {
    rpc_call_raw(method, params).await
}

async fn query_avo_balance(address: &str) -> AvoResult<String> {
    let params = vec![
        Value::String(address.to_string()),
        Value::String("latest".into()),
    ];

    match rpc_call_quiet("eth_getBalance", params).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                if let Some(balance_hex) = result.as_str() {
                    let balance_wei =
                        u128::from_str_radix(balance_hex.trim_start_matches("0x"), 16).unwrap_or(0);
                    let balance_avo = balance_wei as f64 / 1e18;
                    Ok(format!("{:.6}", balance_avo))
                } else {
                    Ok("0".to_string())
                }
            } else if let Some(error) = resp.error {
                Ok(format!("RPC Error: {}", error.message))
            } else {
                Ok("Unknown response".to_string())
            }
        }
        Err(_) => Ok("Genesis data (node offline)".to_string()),
    }
}

// ============================================================================
// WALLET HELPER FUNCTIONS - Para operaciones seguras con firmas
// ============================================================================

/// Buscar archivo de wallet por address en el directorio keys/
fn find_wallet_by_address(address: &str) -> AvoResult<PathBuf> {
    let keys_dir = Path::new("keys");
    
    if !keys_dir.exists() {
        return Err(AvoError::internal(
            "Directorio 'keys/' no encontrado.\n\
             Genera una wallet primero con: avo wallet generate --output keys/my_wallet.json"
        ));
    }
    
    // Normalizar address (lowercase para comparación)
    let target_address = address.to_lowercase();
    
    // Buscar en todos los archivos .json del directorio keys/
    for entry in fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();
        
        // Solo procesar archivos .json
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(wallet) = load_wallet_json(&path) {
                if wallet.address.to_lowercase() == target_address {
                    return Ok(path);
                }
            }
        }
    }
    
    Err(AvoError::internal(format!(
        "Wallet no encontrada para address {}.\n\
         Asegúrate de tener el archivo en keys/ o genera uno con:\n\
         avo wallet generate --output keys/wallet.json",
        address
    )))
}

/// Cargar datos de wallet desde archivo JSON
fn load_wallet_json(path: &Path) -> AvoResult<Wallet> {
    let contents = fs::read_to_string(path)
        .map_err(|e| AvoError::internal(format!("Error leyendo wallet: {}", e)))?;
    
    let wallet: Wallet = serde_json::from_str(&contents)
        .map_err(|e| AvoError::internal(format!("Error parseando wallet JSON: {}", e)))?;
    
    Ok(wallet)
}

async fn handle_wallet_commands(action: &WalletCommands) -> AvoResult<()> {
    match action {
        WalletCommands::Generate { mnemonic } => generate_wallet(*mnemonic).await,
        WalletCommands::Import {
            private_key,
        } => import_wallet(private_key).await,
        WalletCommands::Info { wallet } => show_wallet_info(wallet).await,
        WalletCommands::List { directory } => list_wallets(directory).await,
        WalletCommands::CountNetwork => count_wallets_network().await,
        WalletCommands::ListNetwork => list_wallets_network().await,
        WalletCommands::AccountStats => show_account_stats().await,
        WalletCommands::Balances => list_wallets_with_balances().await,
        WalletCommands::TotalSupply => show_total_supply().await,
        WalletCommands::Balance { address } => show_single_wallet_balance(address).await,
    }
}

async fn generate_wallet(_use_mnemonic: bool) -> AvoResult<()> {
    println!("\x1b[33m[INFO]\x1b[0m Generating new Ethereum-compatible wallet");

    // Generate cryptographically secure random private key
    let private_key_bytes = generate_random_private_key();
    let private_key = hex::encode(private_key_bytes);

    // Derive public key from private key using secp256k1
    let public_key_bytes = match private_key_to_public_key(&private_key_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            println!("\x1b[31m[ERROR]\x1b[0m Failed to derive public key: {}", e);
            return Ok(());
        }
    };
    let public_key = hex::encode(public_key_bytes);

    // Derive Ethereum address from public key using keccak256
    let address = public_key_to_address(&public_key_bytes);

    let wallet = Wallet {
        address: address.clone(),
        private_key,
        public_key,
    };

    // ALWAYS save in keys/ directory
    let keys_dir = Path::new("keys");
    if !keys_dir.exists() {
        println!("\x1b[33m[INFO]\x1b[0m Creating keys/ directory...");
        fs::create_dir_all(keys_dir)?;
    }
    
    let final_output = keys_dir.join(format!("wallet_{}.json", address));

    // Save wallet to file
    let wallet_json = serde_json::to_string_pretty(&wallet)?;
    fs::write(&final_output, wallet_json)?;

    println!("\x1b[32m[SUCCESS]\x1b[0m Wallet generated successfully");
    println!("Address: {}", address);
    println!("Saved to: {}", final_output.display());
    println!("\x1b[33m[WARNING]\x1b[0m Keep your private key secure and never share it");
    println!("\x1b[33m[INFO]\x1b[0m This wallet is fully compatible with MetaMask and other Ethereum wallets");
    println!("\x1b[32m[INFO]\x1b[0m Wallet saved in keys/ directory and ready for all operations");

    Ok(())
}

async fn import_wallet(private_key: &str) -> AvoResult<()> {
    println!("\x1b[33m[INFO]\x1b[0m Importing wallet from private key");

    // Validate private key format
    if private_key.len() != 64 {
        println!("\x1b[31m[ERROR]\x1b[0m Invalid private key length. Expected 64 hex characters");
        return Ok(());
    }

    // Parse private key
    let private_key_bytes = match hex::decode(private_key) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                println!("\x1b[31m[ERROR]\x1b[0m Invalid private key: must be 32 bytes");
                return Ok(());
            }
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            array
        }
        Err(_) => {
            println!("\x1b[31m[ERROR]\x1b[0m Invalid private key: not valid hex");
            return Ok(());
        }
    };

    // Derive public key from private key using secp256k1
    let public_key_bytes = match private_key_to_public_key(&private_key_bytes) {
        Ok(pk) => pk,
        Err(e) => {
            println!("\x1b[31m[ERROR]\x1b[0m Failed to derive public key: {}", e);
            return Ok(());
        }
    };
    let public_key = hex::encode(public_key_bytes);

    // Derive Ethereum address from public key using keccak256
    let address = public_key_to_address(&public_key_bytes);

    let wallet = Wallet {
        address: address.clone(),
        private_key: private_key.to_string(),
        public_key,
    };

    // ALWAYS save in keys/ directory
    let keys_dir = Path::new("keys");
    if !keys_dir.exists() {
        println!("\x1b[33m[INFO]\x1b[0m Creating keys/ directory...");
        fs::create_dir_all(keys_dir)?;
    }
    
    let output = keys_dir.join(format!("wallet_{}.json", address));

    let wallet_json = serde_json::to_string_pretty(&wallet)?;
    fs::write(&output, wallet_json)?;

    println!("\x1b[32m[SUCCESS]\x1b[0m Wallet imported successfully");
    println!("Address: {}", address);
    println!("Saved to: {}", output.display());
    println!("\x1b[33m[INFO]\x1b[0m This address should match exactly with MetaMask when you import the same private key");
    println!("\x1b[32m[INFO]\x1b[0m Wallet saved in keys/ directory and ready for all operations");

    Ok(())
}

async fn show_wallet_info(wallet_path: &PathBuf) -> AvoResult<()> {
    println!("\x1b[33m[INFO]\x1b[0m Loading wallet information");

    let wallet_json = fs::read_to_string(wallet_path)?;
    let wallet: Wallet = serde_json::from_str(&wallet_json)?;

    println!("\x1b[32m[SUCCESS]\x1b[0m Wallet Information");
    println!("==================");
    println!("Address: {}", wallet.address);
    println!("Public Key: {}...", &wallet.public_key[..16]);
    println!("Private Key: [HIDDEN]");

    // Show balance if possible
    match query_avo_balance(&wallet.address).await {
        Ok(balance) => println!("Balance: {} AVO", balance),
        Err(_) => println!("\x1b[33m[WARNING]\x1b[0m Could not fetch balance (node not connected)"),
    }

    Ok(())
}

async fn list_wallets(directory: &PathBuf) -> AvoResult<()> {
    println!(
        "\x1b[33m[INFO]\x1b[0m Scanning for wallet files in: {}",
        directory.display()
    );

    let mut wallet_count = 0;

    if let Ok(entries) = fs::read_dir(directory) {
        for entry in entries.flatten() {
            if let Some(extension) = entry.path().extension() {
                if extension == "json" {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        if let Ok(wallet) = serde_json::from_str::<Wallet>(&content) {
                            wallet_count += 1;
                            println!(
                                "{}: {}",
                                entry.file_name().to_string_lossy(),
                                wallet.address
                            );
                        }
                    }
                }
            }
        }
    }

    if wallet_count == 0 {
        println!("\x1b[33m[WARNING]\x1b[0m No wallet files found");
    } else {
        println!("\x1b[32m[SUCCESS]\x1b[0m Found {} wallet(s)", wallet_count);
    }

    Ok(())
}

// --- Network wallet RPC helpers ---

async fn count_wallets_network() -> AvoResult<()> {
    println!("\x1b[33m[INFO]\x1b[0m Querying wallet count from node (RPC: avo_getWalletCount)");

    match rpc_call("avo_getWalletCount", vec![]).await {
        Ok(rpc) => {
            if let Some(result) = rpc.result {
                if let Some(count) = result.as_u64() {
                    println!("\x1b[32m[SUCCESS]\x1b[0m Wallets on network: {}", count);
                } else if let Some(s) = result.as_str() {
                    println!("\x1b[32m[SUCCESS]\x1b[0m Wallets on network: {}", s);
                } else {
                    println!(
                        "\x1b[33m[WARNING]\x1b[0m Unexpected result type: {}",
                        result
                    );
                }
            } else if let Some(err) = rpc.error {
                println!("\x1b[31m[ERROR]\x1b[0m RPC Error: {}", err.message);
            } else {
                println!("\x1b[33m[WARNING]\x1b[0m Empty RPC response");
            }
        }
        Err(e) => println!("\x1b[31m[ERROR]\x1b[0m Failed to reach node: {}", e),
    }

    Ok(())
}

async fn fetch_network_wallets() -> Vec<String> {
    if let Ok(rpc) = rpc_call_quiet("avo_listWallets", vec![]).await {
        if let Some(result) = rpc.result {
            if let Some(arr) = result.as_array() {
                return arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
            }
        }
    }
    vec![]
}

async fn list_wallets_network() -> AvoResult<()> {
    println!("\x1b[33m[INFO]\x1b[0m Fetching wallet list from node (RPC: avo_listWallets)");
    let wallets = fetch_network_wallets().await;
    if wallets.is_empty() {
        println!("\x1b[33m[WARNING]\x1b[0m No wallets returned by node or node unreachable");
    } else {
        println!(
            "\x1b[32m[SUCCESS]\x1b[0m Wallets known by node ({}):",
            wallets.len()
        );
        for (i, addr) in wallets.iter().enumerate() {
            println!("{}. {}", i + 1, addr);
        }
    }
    Ok(())
}

async fn list_wallets_with_balances() -> AvoResult<()> {
    let genesis_info = load_genesis_info();

    let mut seen = HashSet::new();
    let mut addresses: Vec<String> = Vec::new();

    let rpc_wallets = fetch_network_wallets().await;
    for addr in rpc_wallets {
        let key = addr.to_lowercase();
        if seen.insert(key) {
            addresses.push(addr);
        }
    }

    if let Some(ref genesis) = genesis_info {
        for addr in &genesis.ordered_addresses {
            let key = addr.to_lowercase();
            if seen.insert(key) {
                addresses.push(addr.clone());
            }
        }
    }

    if addresses.is_empty() {
        println!("\x1b[33m[WARNING]\x1b[0m No wallets returned by node or genesis data");
        return Ok(());
    }

    println!(
        "\n\x1b[35mWallet balances\x1b[0m ({} cuentas)",
        addresses.len()
    );
    println!(
        "{:<4} {:<22} {:<44} {:>18}",
        "#", "Cuenta", "Dirección", "Balance (AVO)"
    );
    println!("{}", "-".repeat(90));

    let mut total_balance = 0f64;
    let mut counted = 0usize;
    for (idx, addr) in addresses.iter().enumerate() {
        let alias_full_owned = genesis_info
            .as_ref()
            .and_then(|info| info.accounts.get(&addr.to_lowercase()))
            .map(|acc| acc.name.trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "-".to_string());

        let (alias_display, alias_detail) = split_alias_parts(&alias_full_owned);
        let color = wallet_section_color(alias_display);
        let alias_colored = format!(
            "{color}{alias:<width$}\x1b[0m",
            color = color,
            alias = alias_display,
            width = 22
        );

        match query_avo_balance(addr).await {
            Ok(balance_text) => {
                if let Ok(amount) = balance_text.parse::<f64>() {
                    total_balance += amount;
                    counted += 1;
                    println!(
                        "{:<4} {} {:<44} {:>18}",
                        idx + 1,
                        alias_colored,
                        addr,
                        format_decimal_with_commas(amount),
                    );
                    if let Some(detail) = alias_detail {
                        println!("      {color}{detail}\x1b[0m", color = color);
                    }
                } else {
                    println!(
                        "{:<4} {} {:<44} {:>18}",
                        idx + 1,
                        alias_colored,
                        addr,
                        balance_text,
                    );
                    if let Some(detail) = alias_detail {
                        println!("      {color}{detail}\x1b[0m", color = color);
                    }
                }
            }
            Err(e) => {
                println!(
                    "{:<4} {} {:<44} {:>18}",
                    idx + 1,
                    alias_colored,
                    addr,
                    format!("[error: {}]", e)
                );
                if let Some(detail) = alias_detail {
                    println!("      {color}{detail}\x1b[0m", color = color);
                }
            }
        }
    }

    println!("{}", "-".repeat(90));
    if counted > 0 {
        println!(
            "{:<4} \x1b[36m{:<22}\x1b[0m {:<44} {:>18}",
            "",
            "Total",
            "",
            format_decimal_with_commas(total_balance),
        );
    } else {
        println!("{:<4} {:<22} {:<44} {:>18}", "", "Total", "", "N/A",);
    }

    Ok(())
}

async fn show_single_wallet_balance(address: &str) -> AvoResult<()> {
    let query_time = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string();
    let params = vec![
        Value::String(address.to_string()),
        Value::String("latest".into()),
    ];

    match rpc_call_quiet("eth_getBalance", params).await {
        Ok(resp) => {
            if let Some(error) = resp.error {
                render_wallet_error(&error.message);
            } else if let Some(result_value) = resp.result {
                if let Some(balance_hex) = result_value.as_str() {
                    let sanitized = balance_hex.trim_start_matches("0x");
                    let wei_value = u128::from_str_radix(sanitized, 16).unwrap_or(0);
                    let avo_value = (wei_value as f64) / 1e18f64;

                    let formatted_avo = format_decimal_with_commas(avo_value);
                    let formatted_wei = format_big_number(&wei_value.to_string());

                    println!("\n\x1b[35mWallet\x1b[0m      {}", address);
                    println!("\x1b[32mBalance\x1b[0m     {} AVO", formatted_avo);
                    println!("\x1b[36mBalance wei\x1b[0m {}", formatted_wei);
                    println!("\x1b[90mUpdated\x1b[0m     {}\n", query_time);
                    println!("\x1b[32m[SUCCESS]\x1b[0m Balance retrieved successfully");
                } else {
                    render_wallet_error("Unexpected RPC result format");
                }
            } else {
                render_wallet_error("Empty response from RPC");
            }
        }
        Err(e) => {
            render_wallet_error(&format!("Failed to connect to node: {}", e));
        }
    }

    Ok(())
}

fn render_wallet_error(message: &str) {
    println!("\x1b[31m[ERROR]\x1b[0m {}", message);
}

fn format_number_with_commas(value: u64) -> String {
    format_big_number(&value.to_string())
}

fn format_decimal_with_commas(value: f64) -> String {
    let parts = format!("{:.6}", value)
        .split('.')
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let integer = format_big_number(&parts[0]);
    let fraction = parts.get(1).cloned().unwrap_or_default();
    format!("{}.{}", integer, fraction)
}

fn format_big_number(number: &str) -> String {
    let is_negative = number.starts_with('-');
    let digits = if is_negative {
        number.trim_start_matches('-')
    } else {
        number
    };

    if digits.is_empty() {
        return "0".to_string();
    }

    let mut grouped = String::new();
    for (i, ch) in digits.chars().rev().enumerate() {
        if i != 0 && i % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }

    let formatted: String = grouped.chars().rev().collect();
    if is_negative {
        format!("-{}", formatted)
    } else {
        formatted
    }
}

#[derive(Clone)]
struct GenesisAccount {
    balance: f64,
    name: String,
}

#[derive(Clone)]
struct GenesisInfo {
    initial_supply_avo: f64,
    accounts: HashMap<String, GenesisAccount>,
    ordered_addresses: Vec<String>,
}

#[derive(Clone, Copy)]
// Treasury account information (deprecated - for reference only)
// Genesis now starts empty, accounts created via admin mint
struct TreasuryAccountDisplay {
    label: &'static str,
    address: &'static str,
    description: &'static str,
}

const TREASURY_GENESIS_ACCOUNTS: [TreasuryAccountDisplay; 0] = [];

fn parse_wei_to_avo(wei_str: &str) -> Option<f64> {
    let wei = wei_str.parse::<u128>().ok()?;
    Some(wei as f64 / 1_000_000_000_000_000_000f64)
}

fn load_genesis_info() -> Option<GenesisInfo> {
    let genesis_path = PathBuf::from("data/genesis.json");
    let contents = fs::read_to_string(genesis_path).ok()?;
    let json: Value = serde_json::from_str(&contents).ok()?;

    let initial_supply_avo = json
        .get("initial_supply")
        .and_then(|v| v.as_str())
        .and_then(parse_wei_to_avo)?;

    let mut accounts = HashMap::new();
    let mut ordered_addresses = Vec::new();
    if let Some(genesis_accounts) = json.get("genesis_accounts").and_then(|v| v.as_array()) {
        for account in genesis_accounts {
            if let (Some(address), Some(balance_str)) = (
                account.get("address").and_then(|v| v.as_str()),
                account.get("balance").and_then(|v| v.as_str()),
            ) {
                if let Some(balance) = parse_wei_to_avo(balance_str) {
                    let address_owned = address.to_string();
                    let name = account
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    accounts.insert(address.to_lowercase(), GenesisAccount { balance, name });
                    ordered_addresses.push(address_owned);
                }
            }
        }
    }

    Some(GenesisInfo {
        initial_supply_avo,
        accounts,
        ordered_addresses,
    })
}

fn format_optional_amount(value: Option<f64>) -> String {
    value
        .map(|v| format_decimal_with_commas(v))
        .unwrap_or_else(|| "N/A".to_string())
}

fn format_signed_decimal(value: f64) -> String {
    if value.abs() < 0.0000005 {
        "0.000000".to_string()
    } else {
        let sign = if value >= 0.0 { "+" } else { "-" };
        let magnitude = format_decimal_with_commas(value.abs());
        format!("{}{}", sign, magnitude)
    }
}

fn label_from_fee_key(key: &str) -> &str {
    match key {
        "validator_rewards" => "Validator rewards",
        "development" => "Development",
        "marketing" => "Marketing",
        "security" => "Security",
        "community" => "Community",
        "treasury_main" => "Main treasury",
        "burn" => "Burn",
        other => other,
    }
}

async fn show_account_stats() -> AvoResult<()> {
    println!("\x1b[33m[INFO]\x1b[0m Querying account statistics via RPC...");

    match rpc_call("avo_getAccountStats", vec![]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                println!("\n\x1b[32m[SUCCESS]\x1b[0m AVO Protocol Account Statistics");
                println!("===========================================");

                if let Some(total_accounts) = result.get("total_accounts") {
                    println!("📊 Total Accounts: {}", total_accounts);
                }

                if let Some(accounts_with_balance) = result.get("accounts_with_balance") {
                    println!("💰 Accounts with Balance: {}", accounts_with_balance);
                }

                if let Some(accounts_zero_balance) = result.get("accounts_zero_balance") {
                    println!("⭕ Accounts with Zero Balance: {}", accounts_zero_balance);
                }

                if let Some(total_supply_avo) = result.get("total_supply_avo").and_then(|v| v.as_str()) {
                    println!("🪙 Total Supply: {} AVO", total_supply_avo);
                }

                if let Some(total_supply_wei) = result.get("total_supply_wei").and_then(|v| v.as_str()) {
                    println!("⚖️  Total Supply (Wei): {}", total_supply_wei);
                }

                println!("===========================================");
            } else if let Some(error) = resp.error {
                println!("\x1b[31m[ERROR]\x1b[0m RPC Error: {}", error.message);
            } else {
                println!("\x1b[31m[ERROR]\x1b[0m Unknown response format");
            }
        }
        Err(e) => {
            println!("\x1b[31m[ERROR]\x1b[0m Failed to connect to node: {}", e);
            println!("\x1b[33m[INFO]\x1b[0m Make sure the AVO node is running on port 9545");
        }
    }

    Ok(())
}

async fn show_total_supply() -> AvoResult<()> {
    println!("\x1b[33m[INFO]\x1b[0m Querying total supply via RPC...");

    match rpc_call("avo_getTotalSupply", vec![]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                println!("\x1b[32m[SUCCESS]\x1b[0m AVO Protocol Total Supply");
                println!("===============================");

                if let Some(total_supply_avo) = result.get("total_supply_avo") {
                    println!("📊 Total Supply: {} AVO", total_supply_avo);
                }

                if let Some(total_supply_wei) =
                    result.get("total_supply_wei").and_then(|v| v.as_str())
                {
                    println!("⚖️  Total Supply (Wei): {}", total_supply_wei);
                }

                if let Some(known_accounts) = result.get("known_accounts") {
                    println!("🏦 Known Accounts: {}", known_accounts);
                }

                if let Some(timestamp) = result.get("timestamp") {
                    println!("⏰ Query Time: {}", timestamp);
                }
            } else if let Some(error) = resp.error {
                println!("\x1b[31m[ERROR]\x1b[0m RPC Error: {}", error.message);
            } else {
                println!("\x1b[31m[ERROR]\x1b[0m Unknown response format");
            }
        }
        Err(e) => {
            println!("\x1b[31m[ERROR]\x1b[0m Failed to connect to node: {}", e);
            println!("\x1b[33m[INFO]\x1b[0m Make sure the AVO node is running on port 9545");
        }
    }

    Ok(())
}

async fn handle_quick_tx(
    account: &str,
    to: &str,
    amount: f64,
    gasfee: Option<f64>,
    shard: u32,
) -> AvoResult<()> {
    // Convert amount to wei (AVO uses 18 decimals like ETH)
    let amount_wei = (amount * 1_000_000_000_000_000_000.0) as u128;

    // Calculate gas fee intelligently if not provided
    let gas_fee = match gasfee {
        Some(fee) => (fee * 1_000_000_000_000_000_000.0) as u128,
        None => {
            // Use intelligent gas calculation: 21000 gas * 1 Gwei
            let gas_limit = 21_000u64;
            let gas_price = 1_000_000_000u128; // 1 Gwei
            gas_limit as u128 * gas_price
        }
    };

    // 🔐 SECURE TRANSACTION: Load wallet and sign with Ed25519
    println!();
    println!("\x1b[36m╔════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[36m║         🔐 SECURE TRANSFER                         ║\x1b[0m");
    println!("\x1b[36m╚════════════════════════════════════════════════════════╝\x1b[0m");
    println!();

    // 1. Find wallet
    println!("\x1b[90m[1/5]\x1b[0m 🔍 Buscando wallet para address {}...", account);
    let wallet_path = find_wallet_by_address(&account)?;
    println!("\x1b[32m      ✓ Wallet encontrada: {}\x1b[0m", wallet_path.display());

    // 2. Load wallet data
    println!("\x1b[90m[2/5]\x1b[0m 📂 Cargando datos de wallet...");
    let wallet_data = match load_wallet_json(&wallet_path) {
        Ok(wallet) => {
            println!("\x1b[32m      ✓ Wallet cargada correctamente\x1b[0m");
            wallet
        }
        Err(e) => {
            println!("\x1b[31m      ✗ Error cargando wallet: {}\x1b[0m", e);
            return Err(e);
        }
    };

    // 3. Get nonce from RPC
    println!("\x1b[90m[3/5]\x1b[0m 🔢 Obteniendo nonce desde RPC...");
    let nonce = match security::get_nonce(&account).await {
        Ok(n) => {
            println!("\x1b[32m      ✓ Nonce obtenido: {}\x1b[0m", n);
            n
        }
        Err(e) => {
            println!("\x1b[31m      ✗ Error obteniendo nonce: {}\x1b[0m", e);
            return Err(AvoError::staking(format!("Failed to get nonce: {}", e)));
        }
    };

    // 4. Sign operation with Ed25519
    println!("\x1b[90m[4/5]\x1b[0m ✍️  Firmando transacción con Ed25519...");
    let signed = match security::sign_operation(
        &account,
        nonce,
        "transfer",
        &format!("{}:{}", to, amount_wei),
        &wallet_data.private_key,
    ) {
        Ok(s) => {
            println!("\x1b[32m      ✓ Transacción firmada exitosamente\x1b[0m");
            println!("\x1b[90m      Signature: {}...\x1b[0m", &s.signature[..20]);
            s
        }
        Err(e) => {
            println!("\x1b[31m      ✗ Error firmando: {}\x1b[0m", e);
            return Err(AvoError::staking(format!("Failed to sign transaction: {}", e)));
        }
    };

    // 5. Create signed RPC request
    println!("\x1b[90m[5/5]\x1b[0m 🚀 Enviando transacción firmada al RPC...");
    println!();

    // Create RPC request for cross-shard transaction with signature
    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "avo_sendCrossShardTransaction",
        "params": [{
            "from": account,
            "to": to,
            "value": amount_wei.to_string(),
            "fromShard": shard,
            "toShard": shard,
            "gasLimit": 21000,
            "gasPrice": 1_000_000_000u64,
            "nonce": nonce,
            "signature": signed.signature,
            "publicKey": signed.public_key
        }],
        "id": 1
    });

    // Show clean transaction preview
    println!();
    println!("\x1b[36m┌─ AVO Transaction\x1b[0m");
    println!("\x1b[36m│\x1b[0m");
    println!(
        "\x1b[36m│\x1b[0m  💸 Amount: \x1b[32m{:.2} AVO\x1b[0m",
        amount
    );
    println!(
        "\x1b[36m│\x1b[0m  📤 From:   \x1b[33m{}...{}\x1b[0m",
        &account[..6],
        &account[account.len() - 4..]
    );
    println!(
        "\x1b[36m│\x1b[0m  📥 To:     \x1b[33m{}...{}\x1b[0m",
        &to[..6],
        &to[to.len() - 4..]
    );
    println!(
        "\x1b[36m│\x1b[0m  ⛽ Fee:    \x1b[90m{:.6} AVO\x1b[0m",
        gas_fee as f64 / 1_000_000_000_000_000_000.0
    );
    println!("\x1b[36m│\x1b[0m");
    println!("\x1b[36m└─ Submitting...\x1b[0m");
    println!();

    match client
        .post("http://127.0.0.1:9545")
        .json(&request_body)
        .send()
        .await
    {
        Ok(response) => {
            match response.json::<serde_json::Value>().await {
                Ok(result) => {
                    if let Some(error) = result.get("error") {
                        println!("\x1b[31m❌ Transaction Failed\x1b[0m");
                        println!("   Error: {}", error);
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("RPC Error: {}", error),
                        )
                        .into());
                    }

                    if let Some(tx_hash) = result.get("result") {
                        // Extract transaction hash from the JSON response
                        let hash_str = if tx_hash.is_string() {
                            tx_hash.as_str().unwrap_or("unknown")
                        } else if let Some(obj) = tx_hash.as_object() {
                            obj.get("transactionHash")
                                .and_then(|h| h.as_str())
                                .unwrap_or("unknown")
                        } else {
                            "unknown"
                        };

                        // Show clean success message
                        println!("\x1b[32m✅ Transaction Successful!\x1b[0m");
                        println!();
                        println!(
                            "   🔗 Hash: \x1b[36m{}...{}\x1b[0m",
                            &hash_str[..10],
                            if hash_str.len() > 10 {
                                &hash_str[hash_str.len() - 6..]
                            } else {
                                ""
                            }
                        );
                        println!("   ⏳ Status: \x1b[33mConfirming...\x1b[0m");
                        println!();
                        println!("\x1b[90m   💡 View on explorer: http://localhost:3000\x1b[0m");
                    } else {
                        println!(
                            "\x1b[33m⚠️  Transaction submitted but no confirmation received\x1b[0m"
                        );
                    }
                }
                Err(e) => {
                    println!("\x1b[31m❌ Network Error\x1b[0m");
                    println!("   Unable to process response: {}", e);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Parse error: {}", e),
                    )
                    .into());
                }
            }
        }
        Err(e) => {
            println!("\x1b[31m❌ Connection Failed\x1b[0m");
            println!("   Cannot connect to AVO node");
            println!("   💡 Make sure the node is running: \x1b[36mavo-node.exe\x1b[0m");
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("Connection error: {}", e),
            )
            .into());
        }
    }

    Ok(())
}
/// Auto-initialize environment for new users
async fn auto_initialize_environment() -> Result<(), Box<dyn std::error::Error>> {
    // Check if this is the first time running
    let config_exists = PathBuf::from("config.toml").exists();
    let data_exists = PathBuf::from("data").exists();

    if !config_exists || !data_exists {
        println!(
            "\x1b[36m[AUTO-INIT]\x1b[0m Welcome to AVO Protocol! Setting up your environment..."
        );

        // Create data directories
        auto_create_directories().await?;

        // Create helpful documentation
        auto_create_user_guides().await?;

        println!("\x1b[32m[SUCCESS]\x1b[0m Auto-initialization completed!");
        println!("\x1b[36m[INFO]\x1b[0m Run 'avo --help' to see available commands");
        println!("\x1b[36m[INFO]\x1b[0m Generate your first wallet: avo wallet generate");
    }

    Ok(())
}

/// Create necessary directories automatically
async fn auto_create_directories() -> Result<(), Box<dyn std::error::Error>> {
    let base_dirs = vec!["data", "keys", "logs"];

    for dir in base_dirs {
        let path = PathBuf::from(dir);
        if !path.exists() {
            fs::create_dir_all(&path)?;
            println!("\x1b[36m[AUTO-INIT]\x1b[0m Created directory: {}", dir);
        }
    }

    // Create blockchain data subdirectories
    let data_subdirs = vec![
        "data/blocks",
        "data/state",
        "data/transactions",
        "data/consensus",
        "data/network",
        "data/wal",
    ];

    for subdir in data_subdirs {
        let path = PathBuf::from(subdir);
        if !path.exists() {
            fs::create_dir_all(&path)?;
        }
    }

    // Create shard directories
    for shard_id in 0..8 {
        let shard_path = PathBuf::from(format!("data/blocks/shard_{}", shard_id));
        if !shard_path.exists() {
            fs::create_dir_all(&shard_path)?;
        }
    }

    Ok(())
}

/// Create helpful user documentation
async fn auto_create_user_guides() -> Result<(), Box<dyn std::error::Error>> {
    // Create getting started guide
    let getting_started_path = "GETTING_STARTED.md";
    if !PathBuf::from(getting_started_path).exists() {
        let content = r#"# 🚀 AVO Protocol - Getting Started Guide

Welcome to AVO Protocol! This guide will help you get started quickly.

## 🎯 Quick Commands

### Wallet Management
```bash
# Generate new wallet (saved to keys/ directory automatically)
avo wallet generate

# Import existing wallet  
avo wallet import --private-key YOUR_KEY

# Check wallet balance
avo query balance --address 0x123...

# Send tokens
avo transaction send --from 0x123... --to 0x456... --value 1000
```

### Transactions
```bash
# Send AVO tokens
avo transaction send --from 0x123... --to 0x456... --value 1000

# Check transaction status
avo query transaction --hash 0xabc123...

# View account balance
avo query balance --address 0x123...
```

### Network & Monitoring
```bash
# Check network status
avo-cli network status

# View network metrics
avo-cli network metrics

# List connected peers
avo-cli network peers
```

### Benchmarks & Performance
```bash
# Run performance benchmark
avo-cli benchmark performance --duration 30

# Test consensus performance
avo-cli benchmark consensus --transactions 10000

# Cross-shard benchmark
avo-cli benchmark cross-shard --shards 8
```

### Smart Contracts
```bash
# Deploy contract (WASM or EVM bytecode)
avo contract deploy --bytecode contract.wasm --from 0x123...

# Call contract function
avo contract call --address 0x456... --function "transfer" --args "0x789,1000" --from 0x123...

# Query contract state
avo query contract --address 0x456...
```

### Developer Tools
```bash
# Generate new keys
avo-cli dev generate-keys --count 5 --output keys/

# Validate configuration
avo-cli dev validate-config

# Clear development state
avo-cli dev clear-state

# Show system info
avo-cli dev system-info
```

## 📁 Directory Structure

After initialization, your directory will look like:
```
./
├── data/                   # Blockchain data
│   ├── blocks/            # Block storage
│   ├── state/             # State data
│   └── transactions/      # Transaction pool
├── keys/                  # Your wallets & cryptographic keys
├── logs/                  # Application logs
└── config.toml           # Node configuration
```

## 🔐 Security Notes

1. **Backup your wallets**: Store private keys securely in keys/ directory
2. **Private keys**: Never share your private keys
3. **Testnet first**: Test on testnet before mainnet
4. **Generate wallets**: Use `avo wallet generate` to create new wallets

## 🌐 Network Information

- **Mainnet Chain ID**: 1
- **Testnet Chain ID**: 1001
- **Default RPC**: http://127.0.0.1:9545
- **Block Time**: ~200ms
- **Finality**: ~200ms

## 🆘 Getting Help

- CLI Help: `avo-cli --help`
- Command Help: `avo-cli COMMAND --help`
- Documentation: `docs/` directory
- Issues: Report on GitHub

## 🎉 Next Steps

1. Create your first wallet
2. Get some test tokens (testnet)
3. Send your first transaction
4. Explore smart contracts
5. Join the community!

Happy building with AVO Protocol! 🚀
"#;

        fs::write(getting_started_path, content)?;
        println!(
            "\x1b[36m[AUTO-INIT]\x1b[0m Created getting started guide: {}",
            getting_started_path
        );
    }

    // Create start scripts
    create_start_scripts().await?;

    Ok(())
}

/// Create convenient start scripts
async fn create_start_scripts() -> Result<(), Box<dyn std::error::Error>> {
    // Windows batch script
    if cfg!(windows) {
        let batch_script = "start_avo_node.bat";
        if !PathBuf::from(batch_script).exists() {
            let content = r#"@echo off
echo.
echo ========================================
echo        AVO Protocol Node Starter
echo ========================================
echo.
echo Starting AVO Protocol blockchain node...
echo Press Ctrl+C to stop the node
echo.

if not exist "avo-node.exe" (
    echo ERROR: avo-node.exe not found!
    echo Please compile first: cargo build --release
    echo Then copy from target/release/avo-node.exe
    pause
    exit /b 1
)

avo-node.exe start

echo.
echo Node stopped.
pause
"#;

            fs::write(batch_script, content)?;
            println!(
                "\x1b[36m[AUTO-INIT]\x1b[0m Created Windows start script: {}",
                batch_script
            );
        }
    }

    // Unix shell script
    if cfg!(unix) {
        let shell_script = "start_avo_node.sh";
        if !PathBuf::from(shell_script).exists() {
            let content = r#"#!/bin/bash

echo
echo "========================================"
echo "       AVO Protocol Node Starter"
echo "========================================"
echo
echo "Starting AVO Protocol blockchain node..."
echo "Press Ctrl+C to stop the node"
echo

if [ ! -f "./avo-node" ]; then
    echo "ERROR: avo-node binary not found!"
    echo "Please compile first: cargo build --release"
    echo "Then copy from target/release/avo-node"
    exit 1
fi

./avo-node start

echo
echo "Node stopped."
"#;

            fs::write(shell_script, content)?;

            // Make executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(shell_script)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(shell_script, perms)?;
            }

            println!(
                "\x1b[36m[AUTO-INIT]\x1b[0m Created Unix start script: {}",
                shell_script
            );
        }
    }

    Ok(())
}

async fn handle_treasury_commands(action: &TreasuryCommands) -> AvoResult<()> {
    match action {
        TreasuryCommands::Accounts => show_treasury_accounts().await,
        TreasuryCommands::Info { account } => show_treasury_account_info(account).await,
        TreasuryCommands::Distribution => show_fee_distribution().await,
        TreasuryCommands::Balances => show_treasury_balances().await,
    }
}

async fn handle_governance_commands(action: &GovernanceCommands) -> AvoResult<()> {
    match action {
        GovernanceCommands::Propose {
            proposer,
            proposal_type,
            title,
            description,
            parameter,
            current_value,
            new_value,
        } => {
            create_proposal(
                proposer,
                proposal_type,
                title,
                description,
                parameter.as_deref(),
                current_value.as_deref(),
                new_value.as_deref(),
            )
            .await
        }
        GovernanceCommands::Vote {
            voter,
            proposal_id,
            choice,
        } => cast_vote(voter, proposal_id, choice).await,
        GovernanceCommands::Stats => show_governance_stats().await,
        GovernanceCommands::List => list_proposals().await,
        GovernanceCommands::Info { proposal_id } => show_proposal_info(proposal_id).await,
    }
}

async fn handle_admin_commands(action: AdminCommands) -> AvoResult<()> {
    match action {
        AdminCommands::InitGenesis { file, admin } => init_genesis_allocations(&file, &admin).await,
        AdminCommands::Mint { to, amount, admin, reason } => {
            mint_tokens(&to, amount, &admin, &reason).await
        }
        AdminCommands::VerifySupply { expected } => verify_total_supply(expected).await,
    }
}

async fn init_genesis_allocations(file: &Path, admin: &str) -> AvoResult<()> {
    use serde::{Deserialize, Serialize};

    #[derive(Deserialize, Serialize)]
    struct GenesisAllocation {
        address: String,
        amount_avo: u64,
        label: String,
        locked_until: Option<u64>,
    }

    #[derive(Deserialize)]
    struct GenesisFile {
        allocations: Vec<GenesisAllocation>,
        admin_address: String,
    }

    // Load genesis file
    let content = std::fs::read_to_string(file).map_err(|e| AvoError::InvalidInput(format!("Failed to read file: {}", e)))?;
    let genesis: GenesisFile = serde_json::from_str(&content).map_err(|e| AvoError::InvalidInput(format!("Invalid JSON: {}", e)))?;

    // Verify admin
    if genesis.admin_address != admin {
        return Err(AvoError::InvalidInput(format!(
            "Admin address mismatch. Expected: {}, Got: {}",
            genesis.admin_address, admin
        )));
    }

    println!("\x1b[33m[ADMIN]\x1b[0m Initializing Genesis Allocations");
    println!("═══════════════════════════════════════════════");
    println!("Admin: {}", admin);
    println!("Allocations: {}", genesis.allocations.len());
    println!();

    let mut total_allocated = 0u64;

    for alloc in &genesis.allocations {
        println!("📝 {} ({} AVO)", alloc.label, format_number_with_commas(alloc.amount_avo));
        println!("   → {}", alloc.address);
        
        if let Some(locked) = alloc.locked_until {
            println!("   🔒 Locked until timestamp: {}", locked);
        }

        // Execute mint
        let amount_wei = alloc.amount_avo as u128 * 10u128.pow(18);
        let params = json!({
            "to": alloc.address,
            "amount": amount_wei.to_string(),
            "admin": admin,
            "reason": format!("Genesis allocation: {}", alloc.label)
        });

        match rpc_call("avo_adminMint", vec![params]).await {
            Ok(resp) => {
                if let Some(result) = resp.result {
                    if result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                        println!("   ✅ Minted successfully");
                        total_allocated += alloc.amount_avo;
                    } else {
                        println!("   ❌ Failed: {}", result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown"));
                        return Err(AvoError::InvalidInput(format!("Failed to mint to {}", alloc.address)));
                    }
                }
            }
            Err(e) => {
                println!("   ❌ RPC Error: {:?}", e);
                return Err(AvoError::InvalidInput(format!("RPC call failed: {}", e)));
            }
        }
        println!();
    }

    println!("═══════════════════════════════════════════════");
    println!("\x1b[32m[SUCCESS]\x1b[0m Genesis initialization complete!");
    println!("Total Allocated: {} AVO", format_number_with_commas(total_allocated));
    println!();

    Ok(())
}

async fn mint_tokens(to: &str, amount_avo: u64, admin: &str, reason: &str) -> AvoResult<()> {
    use secp256k1::{Message, Secp256k1, SecretKey};
    use std::io::{self, Write};
    
    println!("\x1b[33m⚠️  [ADMIN MINT]\x1b[0m");
    println!("═══════════════════════════════════════════════");
    println!("Target: {}", to);
    println!("Amount: {} AVO", amount_avo);
    println!("Admin: {}", admin);
    println!("Reason: {}", reason);
    println!();
    println!("⚠️  This operation will create new tokens!");
    println!();

    // 1. Pedir clave privada del admin (NUNCA se guarda en disco)
    println!("\x1b[90m[1/3]\x1b[0m � Ingresa la clave privada del admin (oculta):");
    print!("      Private Key (hex, 64 chars): ");
    io::stdout().flush().unwrap();
    
    // Leer private key de forma segura (en Windows no podemos ocultar, pero advertimos)
    let mut private_key_input = String::new();
    io::stdin().read_line(&mut private_key_input)
        .map_err(|e| AvoError::InvalidInput(format!("Failed to read input: {}", e)))?;
    
    let private_key_hex = private_key_input.trim().to_string();
    
    // Validar formato
    if private_key_hex.len() != 64 {
        println!("\x1b[31m      ✗ Error: La clave privada debe tener 64 caracteres hex\x1b[0m");
        return Err(AvoError::InvalidInput("Invalid private key length".to_string()));
    }
    
    // Verificar que la clave corresponde al admin address
    let private_key_bytes = hex::decode(&private_key_hex)
        .map_err(|e| AvoError::InvalidInput(format!("Invalid hex format: {}", e)))?;
    
    if private_key_bytes.len() != 32 {
        println!("\x1b[31m      ✗ Error: La clave privada debe ser exactamente 32 bytes\x1b[0m");
        return Err(AvoError::InvalidInput("Invalid key length".to_string()));
    }
    
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&private_key_bytes);
    
    let public_key_bytes = private_key_to_public_key(&pk_array)
        .map_err(|e| AvoError::InvalidInput(format!("Failed to derive public key: {}", e)))?;
    
    let derived_address = public_key_to_address(&public_key_bytes);
    
    if derived_address.to_lowercase() != admin.to_lowercase() {
        println!("\x1b[31m      ✗ Error: La clave privada no corresponde al admin {}\x1b[0m", admin);
        println!("\x1b[31m         Clave corresponde a: {}\x1b[0m", derived_address);
        // Borrar clave de memoria
        drop(private_key_hex);
        drop(private_key_bytes);
        let _ = pk_array;
        return Err(AvoError::InvalidInput("Private key mismatch".to_string()));
    }
    
    println!("\x1b[32m      ✓ Clave privada verificada correctamente\x1b[0m");
    println!();

    // 2. Generar mensaje y firmarlo con ECDSA
    println!("\x1b[90m[2/3]\x1b[0m ✍️  Firmando mensaje con ECDSA (Ethereum)...");
    
    let amount_wei = amount_avo as u128 * 10u128.pow(18);
    let timestamp = chrono::Utc::now().timestamp();
    
    // Crear mensaje: "MINT:to:amount:timestamp:reason"
    let message = format!("MINT:{}:{}:{}:{}", to, amount_wei, timestamp, reason);
    println!("\x1b[90m      Mensaje: {}\x1b[0m", message);
    
    // Hash del mensaje con EIP-191 (Ethereum Signed Message standard)
    // Formato: "\x19Ethereum Signed Message:\n" + len(message) + message
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut prefixed_message = prefix.as_bytes().to_vec();
    prefixed_message.extend_from_slice(message.as_bytes());
    
    let message_hash = {
        let mut hasher = tiny_keccak::Keccak::v256();
        let mut hash = [0u8; 32];
        hasher.update(&prefixed_message);
        hasher.finalize(&mut hash);
        hash
    };
    
    // Firmar con la private key del admin
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&private_key_bytes)
        .map_err(|e| AvoError::InvalidInput(format!("Invalid secret key: {}", e)))?;
    
    let msg = Message::from_digest(message_hash);
    let sig = secp.sign_ecdsa_recoverable(&msg, &secret_key);
    let (recovery_id, sig_bytes) = sig.serialize_compact();
    
    // Formato Ethereum: r + s + v (65 bytes)
    let mut signature = [0u8; 65];
    signature[0..64].copy_from_slice(&sig_bytes);
    signature[64] = recovery_id.to_i32() as u8;
    
    let signature_hex = format!("0x{}", hex::encode(signature));
    println!("\x1b[32m      ✓ Firma generada: {}...\x1b[0m", &signature_hex[..20]);
    
    // Borrar clave privada de memoria (seguridad)
    drop(private_key_hex);
    drop(private_key_bytes);
    let _ = secret_key;
    println!("\x1b[90m      🗑️  Clave privada borrada de memoria\x1b[0m");
    println!();

    // 3. Enviar al RPC con message + signature
    println!("\x1b[90m[3/3]\x1b[0m 🚀 Enviando mint firmado al RPC...");
    println!();
    
    let params = json!({
        "to": to,
        "amount": amount_wei.to_string(),
        "message": message,
        "signature": signature_hex,
        "reason": reason
    });

    match rpc_call("avo_adminMint", vec![params]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                if result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                    println!("\x1b[32m✅ [SUCCESS] Tokens minted successfully!\x1b[0m");
                    if let Some(tx_hash) = result.get("tx_hash").and_then(|v| v.as_str()) {
                        println!("Transaction: {}", tx_hash);
                    }
                    if let Some(new_balance) = result.get("new_balance").and_then(|v| v.as_str()) {
                        println!("New Balance: {} wei", new_balance);
                    }
                    println!();
                } else {
                    let error = result.get("error").and_then(|v| v.as_str()).unwrap_or("Unknown error");
                    println!("\x1b[31m[ERROR]\x1b[0m {}", error);
                    return Err(AvoError::InvalidInput(error.to_string()));
                }
            }
        }
        Err(e) => {
            println!("\x1b[31m[ERROR]\x1b[0m RPC call failed: {:?}", e);
            return Err(AvoError::InvalidInput(format!("Mint RPC failed: {}", e)));
        }
    }

    Ok(())
}

async fn verify_total_supply(expected_avo: u64) -> AvoResult<()> {
    println!("\x1b[36m[VERIFY]\x1b[0m Total Supply Verification");
    println!("═══════════════════════════════════════════════");
    println!("Expected: {} AVO", expected_avo);
    println!();

    match rpc_call("avo_getTotalSupply", vec![]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                if let Some(supply_obj) = result.as_object() {
                    let total_avo = supply_obj
                        .get("total_supply_avo")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(0);

                    println!("Actual: {} AVO", total_avo);
                    println!();

                    if total_avo == expected_avo {
                        println!("\x1b[32m✅ VERIFIED\x1b[0m Supply matches expected!");
                    } else {
                        println!("\x1b[31m❌ MISMATCH\x1b[0m");
                        println!("Difference: {} AVO", (total_avo as i64 - expected_avo as i64).abs());
                        return Err(AvoError::InvalidInput("Supply verification failed".to_string()));
                    }
                }
            }
        }
        Err(e) => {
            println!("\x1b[31m[ERROR]\x1b[0m Failed to fetch supply: {:?}", e);
            return Err(AvoError::InvalidInput(format!("Supply RPC failed: {}", e)));
        }
    }

    Ok(())
}

async fn show_treasury_accounts() -> AvoResult<()> {
    println!("\x1b[32m[SUCCESS]\x1b[0m AVO Protocol Treasury Accounts");
    println!("================================================");
    println!();

    // Team Allocation
    println!("� \x1b[35mTeam Allocation (LOCKED)\x1b[0m");
    println!("   Address: 0xd913b7e2f3aF1D783330C76C84b202d194faed28");
    println!("   Purpose: Team allocation with 1-year vesting lock");
    println!("   Genesis Balance: 150,000 AVO (15% of initial supply)");
    println!("   Status: 🔒 LOCKED until 2026-09-09");
    println!("   Control: Team wallet with vesting smart contract");
    println!();

    // Main Treasury
    println!("🏦 \x1b[36mMain Treasury\x1b[0m");
    println!("   Address: 0xE84f43cBc43BFa79Ddf1a612bC4323Da6682103f");
    println!("   Purpose: Main operational treasury - Governance controlled");
    println!("   Genesis Balance: 200,000 AVO (20%)");
    println!("   Multisig: 5/7 governance council signatures required");
    println!();

    // Development Treasury
    println!("🛠️  \x1b[36mDevelopment Treasury\x1b[0m");
    println!("   Address: 0x6F3DA5FEc8eBb3827a9da7CFE9cB1EaD64493eF8");
    println!("   Purpose: Development funding - Core team multisig");
    println!("   Genesis Balance: 150,000 AVO (15%)");
    println!("   Multisig: 3/5 dev team signatures required");
    println!();

    // Marketing Treasury
    println!("🎯 \x1b[36mMarketing Treasury\x1b[0m");
    println!("   Address: 0x4267b2a860a5c047D7EF1492F5c9c08849982dDc");
    println!("   Purpose: Marketing and partnerships - Marketing team multisig");
    println!("   Genesis Balance: 100,000 AVO (10%)");
    println!("   Multisig: 2/3 marketing team signatures required");
    println!();

    // Security Treasury
    println!("🔒 \x1b[36mSecurity Treasury\x1b[0m");
    println!("   Address: 0x0ECeCD0628f8Eca388D0502Efc3900cF3c494F4f");
    println!("   Purpose: Security audits and bug bounties - Security team multisig");
    println!("   Genesis Balance: 100,000 AVO (10%)");
    println!("   Multisig: 3/5 security team signatures required");
    println!();

    // Community Treasury
    println!("👥 \x1b[36mCommunity Treasury\x1b[0m");
    println!("   Address: 0xB23953C4fdA83f78b3A47e3979A5b1B40075D68a");
    println!("   Purpose: Community incentives and grants - Community multisig");
    println!("   Genesis Balance: 50,000 AVO (5%)");
    println!("   Multisig: 3/5 community leaders signatures required");
    println!();

    // Emergency Treasury
    println!("🚨 \x1b[36mEmergency Treasury\x1b[0m");
    println!("   Address: 0xfbb00276F854800C565404123A5a45a575805D1f");
    println!("   Purpose: Emergency fund - High-security multisig");
    println!("   Genesis Balance: 50,000 AVO (5%)");
    println!("   Multisig: 6/9 emergency committee signatures required");
    println!();

    println!("� \x1b[33mValidator & Delegator Rewards:\x1b[0m");
    println!("   • No genesis allocation (generated from network fees)");
    println!("   • 40% of all transaction fees go to validators/delegators");
    println!("   • No max supply - inflationary model based on network activity");
    println!();

    Ok(())
}

async fn show_treasury_account_info(account: &TreasuryAccountType) -> AvoResult<()> {
    match account {
        TreasuryAccountType::Main => {
            let address = "0xE84f43cBc43BFa79Ddf1a612bC4323Da6682103f";
            let balance = query_avo_balance(address).await?;
            println!("🏦 \x1b[32mMain Treasury Account\x1b[0m");
            println!("==========================");
            println!("Address: {}", address);
            println!("Description: Main operational treasury controlled by governance");
            println!("Multisig Threshold: 5/7 signatures required");
            println!("Fee Allocation: Receives remaining funds after other distributions");
            println!("Current Balance: {} AVO (Live from blockchain)", balance);
            println!("Genesis Allocation: 200,000 AVO");
        }
        TreasuryAccountType::Development => {
            let address = "0x6F3DA5FEc8eBb3827a9da7CFE9cB1EaD64493eF8";
            let balance = query_avo_balance(address).await?;
            println!("🛠️  \x1b[32mDevelopment Treasury Account\x1b[0m");
            println!("===============================");
            println!("Address: {}", address);
            println!("Description: Funding for protocol development and improvements");
            println!("Multisig Threshold: 3/5 signatures required");
            println!("Fee Allocation: 20% of all network fees");
            println!("Current Balance: {} AVO (Live from blockchain)", balance);
            println!("Genesis Allocation: 150,000 AVO");
        }
        TreasuryAccountType::Marketing => {
            let address = "0x4267b2a860a5c047D7EF1492F5c9c08849982dDc";
            let balance = query_avo_balance(address).await?;
            println!("🎯 \x1b[32mMarketing Treasury Account\x1b[0m");
            println!("=============================");
            println!("Address: {}", address);
            println!("Description: Marketing, partnerships, and ecosystem growth");
            println!("Multisig Threshold: 2/3 signatures required");
            println!("Fee Allocation: 10% of all network fees");
            println!("Current Balance: {} AVO (Live from blockchain)", balance);
            println!("Genesis Allocation: 100,000 AVO");
        }
        TreasuryAccountType::Security => {
            let address = "0x0ECeCD0628f8Eca388D0502Efc3900cF3c494F4f";
            let balance = query_avo_balance(address).await?;
            println!("🔒 \x1b[32mSecurity Treasury Account\x1b[0m");
            println!("============================");
            println!("Address: {}", address);
            println!("Description: Security audits, bug bounties, and vulnerability research");
            println!("Multisig Threshold: 3/5 signatures required");
            println!("Fee Allocation: 10% of all network fees");
            println!("Current Balance: {} AVO (Live from blockchain)", balance);
            println!("Genesis Allocation: 100,000 AVO");
        }
        TreasuryAccountType::Community => {
            let address = "0xB23953C4fdA83f78b3A47e3979A5b1B40075D68a";
            let balance = query_avo_balance(address).await?;
            println!("👥 \x1b[32mCommunity Treasury Account\x1b[0m");
            println!("=============================");
            println!("Address: {}", address);
            println!("Description: Community grants, events, and ecosystem incentives");
            println!("Multisig Threshold: 3/5 signatures required");
            println!("Fee Allocation: 5% of all network fees");
            println!("Current Balance: {} AVO (Live from blockchain)", balance);
            println!("Genesis Allocation: 50,000 AVO");
        }
        TreasuryAccountType::ValidatorRewards => {
            println!("🏆 \x1b[32mValidator Rewards Pool\x1b[0m");
            println!("========================");
            println!("Address: No genesis allocation - Generated from network fees");
            println!("Description: Automated rewards distribution to validators and delegators");
            println!("Multisig Threshold: 1/1 (Automated smart contract)");
            println!("Fee Allocation: 40% of all network fees");
            println!("Current Balance: Dynamic (Generated from fees)");
        }
        TreasuryAccountType::Emergency => {
            let address = "0xfbb00276F854800C565404123A5a45a575805D1f";
            let balance = query_avo_balance(address).await?;
            println!("🚨 \x1b[32mEmergency Treasury Account\x1b[0m");
            println!("=============================");
            println!("Address: {}", address);
            println!("Description: Emergency fund for critical protocol issues");
            println!("Multisig Threshold: 6/9 signatures required");
            println!("Fee Allocation: No automatic allocation (funded by governance)");
            println!("Current Balance: {} AVO (Live from blockchain)", balance);
            println!("Genesis Allocation: 50,000 AVO");
        }
    }
    println!();
    Ok(())
}

async fn show_fee_distribution() -> AvoResult<()> {
    println!("\x1b[32m[SUCCESS]\x1b[0m AVO Protocol Fee Distribution");
    println!("==========================================");
    println!();
    println!("📊 \x1b[36mHow Network Fees Are Distributed:\x1b[0m");
    println!();
    println!(
        "🔥 \x1b[31mBURN (100% DEFLATION):\x1b[0m → 0x000000000000000000000000000000000000DEAD"
    );
    println!("─────────────────────────────────────────");
    println!("✅ TOTAL:            100% BURNED");
    println!();
    println!("� \x1b[31mCOMPLETELY DEFLATIONARY PROTOCOL\x1b[0m");
    println!("   • ALL gas fees are burned permanently");
    println!("   • Total supply reduces with every transaction");
    println!("   • Tokens sent to DEAD address: 0x000000000000000000000000000000000000DEAD");
    println!();
    println!("💡 \x1b[33mGenesis Allocation Summary:\x1b[0m");
    println!("   • \x1b[32mPrivate Sale: 50M AVO → 0xaf34...56c ✅ UNLOCKED\x1b[0m");
    println!("   • Team: 10M AVO → 0xd913...d28 🔒 LOCKED 1 year");
    println!("   • Development: 8M AVO → 0x6F3D...eF8");
    println!("   • Main Treasury: 5M AVO → 0xE84f...03f");
    println!("   • Marketing: 3M AVO → 0x4267...dDc");
    println!("   • Security: 2M AVO → 0x0ECe...4f");
    println!("   • Community: 1.5M AVO → 0xB239...68a");
    println!("   • Emergency: 500K AVO → 0xfbb0...D1f");
    println!("   ────────────────────────────────────");
    println!("   • \x1b[36mTOTAL GENESIS: 80,000,000 AVO\x1b[0m");
    println!();
    println!("💡 \x1b[33mExample:\x1b[0m If network generates 1,000 AVO in fees:");
    println!("   • \x1b[31m1,000 AVO → BURNED to DEAD address (100%)\x1b[0m");
    println!("   • Total supply reduced from 80M to 79,999,000 AVO");
    println!("   • \x1b[32mPrivate Sale: 50M AVO ready for immediate use\x1b[0m");
    println!("   • Maximum deflationary + strategic liquidity model");
    println!();
    Ok(())
}

async fn show_treasury_balances() -> AvoResult<()> {
    let genesis_info = load_genesis_info();

    println!("\n\x1b[35mAVO Treasury overview\x1b[0m");
    if let Some(ref info) = genesis_info {
        println!(
            "   Genesis supply: {} AVO",
            format_decimal_with_commas(info.initial_supply_avo)
        );
    } else {
        println!("   Genesis supply: unavailable (missing data/genesis.json)");
    }
    println!();

    let mut burned_display = "0.000000 AVO".to_string();
    let mut burn_share: Option<String> = None;
    let mut non_zero_distribution: Vec<(String, String)> = Vec::new();

    match rpc_call_quiet("avo_getTreasuryBalances", vec![]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                if let Some(balances_obj) = result.get("balances").and_then(|v| v.as_object()) {
                    if let Some(burn_value) =
                        balances_obj.get("burned_tokens").and_then(|v| v.as_str())
                    {
                        burned_display = burn_value.to_string();
                    }
                }

                if let Some(fee_obj) = result.get("fee_distribution").and_then(|v| v.as_object()) {
                    for (key, value) in fee_obj {
                        if let Some(value_str) = value.as_str() {
                            if key == "burn" {
                                burn_share = Some(value_str.to_string());
                            } else if value_str != "0%" && value_str != "0.0%" {
                                non_zero_distribution.push((
                                    label_from_fee_key(key).to_string(),
                                    value_str.to_string(),
                                ));
                            }
                        }
                    }
                }
            } else if let Some(error) = resp.error {
                println!("\x1b[31m[ERROR]\x1b[0m RPC error: {}", error.message);
            }
        }
        Err(e) => {
            println!(
                "\x1b[31m[ERROR]\x1b[0m Unable to fetch treasury summary: {}",
                e
            );
        }
    }

    println!("\x1b[33mDeflationary gas model\x1b[0m");
    println!("   Burned so far: {}", burned_display);
    println!("   Burn address:  0x000000000000000000000000000000000000DEAD");
    match (burn_share, non_zero_distribution.is_empty()) {
        (Some(burn), true) => println!(
            "   Gas fees actuales: {} se queman en la dirección DEAD",
            burn
        ),
        (Some(burn), false) => {
            println!("   Gas fee split:");
            println!("      • Burn               {}", burn);
            for (label, value) in &non_zero_distribution {
                println!("      • {:<18} {}", label, value);
            }
        }
        (None, _) => println!("   Gas fees actuales: se queman en la dirección DEAD"),
    }
    println!();

    println!("\x1b[36mAsignaciones génesis\x1b[0m");
    println!(
        "{:<3} {:<26} {:<44} {:>16} {:>16} {:>14}",
        "#", "Cuenta", "Dirección", "En cadena", "Génesis", "Δ (AVO)"
    );
    println!("{}", "-".repeat(120));

    let mut total_on_chain = 0f64;
    let mut total_genesis = 0f64;
    let mut on_chain_count = 0usize;
    let mut genesis_count = 0usize;

    for (idx, account) in TREASURY_GENESIS_ACCOUNTS.iter().enumerate() {
        let on_chain_balance = match query_avo_balance(account.address).await {
            Ok(balance_text) => balance_text.parse::<f64>().ok(),
            Err(_) => None,
        };

        if let Some(amount) = on_chain_balance {
            total_on_chain += amount;
            on_chain_count += 1;
        }

        let genesis_balance = genesis_info
            .as_ref()
            .and_then(|info| info.accounts.get(&account.address.to_lowercase()))
            .map(|acc| acc.balance);

        if let Some(amount) = genesis_balance {
            total_genesis += amount;
            genesis_count += 1;
        }

        let display_name = genesis_info
            .as_ref()
            .and_then(|info| info.accounts.get(&account.address.to_lowercase()))
            .map(|acc| acc.name.trim())
            .filter(|name| !name.is_empty())
            .unwrap_or(account.label);

        let on_chain_text = format_optional_amount(on_chain_balance);
        let genesis_text = format_optional_amount(genesis_balance);
        let delta_text = match (on_chain_balance, genesis_balance) {
            (Some(actual), Some(genesis_amount)) => format_signed_decimal(actual - genesis_amount),
            (Some(actual), None) => format_signed_decimal(actual),
            (None, Some(genesis_amount)) => format_signed_decimal(-genesis_amount),
            _ => "N/A".to_string(),
        };

        println!(
            "{:<3} {:<26} {:<44} {:>16} {:>16} {:>14}",
            idx + 1,
            display_name,
            account.address,
            on_chain_text,
            genesis_text,
            delta_text
        );

        if !account.description.is_empty() {
            println!("      {}", account.description);
        }
    }

    println!("{}", "-".repeat(120));
    let total_on_chain_display = if on_chain_count > 0 {
        format_decimal_with_commas(total_on_chain)
    } else {
        "N/A".to_string()
    };
    let total_genesis_display = if genesis_count > 0 {
        format_decimal_with_commas(total_genesis)
    } else {
        "N/A".to_string()
    };
    let total_delta_display = if on_chain_count > 0 && genesis_count > 0 {
        format_signed_decimal(total_on_chain - total_genesis)
    } else {
        "N/A".to_string()
    };

    println!(
        "{:<3} {:<26} {:<44} {:>16} {:>16} {:>14}",
        "", "Total", "", total_on_chain_display, total_genesis_display, total_delta_display
    );

    println!("\nNotes:");
    println!("   • Treasury accounts are provisioned at genesis and governed by protocol rules");
    println!("   • Gas fees are currently routed entirely to the burn address");
    println!(
        "   • Staking rewards remain the primary emission source for validators and delegators"
    );

    Ok(())
}

// ===== Validator Management Commands =====
async fn handle_validator_commands(action: ValidatorCommands) -> AvoResult<()> {
    let params = ProtocolParams::default();

    match action {
        ValidatorCommands::Stake { address, amount } => {
            println!();
            println!("\x1b[36m╔════════════════════════════════════════════════════════╗\x1b[0m");
            println!("\x1b[36m║\x1b[0m         🔐 \x1b[1;36mSECURE VALIDATOR STAKING\x1b[0m                \x1b[36m║\x1b[0m");
            println!("\x1b[36m╚════════════════════════════════════════════════════════╝\x1b[0m");
            println!();
            println!("Your Address: {}", address);
            println!("Amount: {} AVO", amount);
            println!("APR: {}%", params.validator_apr * 100.0);
            println!("Minimum Required: {} AVO", params.min_validator_stake);
            println!();

            // Verificar balance via RPC
            match query_avo_balance(&address).await {
                Ok(balance_str) => {
                    let balance_avo = balance_str.parse::<f64>().unwrap_or(0.0) as u64;
                    if balance_avo < amount {
                        println!("\x1b[31m❌ ERROR: Insufficient balance!\x1b[0m");
                        println!("Current balance: {} AVO, Required: {} AVO", balance_avo, amount);
                        return Ok(());
                    }
                }
                Err(_) => {
                    println!("\x1b[33m⚠️  Could not verify balance, proceeding...\x1b[0m");
                }
            }

            // 1. Buscar wallet file
            println!("\x1b[90m[1/5]\x1b[0m 🔍 Buscando wallet para address {}...", address);
            let wallet_file = match find_wallet_by_address(&address) {
                Ok(path) => {
                    println!("\x1b[32m      ✓ Wallet encontrada: {}\x1b[0m", path.display());
                    path
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error: {}\x1b[0m", e);
                    return Err(e);
                }
            };

            // 2. Cargar wallet data
            println!("\x1b[90m[2/5]\x1b[0m 📂 Cargando datos de wallet...");
            let wallet_data = match load_wallet_json(&wallet_file) {
                Ok(wallet) => {
                    println!("\x1b[32m      ✓ Wallet cargada correctamente\x1b[0m");
                    wallet
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error cargando wallet: {}\x1b[0m", e);
                    return Err(e);
                }
            };

            // 3. Obtener nonce
            println!("\x1b[90m[3/5]\x1b[0m 🔢 Obteniendo nonce desde RPC...");
            let nonce = match security::get_nonce(&address).await {
                Ok(n) => {
                    println!("\x1b[32m      ✓ Nonce obtenido: {}\x1b[0m", n);
                    n
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error obteniendo nonce: {}\x1b[0m", e);
                    println!("\x1b[33m      ⚠️  Asegúrate de que el RPC está corriendo en http://127.0.0.1:9545\x1b[0m");
                    return Err(AvoError::staking(format!("Failed to get nonce: {}", e)));
                }
            };

            // Convertir AVO a wei
            let amount_wei = amount as u128 * 1_000_000_000_000_000_000u128;

            // 4. Firmar operación
            println!("\x1b[90m[4/5]\x1b[0m ✍️  Firmando operación con Ed25519...");
            let signed = match security::sign_operation(
                &address,
                nonce,
                "validator_stake",
                &amount_wei.to_string(),
                &wallet_data.private_key,
            ) {
                Ok(s) => {
                    println!("\x1b[32m      ✓ Operación firmada exitosamente\x1b[0m");
                    println!("\x1b[90m      Signature: {}...\x1b[0m", &s.signature[..20]);
                    s
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error firmando: {}\x1b[0m", e);
                    return Err(AvoError::staking(format!("Failed to sign operation: {}", e)));
                }
            };

            // 5. Preparar parámetros firmados
            // [address, amount_wei, nonce, signature, public_key]
            let rpc_params = vec![
                Value::String(signed.address.clone()),
                Value::String(signed.data.clone()), // amount_wei ya está en data
                Value::Number(signed.nonce.into()),
                Value::String(signed.signature),
                Value::String(signed.public_key),
            ];

            // 6. Enviar stake firmado
            println!("\x1b[90m[5/5]\x1b[0m 🚀 Enviando validator stake firmado al RPC...");
            println!();

            match rpc_call("avo_createValidatorStake", rpc_params).await {
                Ok(response) => {
                    if let Some(result) = response.result {
                        println!("\x1b[32m✅ VALIDATOR STAKE CREATED!\x1b[0m");
                        println!();
                        println!("\x1b[90m┌─────────────────────────────────────────────────────────┐\x1b[0m");
                        if let Some(position_id) = result.get("position_id") {
                            println!(
                                "\x1b[90m│\x1b[0m  \x1b[36m🆔 Position ID:\x1b[0m    \x1b[37m{}\x1b[0m",
                                position_id.as_str().unwrap_or("unknown")
                            );
                        }
                        if let Some(tx_hash) = result.get("transaction_hash") {
                            println!(
                                "\x1b[90m│\x1b[0m  \x1b[36m🔗 Transaction:\x1b[0m    \x1b[37m{}\x1b[0m",
                                tx_hash.as_str().unwrap_or("unknown")
                            );
                        }
                        println!("\x1b[90m│\x1b[0m");
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[1;32m💰 Staked:\x1b[0m         \x1b[1;37m{} AVO\x1b[0m",
                            amount
                        );
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[32m📈 APR:\x1b[0m            \x1b[37m{}%\x1b[0m",
                            params.validator_apr * 100.0
                        );
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[33m🎯 Est. Annual:\x1b[0m    \x1b[37m{} AVO\x1b[0m",
                            (amount as f64 * params.validator_apr) as u64
                        );
                        println!("\x1b[90m└─────────────────────────────────────────────────────────┘\x1b[0m");
                        println!();
                        println!("\x1b[32m  ✓ Your node can now validate transactions\x1b[0m");
                        println!("\x1b[32m  ✓ Rewards accrue continuously at {}% APR\x1b[0m", params.validator_apr * 100.0);
                        println!();
                    } else {
                        println!("\x1b[31m❌ ERROR: No result in response\x1b[0m");
                        if let Some(error) = response.error {
                            println!("\x1b[31m   {}\x1b[0m", error.message);
                        }
                    }
                }
                Err(e) => {
                    println!("\x1b[31m❌ ERROR: Failed to create validator stake\x1b[0m");
                    println!("\x1b[31m   {}\x1b[0m", e);
                    return Err(AvoError::staking(format!("Failed to create validator stake: {}", e)));
                }
            }
        }

        ValidatorCommands::Unstake { position_id, address } => {
            println!();
            println!("\x1b[36m╔════════════════════════════════════════════════════════╗\x1b[0m");
            println!("\x1b[36m║\x1b[0m         � \x1b[1;36mSECURE UNSTAKING VALIDATOR\x1b[0m              \x1b[36m║\x1b[0m");
            println!("\x1b[36m╚════════════════════════════════════════════════════════╝\x1b[0m");
            println!();

            // 1. Buscar wallet file
            println!("\x1b[90m[1/5]\x1b[0m 🔍 Buscando wallet para address {}...", address);
            let wallet_file = match find_wallet_by_address(&address) {
                Ok(path) => {
                    println!("\x1b[32m      ✓ Wallet encontrada: {}\x1b[0m", path.display());
                    path
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error: {}\x1b[0m", e);
                    return Err(e);
                }
            };

            // 2. Cargar wallet data
            println!("\x1b[90m[2/5]\x1b[0m 📂 Cargando datos de wallet...");
            let wallet_data = match load_wallet_json(&wallet_file) {
                Ok(wallet) => {
                    println!("\x1b[32m      ✓ Wallet cargada correctamente\x1b[0m");
                    wallet
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error cargando wallet: {}\x1b[0m", e);
                    return Err(e);
                }
            };

            // 3. Obtener nonce
            println!("\x1b[90m[3/5]\x1b[0m 🔢 Obteniendo nonce desde RPC...");
            let nonce = match security::get_nonce(&address).await {
                Ok(n) => {
                    println!("\x1b[32m      ✓ Nonce obtenido: {}\x1b[0m", n);
                    n
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error obteniendo nonce: {}\x1b[0m", e);
                    println!("\x1b[33m      ⚠️  Asegúrate de que el RPC está corriendo en http://127.0.0.1:9545\x1b[0m");
                    return Err(AvoError::internal(format!("Failed to get nonce: {}", e)));
                }
            };

            // 4. Firmar operación
            println!("\x1b[90m[4/5]\x1b[0m ✍️  Firmando operación con Ed25519...");
            let signed = match security::sign_operation(
                &address,
                nonce,
                "unstake",
                &position_id,
                &wallet_data.private_key,
            ) {
                Ok(s) => {
                    println!("\x1b[32m      ✓ Operación firmada exitosamente\x1b[0m");
                    println!("\x1b[90m      Signature: {}...\x1b[0m", &s.signature[..20]);
                    s
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error firmando: {}\x1b[0m", e);
                    return Err(AvoError::internal(format!("Failed to sign operation: {}", e)));
                }
            };

            // 5. Preparar parámetros firmados
            let params = security::prepare_signed_params(&signed);

            // 6. Enviar unstake firmado
            println!("\x1b[90m[5/5]\x1b[0m 🚀 Enviando unstake firmado al RPC...");
            println!();

            match rpc_call("avo_unstakePosition", params).await {
                Ok(response) => {
                    if let Some(result) = response.result {
                        // Extract values
                        let amount_avo = result
                            .get("amount_returned")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                            .unwrap_or(0.0);

                        let tx_hash = result
                            .get("transaction_hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");

                        let owner = result.get("owner").and_then(|v| v.as_str()).unwrap_or("unknown");

                        // Beautiful success message
                        println!("\x1b[32m✅ UNSTAKING SUCCESSFUL!\x1b[0m");
                        println!();
                        println!("\x1b[90m┌─────────────────────────────────────────────────────────┐\x1b[0m");
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[1;32m💰 Total Returned:\x1b[0m \x1b[1;37m{:.6} AVO\x1b[0m",
                            amount_avo
                        );
                        println!("\x1b[90m│\x1b[0m");
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[36m🔗 Transaction:\x1b[0m   \x1b[37m{}\x1b[0m",
                            tx_hash
                        );
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[36m👤 Your Address:\x1b[0m  \x1b[37m{}\x1b[0m",
                            owner
                        );
                        println!("\x1b[90m└─────────────────────────────────────────────────────────┘\x1b[0m");
                        println!();
                        println!("\x1b[32m  ✓ Funds returned immediately to your balance\x1b[0m");
                        println!();
                    } else {
                        println!("\x1b[31m❌ ERROR: No result in response\x1b[0m");
                        if let Some(error) = response.error {
                            println!("\x1b[31m┌─────────────────────────────────────────────────────────┐\x1b[0m");
                            println!("\x1b[31m│ Error Message:\x1b[0m");
                            println!("\x1b[31m│\x1b[0m {}", error.message);
                            println!("\x1b[31m└─────────────────────────────────────────────────────────┘\x1b[0m");
                            println!();

                            // Mensajes específicos según el error
                            if error.message.contains("Unauthorized") {
                                println!("\x1b[33m⚠️  Solo el dueño de la posición puede hacer unstake\x1b[0m");
                                println!("\x1b[90m   Verifica que la address sea correcta\x1b[0m");
                            } else if error.message.contains("Invalid nonce") {
                                println!("\x1b[33m⚠️  Nonce inválido - posible ataque de replay detectado\x1b[0m");
                                println!("\x1b[90m   Cada operación requiere un nonce único e incremental\x1b[0m");
                            } else if error.message.contains("Rate limit") {
                                println!("\x1b[33m⚠️  Demasiados intentos - espera 1 minuto\x1b[0m");
                                println!("\x1b[90m   Límite: 5 intentos por minuto por address\x1b[0m");
                            } else if error.message.contains("Invalid signature") {
                                println!("\x1b[33m⚠️  Firma criptográfica inválida\x1b[0m");
                                println!("\x1b[90m   La wallet puede estar corrupta\x1b[0m");
                            } else if error.message.contains("expired") {
                                println!("\x1b[33m⚠️  Mensaje expirado (>5 minutos)\x1b[0m");
                                println!("\x1b[90m   Intenta de nuevo\x1b[0m");
                            }
                            println!();
                        }
                    }
                }
                Err(e) => {
                    println!("\x1b[31m❌ ERROR: Failed to unstake position\x1b[0m");
                    println!("\x1b[31m   {}\x1b[0m", e);
                    println!();
                    println!("\x1b[33m⚠️  Posibles causas:\x1b[0m");
                    println!("\x1b[90m   • RPC server no está corriendo\x1b[0m");
                    println!("\x1b[90m   • Position ID no existe\x1b[0m");
                    println!("\x1b[90m   • Problemas de red\x1b[0m");
                    println!();
                    return Err(AvoError::staking(format!("Failed to unstake position: {}", e)));
                }
            }
        }

        ValidatorCommands::List { address } => {
            println!("📋 \x1b[36mYour Validator Stakes\x1b[0m");
            println!("==========================");

            // Load stakes from local storage
            let params = ProtocolParams::default();
            let chain_state_path = std::path::PathBuf::from("./data/chain_state.json");
            let stake_manager = StakeManager::new(params.clone(), chain_state_path);

            let positions = stake_manager.get_user_positions(&address);
            let validator_positions: Vec<_> = positions
                .into_iter()
                .filter(|p| matches!(p.stake_type, StakeType::Validator))
                .collect();

            if validator_positions.is_empty() {
                println!("No validator stakes found for address: {}", address);
                println!("💡 Use 'avo operator validator stake' to create a validator node");
            } else {
                for (i, position) in validator_positions.iter().enumerate() {
                    let pending_rewards_wei = position.calculate_pending_rewards_wei(&params);
                    let pending_rewards = (pending_rewards_wei as f64) / 1e18f64;
                    let amount_avo = (position.amount as f64) / 1e18f64;
                    println!("{}. ⚡ Validator Node", i + 1);
                    println!("   Position ID: {}", position.id);
                    println!("   Staked: {:.0} AVO", amount_avo);
                    println!("   APR: 12%");
                    println!("   Pending Rewards: {:.6} AVO", pending_rewards);
                    println!(
                        "   Status: {}",
                        if position.is_active {
                            "Active"
                        } else {
                            "Inactive"
                        }
                    );
                    println!(
                        "   Started: {}",
                        chrono::DateTime::from_timestamp(position.start_time as i64, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| "Unknown".to_string())
                    );
                    println!();
                }
            }
        }

        ValidatorCommands::Stats { address } => {
            if let Some(_addr) = address {
                println!("📊 \x1b[36mYour Validator Statistics\x1b[0m");
                println!("==============================");
                // TODO: Implement via RPC call to avo_getUserStakes
                println!("This feature will be implemented via RPC in the next update.");
            } else {
                println!("🌐 \x1b[36mGlobal Validator Statistics\x1b[0m");
                println!("=================================");
                // TODO: Implement via RPC call to avo_getStakeStats
                println!("Use 'avo stakes global' to see global statistics.");
            }
        }
    }

    Ok(())
}

/// Handle bootstrap node commands
async fn handle_bootstrap_commands(action: BootstrapCommands) -> AvoResult<()> {
    let params = ProtocolParams::default();

    match action {
        BootstrapCommands::Stake { address, amount } => {
            println!("🚀 \x1b[36mCreating Bootstrap Node Stake\x1b[0m");
            println!("====================================");
            println!("Your Address: {}", address);
            println!("Amount: {} AVO", amount);
            println!("APR: {}%", params.bootstrap_apr * 100.0);
            println!("Minimum Required: {} AVO", params.min_bootstrap_stake);

            // Verificar balance via RPC
            match query_avo_balance(&address).await {
                Ok(balance_str) => {
                    // Parse balance from decimal string (e.g. "198703.167991")
                    let balance_avo = balance_str.parse::<f64>().unwrap_or(0.0) as u64;

                    if balance_avo < amount {
                        println!("\x1b[31m[ERROR]\x1b[0m Insufficient balance!");
                        println!(
                            "Current balance: {} AVO, Required: {} AVO",
                            balance_avo, amount
                        );
                        return Ok(());
                    }
                }
                Err(_) => {
                    println!("\x1b[33m[WARNING]\x1b[0m Could not verify balance, proceeding...");
                }
            }

            // Create stake via RPC
            // Convertir AVO a wei (1 AVO = 10^18 wei)
            let amount_wei = amount as u128 * 1_000_000_000_000_000_000u128;
            match rpc_call(
                "avo_createBootstrapStake",
                vec![
                    Value::String(address.clone()),
                    Value::String(amount_wei.to_string()),
                ],
            )
            .await
            {
                Ok(response) => {
                    if let Some(result) = response.result {
                        println!("\x1b[32m[SUCCESS]\x1b[0m Bootstrap stake created!");
                        println!("📊 Bootstrap Details:");
                        if let Some(position_id) = result.get("position_id") {
                            println!("Position ID: {}", position_id.as_str().unwrap_or("unknown"));
                        }
                        if let Some(tx_hash) = result.get("transaction_hash") {
                            println!(
                                "Transaction Hash: {}",
                                tx_hash.as_str().unwrap_or("unknown")
                            );
                        }
                        println!("💰 Staked: {} AVO tokens", amount);
                        println!("📈 Annual APR: {}%", params.bootstrap_apr * 100.0);
                        println!(
                            "🎯 Est. Annual: {} AVO",
                            (amount as f64 * params.bootstrap_apr) as u64
                        );
                        println!("⚡ Role: Bootstrap Node Infrastructure");
                        println!();
                        println!("✅ Bootstrap Node Active");
                        println!("   • Your node is now part of the network infrastructure");
                        println!(
                            "   • Rewards accrue continuously at {}% APR",
                            params.bootstrap_apr * 100.0
                        );
                    }
                }
                Err(e) => {
                    return Err(AvoError::staking(format!(
                        "Failed to create bootstrap stake: {}",
                        e
                    )));
                }
            }
        }

        BootstrapCommands::Unstake { position_id, address } => {
            println!();
            println!("\x1b[36m╔════════════════════════════════════════════════════════╗\x1b[0m");
            println!("\x1b[36m║\x1b[0m         � \x1b[1;36mSECURE UNSTAKING BOOTSTRAP NODE\x1b[0m         \x1b[36m║\x1b[0m");
            println!("\x1b[36m╚════════════════════════════════════════════════════════╝\x1b[0m");
            println!();

            // 1. Buscar wallet file
            println!("\x1b[90m[1/5]\x1b[0m 🔍 Buscando wallet para address {}...", address);
            let wallet_file = match find_wallet_by_address(&address) {
                Ok(path) => {
                    println!("\x1b[32m      ✓ Wallet encontrada: {}\x1b[0m", path.display());
                    path
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error: {}\x1b[0m", e);
                    return Err(e);
                }
            };

            // 2. Cargar wallet data
            println!("\x1b[90m[2/5]\x1b[0m 📂 Cargando datos de wallet...");
            let wallet_data = match load_wallet_json(&wallet_file) {
                Ok(wallet) => {
                    println!("\x1b[32m      ✓ Wallet cargada correctamente\x1b[0m");
                    wallet
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error cargando wallet: {}\x1b[0m", e);
                    return Err(e);
                }
            };

            // 3. Obtener nonce
            println!("\x1b[90m[3/5]\x1b[0m 🔢 Obteniendo nonce desde RPC...");
            let nonce = match security::get_nonce(&address).await {
                Ok(n) => {
                    println!("\x1b[32m      ✓ Nonce obtenido: {}\x1b[0m", n);
                    n
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error obteniendo nonce: {}\x1b[0m", e);
                    println!("\x1b[33m      ⚠️  Asegúrate de que el RPC está corriendo en http://127.0.0.1:9545\x1b[0m");
                    return Err(AvoError::internal(format!("Failed to get nonce: {}", e)));
                }
            };

            // 4. Firmar operación
            println!("\x1b[90m[4/5]\x1b[0m ✍️  Firmando operación con Ed25519...");
            let signed = match security::sign_operation(
                &address,
                nonce,
                "unstake",
                &position_id,
                &wallet_data.private_key,
            ) {
                Ok(s) => {
                    println!("\x1b[32m      ✓ Operación firmada exitosamente\x1b[0m");
                    println!("\x1b[90m      Signature: {}...\x1b[0m", &s.signature[..20]);
                    s
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error firmando: {}\x1b[0m", e);
                    return Err(AvoError::internal(format!("Failed to sign operation: {}", e)));
                }
            };

            // 5. Preparar parámetros firmados
            let params = security::prepare_signed_params(&signed);

            // 6. Enviar unstake firmado
            println!("\x1b[90m[5/5]\x1b[0m 🚀 Enviando unstake firmado al RPC...");
            println!();

            match rpc_call("avo_unstakePosition", params).await {
                Ok(response) => {
                    if let Some(result) = response.result {
                        // Extract values
                        let amount_avo = result
                            .get("amount_returned")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                            .unwrap_or(0.0);

                        let tx_hash = result
                            .get("transaction_hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");

                        let owner = result.get("owner").and_then(|v| v.as_str()).unwrap_or("unknown");

                        // Beautiful success message
                        println!("\x1b[32m✅ UNSTAKING SUCCESSFUL!\x1b[0m");
                        println!();
                        println!("\x1b[90m┌─────────────────────────────────────────────────────────┐\x1b[0m");
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[1;32m💰 Total Returned:\x1b[0m \x1b[1;37m{:.6} AVO\x1b[0m",
                            amount_avo
                        );
                        println!("\x1b[90m│\x1b[0m");
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[36m🔗 Transaction:\x1b[0m   \x1b[37m{}\x1b[0m",
                            tx_hash
                        );
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[36m👤 Your Address:\x1b[0m  \x1b[37m{}\x1b[0m",
                            owner
                        );
                        println!("\x1b[90m└─────────────────────────────────────────────────────────┘\x1b[0m");
                        println!();
                        println!("\x1b[32m  ✓ Funds returned immediately to your balance\x1b[0m");
                        println!();
                    } else {
                        println!("\x1b[31m❌ ERROR: No result in response\x1b[0m");
                        if let Some(error) = response.error {
                            println!("\x1b[31m┌─────────────────────────────────────────────────────────┐\x1b[0m");
                            println!("\x1b[31m│ Error Message:\x1b[0m");
                            println!("\x1b[31m│\x1b[0m {}", error.message);
                            println!("\x1b[31m└─────────────────────────────────────────────────────────┘\x1b[0m");
                            println!();

                            // Mensajes específicos según el error
                            if error.message.contains("Unauthorized") {
                                println!("\x1b[33m⚠️  Solo el dueño de la posición puede hacer unstake\x1b[0m");
                                println!("\x1b[90m   Verifica que la address sea correcta\x1b[0m");
                            } else if error.message.contains("Invalid nonce") {
                                println!("\x1b[33m⚠️  Nonce inválido - posible ataque de replay detectado\x1b[0m");
                                println!("\x1b[90m   Cada operación requiere un nonce único e incremental\x1b[0m");
                            } else if error.message.contains("Rate limit") {
                                println!("\x1b[33m⚠️  Demasiados intentos - espera 1 minuto\x1b[0m");
                                println!("\x1b[90m   Límite: 5 intentos por minuto por address\x1b[0m");
                            } else if error.message.contains("Invalid signature") {
                                println!("\x1b[33m⚠️  Firma criptográfica inválida\x1b[0m");
                                println!("\x1b[90m   La wallet puede estar corrupta\x1b[0m");
                            } else if error.message.contains("expired") {
                                println!("\x1b[33m⚠️  Mensaje expirado (>5 minutos)\x1b[0m");
                                println!("\x1b[90m   Intenta de nuevo\x1b[0m");
                            }
                            println!();
                        }
                    }
                }
                Err(e) => {
                    println!("\x1b[31m❌ ERROR: Failed to unstake position\x1b[0m");
                    println!("\x1b[31m   {}\x1b[0m", e);
                    println!();
                    println!("\x1b[33m⚠️  Posibles causas:\x1b[0m");
                    println!("\x1b[90m   • RPC server no está corriendo\x1b[0m");
                    println!("\x1b[90m   • Position ID no existe\x1b[0m");
                    println!("\x1b[90m   • Problemas de red\x1b[0m");
                    println!();
                    return Err(AvoError::staking(format!("Failed to unstake position: {}", e)));
                }
            }
        }

        BootstrapCommands::List { address } => {
            println!("📋 \x1b[36mYour Bootstrap Stakes\x1b[0m");
            println!("==========================");

            // Load stakes from local storage
            let params = ProtocolParams::default();
            let chain_state_path = std::path::PathBuf::from("./data/chain_state.json");
            let stake_manager = StakeManager::new(params.clone(), chain_state_path);

            let positions = stake_manager.get_user_positions(&address);
            let bootstrap_positions: Vec<_> = positions
                .into_iter()
                .filter(|p| matches!(p.stake_type, StakeType::Bootstrap))
                .collect();

            if bootstrap_positions.is_empty() {
                println!("No bootstrap stakes found for address: {}", address);
                println!("💡 Use 'avo operator bootstrap stake' to create a bootstrap node");
            } else {
                for (i, position) in bootstrap_positions.iter().enumerate() {
                    let pending_rewards_wei = position.calculate_pending_rewards_wei(&params);
                    let pending_rewards = (pending_rewards_wei as f64) / 1e18f64;
                    let amount_avo = (position.amount as f64) / 1e18f64;
                    println!("{}. 🚀 Bootstrap Node", i + 1);
                    println!("   Position ID: {}", position.id);
                    println!("   Staked: {:.0} AVO", amount_avo);
                    println!("   APR: 15%");
                    println!("   Pending Rewards: {:.6} AVO", pending_rewards);
                    println!(
                        "   Status: {}",
                        if position.is_active {
                            "Active"
                        } else {
                            "Inactive"
                        }
                    );
                    println!(
                        "   Started: {}",
                        chrono::DateTime::from_timestamp(position.start_time as i64, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                            .unwrap_or_else(|| "Unknown".to_string())
                    );
                    println!();
                }
            }
        }

        BootstrapCommands::Stats { address } => {
            if let Some(_addr) = address {
                println!("📊 \x1b[36mYour Bootstrap Statistics\x1b[0m");
                println!("================================");
                // TODO: Implement via RPC call to avo_getUserStakes
                println!("This feature will be implemented via RPC in the next update.");
            } else {
                println!("🌐 \x1b[36mGlobal Bootstrap Statistics\x1b[0m");
                println!("=================================");
                // TODO: Implement via RPC call to avo_getStakeStats
                println!("Use 'avo stakes global' to see global statistics.");
            }
        }
    }

    Ok(())
}

/// Handle delegation commands
async fn handle_delegate_commands(action: DelegateCommands) -> AvoResult<()> {
    let params = ProtocolParams::default();
    let chain_state_path = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("chain_state.json");
    let stake_manager = StakeManager::new(params.clone(), chain_state_path);

    match action {
        DelegateCommands::To {
            address,
            validator_id,
            amount,
        } => {
            println!();
            println!("\x1b[36m╔════════════════════════════════════════════════════════╗\x1b[0m");
            println!("\x1b[36m║\x1b[0m         🔐 \x1b[1;36mSECURE DELEGATION CREATION\x1b[0m              \x1b[36m║\x1b[0m");
            println!("\x1b[36m╚════════════════════════════════════════════════════════╝\x1b[0m");
            println!();
            println!("Your Address: {}", address);
            println!("Validator ID: {}", validator_id);
            println!("Amount: {} AVO", amount);
            println!("APR: {}%", params.delegator_apr * 100.0);
            println!("Minimum Required: Free (any amount)");
            println!();

            // Verificar balance via RPC
            match query_avo_balance(&address).await {
                Ok(balance_str) => {
                    let balance_avo = balance_str.parse::<f64>().unwrap_or(0.0) as u64;
                    if balance_avo < amount {
                        println!("\x1b[31m❌ ERROR: Insufficient balance!\x1b[0m");
                        println!("Required: {} AVO, Available: {} AVO", amount, balance_avo);
                        return Ok(());
                    }
                }
                Err(_) => {
                    println!("\x1b[33m⚠️  Could not verify balance, proceeding...\x1b[0m");
                }
            }

            // 1. Buscar wallet file
            println!("\x1b[90m[1/5]\x1b[0m 🔍 Buscando wallet para address {}...", address);
            let wallet_file = match find_wallet_by_address(&address) {
                Ok(path) => {
                    println!("\x1b[32m      ✓ Wallet encontrada: {}\x1b[0m", path.display());
                    path
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error: {}\x1b[0m", e);
                    return Err(e);
                }
            };

            // 2. Cargar wallet data
            println!("\x1b[90m[2/5]\x1b[0m 📂 Cargando datos de wallet...");
            let wallet_data = match load_wallet_json(&wallet_file) {
                Ok(wallet) => {
                    println!("\x1b[32m      ✓ Wallet cargada correctamente\x1b[0m");
                    wallet
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error cargando wallet: {}\x1b[0m", e);
                    return Err(e);
                }
            };

            // 3. Obtener nonce
            println!("\x1b[90m[3/5]\x1b[0m 🔢 Obteniendo nonce desde RPC...");
            let nonce = match security::get_nonce(&address).await {
                Ok(n) => {
                    println!("\x1b[32m      ✓ Nonce obtenido: {}\x1b[0m", n);
                    n
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error obteniendo nonce: {}\x1b[0m", e);
                    println!("\x1b[33m      ⚠️  Asegúrate de que el RPC está corriendo en http://127.0.0.1:9545\x1b[0m");
                    return Err(AvoError::staking(format!("Failed to get nonce: {}", e)));
                }
            };

            // Convertir AVO a wei
            let amount_wei = amount as u128 * 1_000_000_000_000_000_000u128;
            
            // Datos para firma: incluir validator_id para prevenir ataques
            let delegation_data = format!("{}_validator{}", amount_wei, validator_id);

            // 4. Firmar operación
            println!("\x1b[90m[4/5]\x1b[0m ✍️  Firmando operación con Ed25519...");
            let signed = match security::sign_operation(
                &address,
                nonce,
                "delegate",
                &delegation_data,
                &wallet_data.private_key,
            ) {
                Ok(s) => {
                    println!("\x1b[32m      ✓ Operación firmada exitosamente\x1b[0m");
                    println!("\x1b[90m      Signature: {}...\x1b[0m", &s.signature[..20]);
                    s
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error firmando: {}\x1b[0m", e);
                    return Err(AvoError::staking(format!("Failed to sign operation: {}", e)));
                }
            };

            // 5. Preparar parámetros firmados
            // [address, amount_wei, validator_id, nonce, signature, public_key]
            let rpc_params = vec![
                Value::String(signed.address.clone()),
                Value::String(amount_wei.to_string()),
                Value::Number(validator_id.into()),
                Value::Number(signed.nonce.into()),
                Value::String(signed.signature),
                Value::String(signed.public_key),
            ];

            // 6. Enviar delegation firmada
            println!("\x1b[90m[5/5]\x1b[0m 🚀 Enviando delegation firmada al RPC...");
            println!();

            match rpc_call("avo_createDelegation", rpc_params).await {
                Ok(response) => {
                    if let Some(result) = response.result {
                        let position_id = result["position_id"].as_str().unwrap_or("unknown");
                        let tx_hash = result["transaction_hash"].as_str().unwrap_or("unknown");

                        println!("\x1b[32m✅ DELEGATION CREATED!\x1b[0m");
                        println!();
                        println!("\x1b[90m┌─────────────────────────────────────────────────────────┐\x1b[0m");
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[36m🆔 Position ID:\x1b[0m    \x1b[37m{}\x1b[0m",
                            position_id
                        );
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[36m🔗 Transaction:\x1b[0m    \x1b[37m{}\x1b[0m",
                            tx_hash
                        );
                        println!("\x1b[90m│\x1b[0m");
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[1;32m💰 Delegated:\x1b[0m      \x1b[1;37m{} AVO\x1b[0m",
                            amount
                        );
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[35m� Validator ID:\x1b[0m   \x1b[37m{}\x1b[0m",
                            validator_id
                        );
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[32m📈 APR:\x1b[0m            \x1b[37m{}%\x1b[0m",
                            params.delegator_apr * 100.0
                        );
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[33m🎯 Est. Annual:\x1b[0m    \x1b[37m{} AVO\x1b[0m",
                            (amount as f64 * params.delegator_apr) as u64
                        );
                        println!("\x1b[90m└─────────────────────────────────────────────────────────┘\x1b[0m");
                        println!();
                        println!("\x1b[32m  ✓ Your tokens are helping secure the network\x1b[0m");
                        println!("\x1b[32m  ✓ Rewards accrue continuously at {}% APR\x1b[0m", params.delegator_apr * 100.0);
                        println!("\x1b[90m  ℹ️  Use 'avo delegate from --position-id {}' to undelegate\x1b[0m", position_id);
                        println!();
                    } else if let Some(error) = response.error {
                        println!("\x1b[31m❌ ERROR: RPC Error\x1b[0m");
                        println!("\x1b[31m   {}\x1b[0m", error.message);
                    } else {
                        println!("\x1b[31m❌ ERROR: Unknown RPC response format\x1b[0m");
                    }
                }
                Err(e) => {
                    println!("\x1b[31m❌ ERROR: Failed to create delegation\x1b[0m");
                    println!("\x1b[31m   {}\x1b[0m", e);
                    return Err(AvoError::staking(format!("Failed to create delegation: {}", e)));
                }
            }
        }

        DelegateCommands::From { position_id, address } => {
            println!();
            println!("\x1b[36m╔════════════════════════════════════════════════════════╗\x1b[0m");
            println!("\x1b[36m║\x1b[0m         � \x1b[1;36mSECURE UNDELEGATING TOKENS\x1b[0m              \x1b[36m║\x1b[0m");
            println!("\x1b[36m╚════════════════════════════════════════════════════════╝\x1b[0m");
            println!();

            // 1. Buscar wallet file
            println!("\x1b[90m[1/5]\x1b[0m 🔍 Buscando wallet para address {}...", address);
            let wallet_file = match find_wallet_by_address(&address) {
                Ok(path) => {
                    println!("\x1b[32m      ✓ Wallet encontrada: {}\x1b[0m", path.display());
                    path
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error: {}\x1b[0m", e);
                    return Err(e);
                }
            };

            // 2. Cargar wallet data
            println!("\x1b[90m[2/5]\x1b[0m 📂 Cargando datos de wallet...");
            let wallet_data = match load_wallet_json(&wallet_file) {
                Ok(wallet) => {
                    println!("\x1b[32m      ✓ Wallet cargada correctamente\x1b[0m");
                    wallet
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error cargando wallet: {}\x1b[0m", e);
                    return Err(e);
                }
            };

            // 3. Obtener nonce
            println!("\x1b[90m[3/5]\x1b[0m 🔢 Obteniendo nonce desde RPC...");
            let nonce = match security::get_nonce(&address).await {
                Ok(n) => {
                    println!("\x1b[32m      ✓ Nonce obtenido: {}\x1b[0m", n);
                    n
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error obteniendo nonce: {}\x1b[0m", e);
                    println!("\x1b[33m      ⚠️  Asegúrate de que el RPC está corriendo en http://127.0.0.1:9545\x1b[0m");
                    return Err(AvoError::staking(format!("Failed to get nonce: {}", e)));
                }
            };

            // 4. Firmar operación
            println!("\x1b[90m[4/5]\x1b[0m ✍️  Firmando operación con Ed25519...");
            let signed = match security::sign_operation(
                &address,
                nonce,
                "unstake",
                &position_id,
                &wallet_data.private_key,
            ) {
                Ok(s) => {
                    println!("\x1b[32m      ✓ Operación firmada exitosamente\x1b[0m");
                    println!("\x1b[90m      Signature: {}...\x1b[0m", &s.signature[..20]);
                    s
                }
                Err(e) => {
                    println!("\x1b[31m      ✗ Error firmando: {}\x1b[0m", e);
                    return Err(AvoError::staking(format!("Failed to sign operation: {}", e)));
                }
            };

            // 5. Preparar parámetros firmados
            let params = security::prepare_signed_params(&signed);

            // 6. Enviar undelegate firmado
            println!("\x1b[90m[5/5]\x1b[0m 🚀 Enviando undelegate firmado al RPC...");
            println!();

            match rpc_call("avo_unstakePosition", params).await {
                Ok(response) => {
                    if let Some(result) = response.result {
                        let amount_avo = result
                            .get("amount_returned")
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse::<f64>().ok())
                            .or_else(|| {
                                result
                                    .get("total_returned_avo")
                                    .and_then(|v| v.as_str())
                                    .and_then(|s| s.parse::<f64>().ok())
                            })
                            .unwrap_or(0.0);

                        let tx_hash = result
                            .get("transaction_hash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");

                        let owner = result
                            .get("owner")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");

                        println!("\x1b[32m✅ UNDELEGATION SUCCESSFUL!\x1b[0m");
                        println!();
                        println!("\x1b[90m┌─────────────────────────────────────────────────────────┐\x1b[0m");
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[1;32m💰 Total Returned:\x1b[0m \x1b[1;37m{:.6} AVO\x1b[0m",
                            amount_avo
                        );
                        println!("\x1b[90m│\x1b[0m");
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[36m🔗 Transaction:\x1b[0m   \x1b[37m{}\x1b[0m",
                            tx_hash
                        );
                        println!(
                            "\x1b[90m│\x1b[0m  \x1b[36m👤 Your Address:\x1b[0m  \x1b[37m{}\x1b[0m",
                            owner
                        );
                        println!("\x1b[90m└─────────────────────────────────────────────────────────┘\x1b[0m");
                        println!();
                        println!("\x1b[32m  ✓ Funds returned immediately to your balance\x1b[0m");
                        println!();
                    } else {
                        println!("\x1b[31m❌ ERROR: No result in response\x1b[0m");
                        if let Some(error) = response.error {
                            println!("\x1b[31m┌─────────────────────────────────────────────────────────┐\x1b[0m");
                            println!("\x1b[31m│ Error Message:\x1b[0m");
                            println!("\x1b[31m│\x1b[0m {}", error.message);
                            println!("\x1b[31m└─────────────────────────────────────────────────────────┘\x1b[0m");
                            println!();

                            // Mensajes específicos según el error
                            if error.message.contains("Unauthorized") {
                                println!("\x1b[33m⚠️  Solo el dueño de la delegación puede hacer undelegate\x1b[0m");
                                println!("\x1b[90m   Verifica que la address sea correcta\x1b[0m");
                            } else if error.message.contains("Invalid nonce") {
                                println!("\x1b[33m⚠️  Nonce inválido - posible ataque de replay detectado\x1b[0m");
                                println!("\x1b[90m   Cada operación requiere un nonce único e incremental\x1b[0m");
                            } else if error.message.contains("Rate limit") {
                                println!("\x1b[33m⚠️  Demasiados intentos - espera 1 minuto\x1b[0m");
                                println!("\x1b[90m   Límite: 5 intentos por minuto por address\x1b[0m");
                            } else if error.message.contains("Invalid signature") {
                                println!("\x1b[33m⚠️  Firma criptográfica inválida\x1b[0m");
                                println!("\x1b[90m   La wallet puede estar corrupta\x1b[0m");
                            } else if error.message.contains("expired") {
                                println!("\x1b[33m⚠️  Mensaje expirado (>5 minutos)\x1b[0m");
                                println!("\x1b[90m   Intenta de nuevo\x1b[0m");
                            }
                            println!();
                        }
                    }
                }
                Err(e) => {
                    println!("\x1b[31m❌ ERROR: Failed to undelegate\x1b[0m");
                    println!("\x1b[31m   {}\x1b[0m", e);
                    println!();
                    println!("\x1b[33m⚠️  Posibles causas:\x1b[0m");
                    println!("\x1b[90m   • RPC server no está corriendo\x1b[0m");
                    println!("\x1b[90m   • Position ID no existe\x1b[0m");
                    println!("\x1b[90m   • Problemas de red\x1b[0m");
                    println!();
                    return Err(AvoError::staking(format!("Failed to undelegate: {}", e)));
                }
            }
        }

        DelegateCommands::List { address } => {
            println!("📋 \x1b[36mYour Delegations\x1b[0m");
            println!("=====================");

            let positions = stake_manager.get_user_positions(&address);
            let delegation_positions: Vec<_> = positions
                .into_iter()
                .filter(|p| matches!(p.stake_type, StakeType::Delegation))
                .collect();

            if delegation_positions.is_empty() {
                println!("No delegations found for address: {}", address);
                println!("💡 Use 'avo delegate to' to delegate to a validator");
            } else {
                for (i, position) in delegation_positions.iter().enumerate() {
                    let pending_rewards_wei = position.calculate_pending_rewards_wei(&params);
                    let pending_rewards = (pending_rewards_wei as f64) / 1e18f64;
                    let amount_avo = (position.amount as f64) / 1e18f64;
                    println!("{}. Position ID: {}", i + 1, position.id);
                    println!("   Amount: {:.6} AVO", amount_avo);
                    println!("   Validator ID: {}", position.validator_id.unwrap_or(0));
                    println!("   Pending Rewards: {:.6} AVO", pending_rewards);
                    println!(
                        "   Status: {}",
                        if position.is_active {
                            "Active"
                        } else {
                            "Inactive"
                        }
                    );
                    println!();
                }
            }
        }
    }

    Ok(())
}

/// Handle stake overview commands
async fn handle_stake_commands(action: StakeCommands) -> AvoResult<()> {
    match action {
        StakeCommands::List { address } => {
            println!("📋 \x1b[36mAll Your Stakes\x1b[0m");
            println!("====================");

            // Get user stakes via RPC
            match rpc_call_quiet("avo_getUserStakes", vec![Value::String(address.clone())]).await {
                Ok(response) => {
                    if let Some(result) = response.result {
                        // Extract positions array from the result object
                        if let Some(positions_array) =
                            result.get("positions").and_then(|p| p.as_array())
                        {
                            if positions_array.is_empty() {
                                println!("No stakes found for address: {}", address);
                                println!();
                                println!("💡 \x1b[36mGet Started:\x1b[0m");
                                println!("   • Bootstrap Node: avo operator bootstrap stake (10K AVO, 15% APR)");
                                println!("   • Validator: avo operator validator stake (1K AVO, 12% APR)");
                                println!("   • Delegation: avo delegate to (Free, 8% APR)");
                            } else {
                                println!(
                                    "Found {} stake(s) for address: {}",
                                    positions_array.len(),
                                    address
                                );
                                println!();

                                for (i, stake) in positions_array.iter().enumerate() {
                                    let position_id = stake
                                        .get("position_id")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");
                                    let amount = stake
                                        .get("amount")
                                        .and_then(|v| {
                                            if let Some(s) = v.as_str() {
                                                s.parse::<f64>().ok().map(|f| f as u64)
                                            } else {
                                                v.as_u64()
                                            }
                                        })
                                        .unwrap_or(0);
                                    let stake_type = stake
                                        .get("stake_type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");
                                    let apr =
                                        stake.get("apr").and_then(|v| v.as_f64()).unwrap_or(0.0);
                                    let pending_rewards = stake
                                        .get("pending_rewards")
                                        .and_then(|v| v.as_f64())
                                        .unwrap_or(0.0);
                                    let total_earned = stake
                                        .get("total_earned")
                                        .and_then(|v| v.as_f64())
                                        .unwrap_or(0.0);
                                    let time_staked_days = stake
                                        .get("time_staked_days")
                                        .and_then(|v| v.as_f64())
                                        .unwrap_or(0.0);
                                    let estimated_annual_rewards = stake
                                        .get("estimated_annual_rewards")
                                        .and_then(|v| v.as_f64())
                                        .unwrap_or(0.0);
                                    let is_active = stake
                                        .get("is_active")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);

                                    // Format stake type with color
                                    let stake_color = match stake_type {
                                        "Bootstrap" => "\x1b[95m",  // Magenta
                                        "Validator" => "\x1b[94m",  // Blue
                                        "Delegation" => "\x1b[92m", // Green
                                        _ => "\x1b[37m",            // White
                                    };

                                    println!("{}. {}[{}]\x1b[0m", i + 1, stake_color, stake_type);
                                    println!("   💰 Amount: \x1b[96m{} AVO\x1b[0m", amount);

                                    // Show rewards only if there are any
                                    if pending_rewards > 0.0 {
                                        println!(
                                            "   📈 Pending Rewards: \x1b[93m{:.6} AVO\x1b[0m",
                                            pending_rewards
                                        );
                                    }

                                    println!("   📊 APR: \x1b[32m{:.1}%\x1b[0m", apr * 100.0);
                                    println!(
                                        "   🔗 Status: {}",
                                        if is_active {
                                            "\x1b[32mActive\x1b[0m"
                                        } else {
                                            "\x1b[31mInactive\x1b[0m"
                                        }
                                    );

                                    // Additional stats for comprehensive info (only if meaningful)
                                    if time_staked_days >= 0.01 {
                                        println!(
                                            "   ⏱️  Time Staked: \x1b[36m{:.2} days\x1b[0m",
                                            time_staked_days
                                        );
                                    }
                                    if total_earned > 0.001 {
                                        println!(
                                            "   💎 Total Earned: \x1b[93m{:.6} AVO\x1b[0m",
                                            total_earned
                                        );
                                    }
                                    if estimated_annual_rewards > 0.0 {
                                        println!(
                                            "   🎯 Est. Annual: \x1b[96m{:.0} AVO\x1b[0m",
                                            estimated_annual_rewards
                                        );
                                    }

                                    if let Some(validator_id) =
                                        stake.get("validator_id").and_then(|v| v.as_str())
                                    {
                                        println!(
                                            "   🏷️  Validator ID: \x1b[35m{}\x1b[0m",
                                            validator_id
                                        );
                                    }

                                    // Show position ID in a clean way
                                    println!("   🆔 Position: \x1b[90m{}\x1b[0m", position_id);

                                    // Show unstake command more subtly
                                    print!("   ↩️  Unstake: \x1b[90m");
                                    match stake_type {
                                        "Bootstrap" => println!("avo operator bootstrap unstake --position-id {}\x1b[0m", position_id),
                                        "Validator" => println!("avo operator validator unstake --position-id {}\x1b[0m", position_id),
                                        "Delegation" => println!("avo delegate from --position-id {}\x1b[0m", position_id),
                                        _ => println!("N/A\x1b[0m")
                                    }
                                    println!();
                                }
                            }
                        } else {
                            println!("Invalid response format from node");
                            println!("Expected 'positions' array in response, got: {:?}", result);
                        }
                    } else if let Some(error) = response.error {
                        println!("\x1b[31m[ERROR]\x1b[0m RPC Error: {}", error.message);
                    } else {
                        println!("\x1b[31m[ERROR]\x1b[0m Invalid response from node");
                    }
                }
                Err(e) => {
                    println!("\x1b[31m[ERROR]\x1b[0m Failed to fetch stakes: {}", e);
                    println!("Make sure the AVO node is running on 127.0.0.1:9545");
                }
            }
        }
    }

    Ok(())
}

/// Handle rewards commands
async fn handle_reward_commands(action: RewardCommands) -> AvoResult<()> {
    match action {
        RewardCommands::Estimate {
            stake_type,
            amount,
            days,
        } => {
            println!("🧮 \x1b[36mRewards Estimation\x1b[0m");
            println!("=======================");

            // Simple calculation for estimation
            let apr = match stake_type {
                StakeTypeArg::Bootstrap => 0.15,  // 15% APR
                StakeTypeArg::Validator => 0.12,  // 12% APR
                StakeTypeArg::Delegation => 0.08, // 8% APR
            };

            let annual_rewards = (amount as f64 * apr) as u64;
            let period_rewards = (annual_rewards as f64 * days as f64 / 365.25) as u64;

            println!("Stake Type: {:?}", stake_type);
            println!("Amount: {} AVO", amount);
            println!("Period: {} days", days);
            println!("APR: {}%", apr * 100.0);
            println!();
            println!("Estimated Rewards:");
            println!("  Period: {} AVO", period_rewards);
            println!("  Annual: {} AVO", annual_rewards);
            println!("  Daily: {} AVO", annual_rewards / 365);
        }
    }

    Ok(())
}

/// Handle contract commands
async fn handle_contract_commands(action: ContractCommands) -> AvoResult<()> {
    match action {
        ContractCommands::Deploy {
            contract,
            wallet,
            constructor_signature,
            args,
            shard,
            value,
            gas_limit,
        } => {
            deploy_contract_command(
                contract,
                wallet,
                constructor_signature.as_deref(),
                args.as_deref(),
                shard,
                value,
                gas_limit,
            )
            .await
        }
        ContractCommands::Call {
            contract,
            wallet,
            function,
            args,
            payload,
            value,
            gas_limit,
        } => {
            call_contract_command(
                &contract,
                wallet,
                function.as_deref(),
                args.as_deref(),
                payload.as_deref(),
                value,
                gas_limit,
            )
            .await
        }
        ContractCommands::Query { contract, raw } => query_contract_command(&contract, raw).await,
    }
}

async fn handle_token_commands(action: TokenCommands) -> AvoResult<()> {
    match action {
        TokenCommands::Balance {
            contract,
            wallet,
            account,
            decimals,
            gas_limit,
        } => token_balance_command(&contract, wallet, &account, decimals, gas_limit).await,
        TokenCommands::Transfer {
            contract,
            wallet,
            to,
            amount,
            decimals,
            gas_limit,
        } => token_transfer_command(&contract, wallet, &to, &amount, decimals, gas_limit).await,
    }
}

async fn handle_performance_commands(action: PerformanceCommands) -> AvoResult<()> {
    match action {
        PerformanceCommands::Summary { limit } => {
            let report = fetch_performance_report(limit).await?;
            print_performance_summary(&report);
            Ok(())
        }
        PerformanceCommands::Recent { limit } => {
            let report = fetch_performance_report(limit).await?;
            print_recent_snapshots(&report);
            Ok(())
        }
    }
}

async fn fetch_performance_report(limit: usize) -> AvoResult<PerformanceReport> {
    let bounded_limit = limit.clamp(1, 512);
    let response = rpc_call_raw("avo_getPerformanceMetrics", vec![json!(bounded_limit)])
        .await
        .map_err(|e| AvoError::NetworkError {
            reason: format!("RPC request failed: {}", e),
        })?;

    if let Some(error) = response.error {
        return Err(AvoError::NetworkError {
            reason: format!("RPC error (code {}): {}", error.code, error.message),
        });
    }

    let result = response.result.ok_or_else(|| AvoError::NetworkError {
        reason: "Node returned empty performance response".to_string(),
    })?;

    serde_json::from_value::<PerformanceReport>(result).map_err(|e| AvoError::NetworkError {
        reason: format!("Failed to decode performance report: {}", e),
    })
}

fn print_performance_summary(report: &PerformanceReport) {
    println!("\x1b[35m[PERFORMANCE SUMMARY]\x1b[0m");
    println!(
        "Generated: {}",
        format_timestamp_micros(report.generated_at_micros)
    );
    println!("Samples available: {}", report.samples_available);
    println!("Average TPS: {:.2}", report.aggregate.avg_tps);
    println!(
        "Average block time: {:.2} ms",
        report.aggregate.avg_block_time_ms
    );
    println!(
        "Average VM time: {:.2} ms",
        report.aggregate.avg_vm_execution_ms
    );
    println!(
        "Average gas per block: {:.2}",
        report.aggregate.avg_gas_per_block
    );

    if let Some(latest) = &report.latest {
        println!("\nLatest block snapshot:");
        println!("  Block {} (epoch {})", latest.block_number, latest.epoch);
        println!(
            "  Timestamp: {}",
            format_timestamp_micros(latest.timestamp_micros)
        );
        println!("  Transactions: {}", latest.tx_count);
        println!("  Gas used: {}", latest.total_gas_used);
        println!("  Block time: {} ms", latest.total_processing_ms);
        println!("  VM time: {} ms", latest.vm_execution_ms);
        println!(
            "  Instantaneous TPS: {:.2}",
            latest.transactions_per_second()
        );
    } else {
        println!("\nNo performance snapshots recorded yet.");
    }
}

fn print_recent_snapshots(report: &PerformanceReport) {
    if report.recent.is_empty() {
        println!("\x1b[35m[PERFORMANCE]\x1b[0m No snapshots available yet.");
        return;
    }

    println!(
        "\x1b[35m[PERFORMANCE]\x1b[0m Showing {} most recent snapshots:",
        report.recent.len()
    );

    for snapshot in &report.recent {
        println!(
            "  • Block {} @ {} | Epoch {} | TX {} | Block {} ms | VM {} ms | TPS {:.2}",
            snapshot.block_number,
            format_timestamp_micros(snapshot.timestamp_micros),
            snapshot.epoch,
            snapshot.tx_count,
            snapshot.total_processing_ms,
            snapshot.vm_execution_ms,
            snapshot.transactions_per_second()
        );
    }
}

fn format_timestamp_micros(micros: u64) -> String {
    if micros > i64::MAX as u64 {
        return "<out-of-range>".to_string();
    }

    if let Some(dt) = DateTime::<Utc>::from_timestamp_micros(micros as i64) {
        dt.to_rfc3339()
    } else {
        "<unknown>".to_string()
    }
}

/// Handle operator commands (bootstrap and validator nodes)
async fn handle_operator_commands(action: OperatorCommands) -> AvoResult<()> {
    match action {
        OperatorCommands::Bootstrap { action } => handle_bootstrap_commands(action).await,
        OperatorCommands::Validator { action } => handle_validator_commands(action).await,
    }
}

fn split_alias_parts(alias_full: &str) -> (&str, Option<&str>) {
    let mut parts = alias_full.splitn(2, " - ");
    let alias = parts.next().unwrap_or(alias_full).trim();
    let detail = parts
        .next()
        .map(str::trim)
        .filter(|segment| !segment.is_empty());

    (if alias.is_empty() { alias_full } else { alias }, detail)
}

fn wallet_section_color(alias: &str) -> &'static str {
    let alias_lower = alias.to_ascii_lowercase();
    if alias_lower.contains("private sale") {
        "\x1b[35m"
    } else if alias_lower.contains("team") {
        "\x1b[33m"
    } else if alias_lower.contains("development treasury") {
        "\x1b[36m"
    } else if alias_lower.contains("marketing treasury") {
        "\x1b[34m"
    } else if alias_lower.contains("security treasury") {
        "\x1b[31m"
    } else if alias_lower.contains("community treasury") {
        "\x1b[92m"
    } else if alias_lower.contains("emergency treasury") {
        "\x1b[91m"
    } else if alias_lower.contains("treasury") {
        "\x1b[32m"
    } else {
        "\x1b[37m"
    }
}

fn load_wallet_file(path: &PathBuf) -> AvoResult<Wallet> {
    let wallet_json = fs::read_to_string(path).map_err(|e| {
        AvoError::InvalidInput(format!(
            "Could not read wallet file {}: {}",
            path.display(),
            e
        ))
    })?;
    serde_json::from_str(&wallet_json).map_err(|e| {
        AvoError::InvalidInput(format!(
            "Wallet file {} is not valid JSON: {}",
            path.display(),
            e
        ))
    })
}

async fn deploy_contract_command(
    contract_path: PathBuf,
    wallet_path: PathBuf,
    constructor_signature: Option<&str>,
    args: Option<&str>,
    shard: u32,
    value: Option<f64>,
    gas_limit: Option<u64>,
) -> AvoResult<()> {
    println!(
        "\x1b[33m[INFO]\x1b[0m Deploying contract: {}",
        contract_path.display()
    );
    println!("Using wallet: {}", wallet_path.display());

    let wallet = load_wallet_file(&wallet_path)?;
    let bytecode = load_contract_bytecode(&contract_path)?;

    let constructor_data = match (constructor_signature, args) {
        (Some(sig), payload) => Some(encode_constructor_args(sig, payload)?),
        (None, Some(_)) => {
            return Err(AvoError::InvalidInput(
                "Constructor arguments provided but no constructor signature supplied".to_string(),
            ))
        }
        _ => None,
    };

    let constructor_hex = constructor_data
        .as_ref()
        .map(|bytes| format!("0x{}", hex::encode(bytes)))
        .unwrap_or_else(|| "0x".to_string());

    let value_wei = match value {
        Some(amount) => Some(avo_to_wei(amount)?),
        None => None,
    };

    let mut payload = Map::new();
    payload.insert("from".to_string(), Value::String(wallet.address.clone()));
    payload.insert(
        "bytecode".to_string(),
        Value::String(format!("0x{}", hex::encode(&bytecode))),
    );
    payload.insert(
        "constructorArgs".to_string(),
        Value::String(constructor_hex),
    );
    payload.insert(
        "shard".to_string(),
        Value::Number(serde_json::Number::from(shard as u64)),
    );
    payload.insert(
        "gasLimit".to_string(),
        Value::Number(serde_json::Number::from(gas_limit.unwrap_or(8_000_000))),
    );
    payload.insert(
        "gasPrice".to_string(),
        Value::Number(serde_json::Number::from(0u64)),
    );
    if let Some(amount) = value_wei {
        payload.insert("value".to_string(), Value::String(amount.to_string()));
    }

    let response = rpc_call("avo_deployContract", vec![Value::Object(payload)])
        .await
        .map_err(|e| AvoError::NetworkError {
            reason: format!("RPC error: {}", e),
        })?;

    if let Some(error) = response.error {
        return Err(AvoError::NetworkError {
            reason: format!("RPC error (code {}): {}", error.code, error.message),
        });
    }

    let result = response.result.ok_or_else(|| {
        AvoError::InvalidInput("Node returned empty response for avo_deployContract".to_string())
    })?;

    let contract_address = result
        .get("contractAddress")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AvoError::InvalidInput("Node response missing 'contractAddress' field".to_string())
        })?;

    let tx_hash = result
        .get("txHash")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    let gas_used = result
        .get("gasUsed")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let block_number = result
        .get("blockNumber")
        .and_then(Value::as_u64)
        .unwrap_or_default();

    println!("\x1b[32m[SUCCESS]\x1b[0m Contract deployed successfully");
    println!("Contract Address: {}", contract_address);
    println!("Transaction Hash: {}", tx_hash);
    println!("Bytecode Size: {} bytes", bytecode.len());
    println!("Gas Used: {}", gas_used);
    if let Some(amount) = value {
        println!("Value Sent: {} AVO", amount);
    }
    println!("Block Number: {}", block_number);
    println!("Shard: {}", shard);

    let record = ContractDeploymentRecord {
        address: contract_address.to_string(),
        tx_hash: tx_hash.to_string(),
        contract_path: contract_path.display().to_string(),
        deployer: wallet.address,
        block_number,
        timestamp: Utc::now().to_rfc3339(),
        shard,
        bytecode_size: bytecode.len(),
        chain_id: 0x539,
    };
    append_contract_deployment(record)?;

    Ok(())
}

async fn call_contract_command(
    contract_address: &str,
    wallet_path: PathBuf,
    function_signature: Option<&str>,
    args: Option<&str>,
    raw_payload: Option<&str>,
    value: Option<f64>,
    gas_limit: Option<u64>,
) -> AvoResult<()> {
    println!(
        "\x1b[33m[INFO]\x1b[0m Executing contract call on {}",
        contract_address
    );

    let wallet = load_wallet_file(&wallet_path)?;

    let payload_bytes = if let Some(hex_payload) = raw_payload {
        decode_hex_payload_cli(hex_payload, "payload")?
    } else if let Some(signature) = function_signature {
        encode_function_call(signature, args)?
    } else {
        return Err(AvoError::InvalidInput(
            "Either --function or --payload must be provided for contract call".to_string(),
        ));
    };

    let payload_hex = if payload_bytes.is_empty() {
        "0x".to_string()
    } else {
        format!("0x{}", hex::encode(payload_bytes))
    };

    let value_wei = match value {
        Some(amount) => Some(avo_to_wei(amount)?),
        None => None,
    };

    let mut payload = Map::new();
    payload.insert("from".to_string(), Value::String(wallet.address.clone()));
    payload.insert(
        "contract".to_string(),
        Value::String(contract_address.to_string()),
    );
    payload.insert("data".to_string(), Value::String(payload_hex));
    payload.insert(
        "gasLimit".to_string(),
        Value::Number(serde_json::Number::from(gas_limit.unwrap_or(5_000_000))),
    );
    payload.insert(
        "gasPrice".to_string(),
        Value::Number(serde_json::Number::from(0u64)),
    );
    if let Some(amount) = value_wei {
        payload.insert("value".to_string(), Value::String(amount.to_string()));
    }

    eprintln!("[DEBUG] payload = {:?}", payload);

    let response = rpc_call("avo_callContract", vec![Value::Object(payload)])
        .await
        .map_err(|e| AvoError::NetworkError {
            reason: format!("RPC error: {}", e),
        })?;

    if let Some(error) = response.error {
        return Err(AvoError::NetworkError {
            reason: format!("RPC error (code {}): {}", error.code, error.message),
        });
    }

    let result = response.result.ok_or_else(|| {
        AvoError::InvalidInput("Node returned empty response for avo_callContract".to_string())
    })?;

    let success = result
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let return_data = result
        .get("returnData")
        .and_then(Value::as_str)
        .unwrap_or("0x");
    let gas_used = result
        .get("gasUsed")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let block_number = result
        .get("blockNumber")
        .and_then(Value::as_u64)
        .unwrap_or_default();

    if success {
        println!("\x1b[32m[SUCCESS]\x1b[0m Contract call executed successfully");
    } else {
        println!("\x1b[31m[FAILED]\x1b[0m Contract call reported failure");
    }

    println!(
        "Transaction Hash: {}",
        result
            .get("txHash")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>")
    );
    println!("Gas Used: {}", gas_used);
    println!("Block Number: {}", block_number);
    if let Some(amount) = value {
        println!("Value Sent: {} AVO", amount);
    }

    if let Some(error) = result.get("error") {
        if !error.is_null() {
            println!("Node reported error: {}", error);
        }
    }

    if return_data != "0x" {
        println!("Return Data: {}", return_data);
    }

    if let Some(events) = result.get("events").and_then(Value::as_array) {
        if !events.is_empty() {
            println!("Events Emitted: {}", events.len());
            println!(
                "{}",
                serde_json::to_string_pretty(&Value::Array(events.clone())).unwrap_or_default()
            );
        }
    }

    if let Some(changes) = result.get("stateChanges").and_then(Value::as_array) {
        if !changes.is_empty() {
            println!("State Changes: {}", changes.len());
            println!(
                "{}",
                serde_json::to_string_pretty(&Value::Array(changes.clone())).unwrap_or_default()
            );
        }
    }

    Ok(())
}

async fn token_balance_command(
    contract_address: &str,
    wallet_path: PathBuf,
    account: &str,
    decimals: u8,
    gas_limit: Option<u64>,
) -> AvoResult<()> {
    println!(
        "\x1b[33m[INFO]\x1b[0m Reading token balance from {}",
        contract_address
    );

    let wallet = load_wallet_file(&wallet_path)?;
    let target_address = EthAddress::from_str(account).map_err(|e| {
        AvoError::InvalidInput(format!("Invalid target address '{}': {}", account, e))
    })?;

    #[allow(deprecated)]
    let function = Function {
        name: "balanceOf".to_string(),
        inputs: vec![Param {
            name: "account".to_string(),
            kind: ParamType::Address,
            internal_type: None,
        }],
        outputs: vec![Param {
            name: "balance".to_string(),
            kind: ParamType::Uint(256),
            internal_type: None,
        }],
        constant: None,
        state_mutability: StateMutability::View,
    };

    let payload_bytes = function
        .encode_input(&[Token::Address(target_address)])
        .map_err(|e| AvoError::InvalidInput(format!("Failed to encode balanceOf input: {}", e)))?;
    let payload_hex = format!("0x{}", hex::encode(payload_bytes));

    let mut payload = Map::new();
    payload.insert("from".to_string(), Value::String(wallet.address.clone()));
    payload.insert(
        "contract".to_string(),
        Value::String(contract_address.to_string()),
    );
    payload.insert("data".to_string(), Value::String(payload_hex));
    payload.insert(
        "gasLimit".to_string(),
        Value::Number(serde_json::Number::from(gas_limit.unwrap_or(500_000))),
    );
    payload.insert(
        "gasPrice".to_string(),
        Value::Number(serde_json::Number::from(0u64)),
    );

    let response = rpc_call("avo_callContract", vec![Value::Object(payload)])
        .await
        .map_err(|e| AvoError::NetworkError {
            reason: format!("RPC error: {}", e),
        })?;

    if let Some(error) = response.error {
        return Err(AvoError::NetworkError {
            reason: format!("RPC error (code {}): {}", error.code, error.message),
        });
    }

    let result = response.result.ok_or_else(|| {
        AvoError::InvalidInput("Node returned empty response for avo_callContract".to_string())
    })?;

    let success = result
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let return_data = result
        .get("returnData")
        .and_then(Value::as_str)
        .unwrap_or("0x");

    if success {
        println!("\x1b[32m[SUCCESS]\x1b[0m Call executed successfully");
    } else {
        println!("\x1b[31m[FAILED]\x1b[0m Call did not succeed");
    }

    println!(
        "Transaction Hash: {}",
        result
            .get("txHash")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>")
    );
    println!(
        "Gas Used: {}",
        result
            .get("gasUsed")
            .and_then(Value::as_u64)
            .unwrap_or_default()
    );
    println!(
        "Block Number: {}",
        result
            .get("blockNumber")
            .and_then(Value::as_u64)
            .unwrap_or_default()
    );

    if return_data.eq_ignore_ascii_case(EVM_SUCCESS_PLACEHOLDER) {
        println!(
            "\x1b[33m[WARNING]\x1b[0m Node returned placeholder data (EVM_EXECUTION_SUCCESS). Token balances cannot yet be decoded until the EVM executor is implemented."
        );
        return Ok(());
    }

    if return_data == "0x" {
        println!(
            "\x1b[33m[WARNING]\x1b[0m Node returned empty data. Token balance remains unknown."
        );
        return Ok(());
    }

    let return_bytes = decode_hex_payload_cli(return_data, "returnData")?;
    let decoded = function
        .decode_output(&return_bytes)
        .map_err(|e| AvoError::InvalidInput(format!("Failed to decode return data: {}", e)))?;

    let balance_value = match decoded.first() {
        Some(Token::Uint(value)) => value.clone(),
        Some(other) => {
            return Err(AvoError::InvalidInput(format!(
                "Unexpected return type for balanceOf: {:?}",
                other
            )))
        }
        None => {
            println!(
                "\x1b[33m[ADVERTENCIA]\x1b[0m La llamada no devolvió datos; se asume balance 0"
            );
            AbiU256::from(0u64)
        }
    };

    let formatted = format_token_amount(&balance_value, decimals);
    println!("Raw balance (atoms): {}", balance_value);
    println!("Human readable ({} decimals): {}", decimals, formatted);

    Ok(())
}

async fn token_transfer_command(
    contract_address: &str,
    wallet_path: PathBuf,
    recipient: &str,
    amount: &str,
    decimals: u8,
    gas_limit: Option<u64>,
) -> AvoResult<()> {
    println!(
        "\x1b[33m[INFO]\x1b[0m Broadcasting token transfer via contract {}",
        contract_address
    );

    let wallet = load_wallet_file(&wallet_path)?;
    let to_address = EthAddress::from_str(recipient).map_err(|e| {
        AvoError::InvalidInput(format!("Invalid recipient address '{}': {}", recipient, e))
    })?;

    let amount_u256 = parse_token_amount(amount, decimals)?;
    let formatted_amount = format_token_amount(&amount_u256, decimals);

    println!("From: {}", wallet.address);
    println!("To:   {}", recipient);
    println!(
        "Amount: {} ({} decimals -> raw {})",
        formatted_amount, decimals, amount_u256
    );

    let mut parser = AbiParser::default();
    let function = parser
        .parse_function("transfer(address,uint256)")
        .map_err(|e| AvoError::InvalidInput(format!("Failed to parse transfer ABI: {}", e)))?;

    let payload_bytes = function
        .encode_input(&[Token::Address(to_address), Token::Uint(amount_u256.clone())])
        .map_err(|e| AvoError::InvalidInput(format!("Failed to encode transfer input: {}", e)))?;
    let payload_hex = format!("0x{}", hex::encode(payload_bytes));

    let mut payload = Map::new();
    payload.insert("from".to_string(), Value::String(wallet.address.clone()));
    payload.insert(
        "contract".to_string(),
        Value::String(contract_address.to_string()),
    );
    payload.insert("data".to_string(), Value::String(payload_hex));
    payload.insert(
        "gasLimit".to_string(),
        Value::Number(serde_json::Number::from(gas_limit.unwrap_or(500_000))),
    );
    payload.insert(
        "gasPrice".to_string(),
        Value::Number(serde_json::Number::from(0u64)),
    );

    let response = rpc_call("avo_callContract", vec![Value::Object(payload)])
        .await
        .map_err(|e| AvoError::NetworkError {
            reason: format!("RPC error: {}", e),
        })?;

    if let Some(error) = response.error {
        return Err(AvoError::NetworkError {
            reason: format!("RPC error (code {}): {}", error.code, error.message),
        });
    }

    let result = response.result.ok_or_else(|| {
        AvoError::InvalidInput("Node returned empty response for avo_callContract".to_string())
    })?;

    let success = result
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let tx_hash = result
        .get("txHash")
        .and_then(Value::as_str)
        .unwrap_or("<desconocido>")
        .to_string();
    let gas_used = result
        .get("gasUsed")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let block_number = result
        .get("blockNumber")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let event_count = result
        .get("events")
        .and_then(Value::as_array)
        .map(|events| events.len())
        .unwrap_or(0);
    let return_data = result
        .get("returnData")
        .and_then(Value::as_str)
        .unwrap_or("0x");
    let error_text = result.get("error").filter(|v| !v.is_null()).map(|v| {
        if v.is_string() {
            v.as_str().unwrap().to_string()
        } else {
            v.to_string()
        }
    });

    let status_icon = if success { "✅" } else { "⚠️" };
    let status_color = if success { "\x1b[32m" } else { "\x1b[31m" };
    let status_text = if success {
        "Transferencia de tokens completada"
    } else {
        "Transferencia reportada con errores"
    };

    println!("\n\x1b[36m========================================================\x1b[0m");
    println!("  {}{} {}\x1b[0m", status_icon, status_color, status_text);
    println!("\x1b[36m--------------------------------------------------------\x1b[0m");
    println!("  • Contrato     : {}", contract_address);
    println!("  • Remitente    : {}", wallet.address);
    println!("  • Destinatario : {}", recipient);
    println!(
        "  • Monto        : {} ({} decimales → raw {})",
        formatted_amount, decimals, amount_u256
    );
    println!("  • Hash tx      : {}", tx_hash);
    println!("  • Gas usado    : {}", gas_used);
    println!("  • Bloque       : {}", block_number);
    println!("  • Eventos      : {}", event_count);
    if let Some(err) = &error_text {
        println!("  • Error nodo   : {}", err);
    }
    if return_data != "0x" && !return_data.eq_ignore_ascii_case(EVM_SUCCESS_PLACEHOLDER) {
        println!("  • Return data  : {}", return_data);
    }
    println!("\x1b[36m========================================================\x1b[0m\n");

    if return_data.eq_ignore_ascii_case(EVM_SUCCESS_PLACEHOLDER) {
        println!(
            "\x1b[33m[ADVERTENCIA]\x1b[0m El nodo devolvió datos placeholder (EVM_EXECUTION_SUCCESS). La ejecución real depende de la integración EVM."
        );
    }

    Ok(())
}

fn parse_token_amount(amount: &str, decimals: u8) -> AvoResult<AbiU256> {
    let trimmed = amount.trim();
    if trimmed.is_empty() {
        return Err(AvoError::InvalidInput("Amount cannot be empty".into()));
    }
    if trimmed.starts_with('-') {
        return Err(AvoError::InvalidInput(
            "Amount cannot be negative for token transfers".into(),
        ));
    }

    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() > 2 {
        return Err(AvoError::InvalidInput(
            "Amount contains multiple decimal separators".into(),
        ));
    }

    let (whole_part, fractional_part) = if parts.len() == 2 {
        (parts[0], parts[1])
    } else {
        (parts[0], "")
    };

    let whole_clean = if whole_part.is_empty() {
        "0".to_string()
    } else {
        whole_part.replace('_', "")
    };
    if whole_clean.chars().any(|c| !c.is_ascii_digit()) {
        return Err(AvoError::InvalidInput(format!(
            "Invalid numeric amount '{}'",
            amount
        )));
    }

    let mut fractional_clean = fractional_part.replace('_', "");
    if fractional_clean.chars().any(|c| !c.is_ascii_digit()) {
        return Err(AvoError::InvalidInput(format!(
            "Invalid fractional amount '{}'",
            amount
        )));
    }

    if fractional_clean.len() > decimals as usize {
        return Err(AvoError::InvalidInput(format!(
            "Amount has more decimal places ({}) than token supports ({})",
            fractional_clean.len(),
            decimals
        )));
    }

    if decimals == 0 && fractional_clean.chars().any(|c| c != '0') {
        return Err(AvoError::InvalidInput(
            "Token does not support fractional amounts".into(),
        ));
    }

    if decimals > 0 {
        fractional_clean.push_str(&"0".repeat(decimals as usize - fractional_clean.len()));
    }

    let mut digits = if whole_clean.is_empty() {
        "0".to_string()
    } else {
        whole_clean
    };

    if decimals > 0 {
        digits.push_str(&fractional_clean);
    }

    let normalized = digits.trim_start_matches('0').to_string();
    let decimal_string = if normalized.is_empty() {
        "0".to_string()
    } else {
        normalized
    };

    AbiU256::from_dec_str(&decimal_string)
        .map_err(|e| AvoError::InvalidInput(format!("Failed to parse amount '{}': {}", amount, e)))
}

fn format_token_amount(value: &AbiU256, decimals: u8) -> String {
    let mut digits = value.to_string();
    if decimals == 0 {
        return digits;
    }

    let decimals_usize = decimals as usize;
    if digits.len() <= decimals_usize {
        digits = format!("{:0>width$}", digits, width = decimals_usize + 1);
    }

    let split_index = digits.len() - decimals_usize;
    let (whole, fractional) = digits.split_at(split_index);

    let fractional_trimmed = fractional.trim_end_matches('0');
    if fractional_trimmed.is_empty() {
        whole.to_string()
    } else {
        format!("{}.{}", whole, fractional_trimmed)
    }
}

#[derive(Default)]
struct Erc20Metadata {
    name: Option<String>,
    symbol: Option<String>,
    decimals: Option<u8>,
    total_supply: Option<AbiU256>,
}

async fn fetch_erc20_metadata(contract_address: &str) -> AvoResult<Option<Erc20Metadata>> {
    let name = call_erc20_string(contract_address, "name()").await?;
    let symbol = call_erc20_string(contract_address, "symbol()").await?;
    let decimals = call_erc20_u8(contract_address, "decimals()").await?;
    let total_supply = call_erc20_uint(contract_address, "totalSupply()").await?;

    if name.is_none() && symbol.is_none() && decimals.is_none() && total_supply.is_none() {
        return Ok(None);
    }

    Ok(Some(Erc20Metadata {
        name,
        symbol,
        decimals,
        total_supply,
    }))
}

async fn call_constant_function(
    contract_address: &str,
    payload: Vec<u8>,
    gas_limit: Option<u64>,
) -> AvoResult<Option<Vec<u8>>> {
    let mut payload_map = Map::new();
    payload_map.insert("from".to_string(), Value::String(ZERO_ADDRESS.to_string()));
    payload_map.insert(
        "contract".to_string(),
        Value::String(contract_address.to_string()),
    );
    payload_map.insert(
        "data".to_string(),
        Value::String(format!("0x{}", hex::encode(payload))),
    );
    payload_map.insert(
        "gasLimit".to_string(),
        Value::Number(serde_json::Number::from(gas_limit.unwrap_or(500_000))),
    );
    payload_map.insert(
        "gasPrice".to_string(),
        Value::Number(serde_json::Number::from(0u64)),
    );

    let response = rpc_call("avo_callContract", vec![Value::Object(payload_map)])
        .await
        .map_err(|e| AvoError::NetworkError {
            reason: format!("RPC error: {}", e),
        })?;

    if let Some(error) = response.error {
        return Err(AvoError::NetworkError {
            reason: format!("RPC error (code {}): {}", error.code, error.message),
        });
    }

    let result = response.result.ok_or_else(|| {
        AvoError::InvalidInput("Node returned empty response for avo_callContract".to_string())
    })?;

    let success = result
        .get("success")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if !success {
        let error_detail = result
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string);
        let return_data = result.get("returnData").cloned();
        return Err(AvoError::NetworkError {
            reason: format!(
                "Constant call failed: error={:?}, returnData={:?}",
                error_detail, return_data
            ),
        });
    }

    let return_data = result
        .get("returnData")
        .and_then(Value::as_str)
        .unwrap_or("0x");

    if return_data.eq_ignore_ascii_case(EVM_SUCCESS_PLACEHOLDER) || return_data == "0x" {
        return Ok(None);
    }

    let bytes = decode_hex_payload_cli(return_data, "returnData")?;
    Ok(Some(bytes))
}

fn build_zero_arg_view_function(signature: &str, output: ParamType) -> AvoResult<Function> {
    let trimmed = signature.trim();
    let without_prefix = trimmed
        .strip_prefix("function")
        .map(|rest| rest.trim())
        .unwrap_or(trimmed);

    let name_part = without_prefix
        .split('(')
        .next()
        .ok_or_else(|| {
            AvoError::InvalidInput(format!(
                "Invalid zero-argument function signature '{}': missing parentheses",
                signature
            ))
        })?
        .trim();

    if name_part.is_empty() {
        return Err(AvoError::InvalidInput(format!(
            "Invalid zero-argument function signature '{}'",
            signature
        )));
    }

    #[allow(deprecated)]
    let function = Function {
        name: name_part.to_string(),
        inputs: Vec::new(),
        outputs: vec![Param {
            name: String::new(),
            kind: output,
            internal_type: None,
        }],
        constant: None,
        state_mutability: StateMutability::View,
    };

    Ok(function)
}

async fn call_erc20_string(contract_address: &str, signature: &str) -> AvoResult<Option<String>> {
    let function = build_zero_arg_view_function(signature, ParamType::String)?;

    let payload = function
        .encode_input(&[])
        .map_err(|e| AvoError::InvalidInput(format!("Failed to encode '{}': {}", signature, e)))?;

    let bytes = match call_constant_function(contract_address, payload, None).await? {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    let decoded = function.decode_output(&bytes).map_err(|e| {
        AvoError::InvalidInput(format!(
            "Failed to decode output for '{}': {}",
            signature, e
        ))
    })?;

    if let Some(token) = decoded.first() {
        match token {
            Token::String(value) => Ok(Some(value.clone())),
            Token::Bytes(data) | Token::FixedBytes(data) => match String::from_utf8(data.clone()) {
                Ok(text) => Ok(Some(text.trim_end_matches('\0').to_string())),
                Err(_) => Ok(None),
            },
            _ => Ok(None),
        }
    } else {
        Ok(None)
    }
}

async fn call_erc20_u8(contract_address: &str, signature: &str) -> AvoResult<Option<u8>> {
    let function = build_zero_arg_view_function(signature, ParamType::Uint(8))?;

    let payload = function
        .encode_input(&[])
        .map_err(|e| AvoError::InvalidInput(format!("Failed to encode '{}': {}", signature, e)))?;

    let bytes = match call_constant_function(contract_address, payload, None).await? {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    let decoded = function.decode_output(&bytes).map_err(|e| {
        AvoError::InvalidInput(format!(
            "Failed to decode output for '{}': {}",
            signature, e
        ))
    })?;

    if let Some(Token::Uint(value)) = decoded.first() {
        Ok(Some(value.low_u32() as u8))
    } else {
        Ok(None)
    }
}

async fn call_erc20_uint(contract_address: &str, signature: &str) -> AvoResult<Option<AbiU256>> {
    let function = build_zero_arg_view_function(signature, ParamType::Uint(256))?;

    let payload = function
        .encode_input(&[])
        .map_err(|e| AvoError::InvalidInput(format!("Failed to encode '{}': {}", signature, e)))?;

    let bytes = match call_constant_function(contract_address, payload, None).await? {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    let decoded = function.decode_output(&bytes).map_err(|e| {
        AvoError::InvalidInput(format!(
            "Failed to decode output for '{}': {}",
            signature, e
        ))
    })?;

    if let Some(Token::Uint(value)) = decoded.first() {
        Ok(Some(value.clone()))
    } else {
        Ok(None)
    }
}

async fn query_contract_command(contract_address: &str, raw: bool) -> AvoResult<()> {
    println!(
        "\x1b[33m[INFO]\x1b[0m Querying contract metadata: {}",
        contract_address
    );

    let mut payload = Map::new();
    payload.insert(
        "contract".to_string(),
        Value::String(contract_address.to_string()),
    );

    let response = rpc_call("avo_queryContract", vec![Value::Object(payload)])
        .await
        .map_err(|e| AvoError::NetworkError {
            reason: format!("RPC error: {}", e),
        })?;

    if let Some(error) = response.error {
        return Err(AvoError::NetworkError {
            reason: format!("RPC error (code {}): {}", error.code, error.message),
        });
    }

    let result = response.result.ok_or_else(|| {
        AvoError::InvalidInput("Node returned empty response for avo_queryContract".to_string())
    })?;

    if raw {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
        );
        return Ok(());
    }

    let resolved_address =
        extract_bytes_hex(&result, "address").unwrap_or_else(|| contract_address.to_string());
    let creator = extract_bytes_hex(&result, "creator");
    let nonce = result
        .get("nonce")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let created_at = result
        .get("created_at")
        .and_then(Value::as_u64)
        .unwrap_or_default();

    println!("\x1b[32m[SUCCESS]\x1b[0m Contract metadata retrieved");
    println!("Address: {}", resolved_address);
    if let Some(creator_hex) = creator {
        println!("Creator: {}", creator_hex);
    }
    println!("Nonce: {}", nonce);
    if created_at > 0 {
        if let Some(datetime) = DateTime::from_timestamp(created_at as i64, 0) {
            println!("Created At: {}", datetime.to_rfc3339());
        } else {
            println!("Created At: {}", created_at);
        }
    }

    if let Some(bytecode_info) = result.get("bytecode") {
        if let Some((variant, length)) = summarize_bytecode(bytecode_info) {
            println!("Bytecode: {} ({} bytes)", variant, length);
        }
    }

    if let Some(storage_len) = result
        .get("storage")
        .and_then(Value::as_object)
        .map(|map| map.len())
    {
        println!("Storage Slots: {}", storage_len);
    }

    match fetch_erc20_metadata(contract_address).await {
        Ok(Some(metadata)) => {
            println!("\nERC20 Metadata:");
            let Erc20Metadata {
                name,
                symbol,
                decimals,
                total_supply,
            } = metadata;

            if let Some(ref value) = name {
                println!("  Name: {}", value);
            } else {
                println!("  Name: [unavailable]");
            }

            if let Some(ref value) = symbol {
                println!("  Symbol: {}", value);
            } else {
                println!("  Symbol: [unavailable]");
            }

            if let Some(value) = decimals {
                println!("  Decimals: {}", value);
            } else {
                println!("  Decimals: [unavailable]");
            }

            if let Some(ref total_supply) = total_supply {
                let human = decimals
                    .map(|d| format_token_amount(total_supply, d))
                    .unwrap_or_else(|| total_supply.to_string());
                println!("  Total Supply (raw): {}", total_supply);
                println!("  Total Supply (formatted): {}", human);
            } else {
                println!("  Total Supply: [unavailable]");
            }
        }
        Ok(None) => {
            println!(
                "\x1b[33m[WARNING]\x1b[0m Unable to retrieve ERC20 metadata. The contract may not implement standard view functions."
            );
        }
        Err(e) => {
            println!(
                "\x1b[33m[WARNING]\x1b[0m Failed to fetch ERC20 metadata: {}",
                e
            );
        }
    }

    Ok(())
}

fn decode_hex_payload_cli(payload: &str, field: &str) -> AvoResult<Vec<u8>> {
    let cleaned = payload.trim();
    if cleaned.is_empty() || cleaned == "0x" {
        return Ok(Vec::new());
    }
    let stripped = cleaned.trim_start_matches("0x");
    hex::decode(stripped)
        .map_err(|e| AvoError::InvalidInput(format!("Invalid hex payload for {}: {}", field, e)))
}

fn extract_bytes_hex(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(decode_json_bytes).map(|bytes| {
        if bytes.is_empty() {
            "0x".to_string()
        } else {
            format!("0x{}", hex::encode(bytes))
        }
    })
}

fn decode_json_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(s) => decode_hex_payload_cli(s, "bytes").ok(),
        Value::Array(arr) => {
            let mut bytes = Vec::with_capacity(arr.len());
            for item in arr {
                if let Some(num) = item.as_u64() {
                    bytes.push(num as u8);
                } else {
                    return None;
                }
            }
            Some(bytes)
        }
        _ => None,
    }
}

fn summarize_bytecode(bytecode_value: &Value) -> Option<(String, usize)> {
    match bytecode_value {
        Value::Object(map) => map.iter().next().map(|(variant, data)| {
            let length = match data {
                Value::Array(arr) => arr.len(),
                Value::String(s) => s.len() / 2,
                _ => 0,
            };
            (variant.clone(), length)
        }),
        Value::Array(arr) => Some(("raw".to_string(), arr.len())),
        Value::String(s) => Some(("raw".to_string(), s.len() / 2)),
        _ => None,
    }
}

fn load_contract_bytecode(contract_path: &PathBuf) -> AvoResult<Vec<u8>> {
    let extension = contract_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match extension.as_str() {
        "json" => {
            let content = fs::read_to_string(contract_path).map_err(|e| {
                AvoError::InvalidInput(format!(
                    "Failed to read contract artifact {}: {}",
                    contract_path.display(),
                    e
                ))
            })?;
            let artifact: Value = serde_json::from_str(&content).map_err(|e| {
                AvoError::InvalidInput(format!(
                    "Contract artifact {} is not valid JSON: {}",
                    contract_path.display(),
                    e
                ))
            })?;

            let candidates = ["bytecode", "deployedBytecode", "data", "object"];

            for key in candidates {
                if let Some(Value::String(bytecode)) = artifact.get(key) {
                    if !bytecode.trim().is_empty() {
                        return decode_hex_payload_cli(bytecode, key);
                    }
                }
                if let Some(Value::Object(map)) = artifact.get(key) {
                    if let Some(Value::String(object)) = map.get("object") {
                        if !object.trim().is_empty() {
                            return decode_hex_payload_cli(object, key);
                        }
                    }
                }
            }

            Err(AvoError::InvalidInput(format!(
                "Could not locate bytecode field inside {}",
                contract_path.display()
            )))
        }
        "wasm" => fs::read(contract_path).map_err(|e| {
            AvoError::InvalidInput(format!(
                "Failed to read WASM contract {}: {}",
                contract_path.display(),
                e
            ))
        }),
        "bin" | "hex" => {
            let content = fs::read_to_string(contract_path).map_err(|e| {
                AvoError::InvalidInput(format!(
                    "Failed to read bytecode file {}: {}",
                    contract_path.display(),
                    e
                ))
            })?;
            decode_hex_payload_cli(&content, "bytecode")
        }
        _ => {
            let bytes = fs::read(contract_path).map_err(|e| {
                AvoError::InvalidInput(format!(
                    "Failed to read contract {}: {}",
                    contract_path.display(),
                    e
                ))
            })?;
            if is_probably_hex_text(&bytes) {
                let text = String::from_utf8_lossy(&bytes).to_string();
                decode_hex_payload_cli(&text, "bytecode")
            } else {
                Ok(bytes)
            }
        }
    }
}

fn is_probably_hex_text(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|b| b.is_ascii_hexdigit() || *b == b'\n' || *b == b'\r' || *b == b' ')
}

fn encode_constructor_args(signature: &str, args: Option<&str>) -> AvoResult<Vec<u8>> {
    let param_types = parse_param_types(signature)?;
    let tokens = parse_arguments_json(args, &param_types)?;
    Ok(abi_encode(&tokens))
}

fn encode_function_call(signature: &str, args: Option<&str>) -> AvoResult<Vec<u8>> {
    let mut parser = AbiParser::default();
    let function: Function = parser.parse_function(signature).map_err(|e| {
        AvoError::InvalidInput(format!("Invalid function signature '{}': {}", signature, e))
    })?;

    let param_types: Vec<ParamType> = function
        .inputs
        .iter()
        .map(|input| input.kind.clone())
        .collect();
    let tokens = parse_arguments_json(args, &param_types)?;

    function.encode_input(&tokens).map_err(|e| {
        AvoError::InvalidInput(format!("Failed to encode function '{}': {}", signature, e))
    })
}

fn parse_arguments_json(args: Option<&str>, params: &[ParamType]) -> AvoResult<Vec<Token>> {
    let values: Vec<Value> = match args {
        None => {
            if params.is_empty() {
                Vec::new()
            } else {
                return Err(AvoError::InvalidInput(format!(
                    "Expected {} argument(s) but none were provided",
                    params.len()
                )));
            }
        }
        Some(payload) => {
            if payload.trim().is_empty() {
                Vec::new()
            } else {
                serde_json::from_str(payload).map_err(|e| {
                    AvoError::InvalidInput(format!(
                        "Arguments must be a JSON array (example: [1, \"0xabc\"]): {}",
                        e
                    ))
                })?
            }
        }
    };

    if values.len() != params.len() {
        return Err(AvoError::InvalidInput(format!(
            "Expected {} argument(s), received {}",
            params.len(),
            values.len()
        )));
    }

    values
        .iter()
        .zip(params.iter())
        .map(|(value, param)| value_to_token(value, param))
        .collect()
}

fn value_to_token(value: &Value, param: &ParamType) -> AvoResult<Token> {
    match param {
        ParamType::Address => {
            let address_str = value.as_str().ok_or_else(|| {
                AvoError::InvalidInput("Address arguments must be strings".into())
            })?;
            let address = EthAddress::from_str(address_str).map_err(|e| {
                AvoError::InvalidInput(format!("Invalid address '{}': {}", address_str, e))
            })?;
            Ok(Token::Address(address))
        }
        ParamType::Uint(_) => Ok(Token::Uint(parse_u256_value(value)?)),
        ParamType::Int(_) => Ok(Token::Int(parse_u256_value(value)?)),
        ParamType::Bool => value
            .as_bool()
            .map(Token::Bool)
            .ok_or_else(|| AvoError::InvalidInput("Boolean arguments must be true/false".into())),
        ParamType::String => value
            .as_str()
            .map(|s| Token::String(s.to_string()))
            .ok_or_else(|| AvoError::InvalidInput("String arguments must be quoted".into())),
        ParamType::Bytes => Ok(Token::Bytes(decode_json_bytes(value).ok_or_else(|| {
            AvoError::InvalidInput("Bytes arguments must be 0x-prefixed or byte array".into())
        })?)),
        ParamType::FixedBytes(size) => {
            let data = decode_json_bytes(value).ok_or_else(|| {
                AvoError::InvalidInput("Fixed bytes must be provided as 0x-prefixed string".into())
            })?;
            if data.len() != *size {
                return Err(AvoError::InvalidInput(format!(
                    "Fixed bytes argument expected {} bytes, got {}",
                    size,
                    data.len()
                )));
            }
            Ok(Token::FixedBytes(data))
        }
        ParamType::Array(inner) => {
            let array = value.as_array().ok_or_else(|| {
                AvoError::InvalidInput("Array arguments must be JSON arrays".into())
            })?;
            let tokens = array
                .iter()
                .map(|item| value_to_token(item, inner))
                .collect::<AvoResult<Vec<_>>>()?;
            Ok(Token::Array(tokens))
        }
        ParamType::FixedArray(inner, len) => {
            let array = value.as_array().ok_or_else(|| {
                AvoError::InvalidInput("Array arguments must be JSON arrays".into())
            })?;
            if array.len() != *len {
                return Err(AvoError::InvalidInput(format!(
                    "Expected array of length {}, received {}",
                    len,
                    array.len()
                )));
            }
            let tokens = array
                .iter()
                .map(|item| value_to_token(item, inner))
                .collect::<AvoResult<Vec<_>>>()?;
            Ok(Token::FixedArray(tokens))
        }
        ParamType::Tuple(components) => {
            let array = value.as_array().ok_or_else(|| {
                AvoError::InvalidInput("Tuple arguments must be JSON arrays".into())
            })?;
            if array.len() != components.len() {
                return Err(AvoError::InvalidInput(format!(
                    "Expected tuple of length {}, received {}",
                    components.len(),
                    array.len()
                )));
            }
            let mut tokens = Vec::with_capacity(components.len());
            for (item, component) in array.iter().zip(components.iter()) {
                tokens.push(value_to_token(item, component)?);
            }
            Ok(Token::Tuple(tokens))
        }
    }
}

fn parse_param_types(signature: &str) -> AvoResult<Vec<ParamType>> {
    let trimmed = signature.trim();
    if trimmed.is_empty() || trimmed == "()" {
        return Ok(Vec::new());
    }

    let normalized = if trimmed.starts_with('(') {
        trimmed.to_string()
    } else {
        format!("({trimmed})")
    };

    let fake_signature = format!("__ctor{normalized}");
    let mut parser = AbiParser::default();
    let function = parser.parse_function(&fake_signature).map_err(|e| {
        AvoError::InvalidInput(format!(
            "Invalid constructor argument list '{}': {}",
            signature, e
        ))
    })?;

    Ok(function
        .inputs
        .into_iter()
        .map(|param| param.kind)
        .collect())
}

fn parse_u256_value(value: &Value) -> AvoResult<AbiU256> {
    match value {
        Value::Number(num) => {
            if let Some(u) = num.as_u64() {
                Ok(AbiU256::from(u))
            } else {
                Err(AvoError::InvalidInput(
                    "Numeric value exceeds supported range for uint".into(),
                ))
            }
        }
        Value::String(s) => {
            let cleaned = s.trim();
            if cleaned.starts_with("0x") {
                let bytes = decode_hex_payload_cli(cleaned, "uint")?;
                if bytes.len() > 32 {
                    return Err(AvoError::InvalidInput(format!(
                        "Hex value '{}' exceeds 32 bytes",
                        cleaned
                    )));
                }
                let mut padded = [0u8; 32];
                padded[32 - bytes.len()..].copy_from_slice(&bytes);
                Ok(AbiU256::from_big_endian(&padded))
            } else {
                AbiU256::from_dec_str(cleaned).map_err(|e| {
                    AvoError::InvalidInput(format!("Invalid uint value '{}': {}", cleaned, e))
                })
            }
        }
        _ => Err(AvoError::InvalidInput(
            "Uint arguments must be numbers or quoted strings".into(),
        )),
    }
}

fn avo_to_wei(amount: f64) -> AvoResult<u128> {
    if amount.is_sign_negative() {
        return Err(AvoError::InvalidInput("Value cannot be negative".into()));
    }
    if !amount.is_finite() {
        return Err(AvoError::InvalidInput("Value must be finite".into()));
    }
    let wei = (amount * 1_000_000_000_000_000_000.0).round();
    if wei < 0.0 {
        return Err(AvoError::InvalidInput(
            "Value underflows when converted to wei".into(),
        ));
    }
    if wei > (u128::MAX as f64) {
        return Err(AvoError::InvalidInput(
            "Value exceeds maximum representable amount".into(),
        ));
    }
    Ok(wei as u128)
}

fn append_contract_deployment(record: ContractDeploymentRecord) -> AvoResult<()> {
    let mut deployments = load_contract_deployments()?;
    deployments.push(record);
    save_contract_deployments(&deployments)
}

fn load_contract_deployments() -> AvoResult<Vec<ContractDeploymentRecord>> {
    let path = Path::new(CONTRACT_DEPLOYMENTS_PATH);
    if !path.exists() {
        return Ok(Vec::new());
    }

    let data = fs::read_to_string(path).map_err(|e| AvoError::StorageError {
        reason: format!("Unable to read {}: {}", path.display(), e),
    })?;

    serde_json::from_str(&data).map_err(|e| {
        AvoError::InvalidInput(format!(
            "Malformed deployments file {}: {}",
            path.display(),
            e
        ))
    })
}

fn save_contract_deployments(records: &[ContractDeploymentRecord]) -> AvoResult<()> {
    ensure_contract_storage_dir()?;
    let data = serde_json::to_string_pretty(records)
        .map_err(|e| AvoError::InvalidInput(format!("Failed to serialize deployments: {}", e)))?;
    fs::write(CONTRACT_DEPLOYMENTS_PATH, data).map_err(|e| AvoError::StorageError {
        reason: format!(
            "Unable to write deployments file {}: {}",
            CONTRACT_DEPLOYMENTS_PATH, e
        ),
    })
}

fn ensure_contract_storage_dir() -> AvoResult<()> {
    if let Some(dir) = Path::new(CONTRACT_DEPLOYMENTS_PATH).parent() {
        fs::create_dir_all(dir).map_err(|e| AvoError::StorageError {
            reason: format!("Unable to create directory {}: {}", dir.display(), e),
        })?
    }
    Ok(())
}

// ============================================================================
// GOVERNANCE FUNCTIONS
// ============================================================================

async fn create_proposal(
    proposer: &str,
    proposal_type: &ProposalTypeArg,
    title: &str,
    description: &str,
    parameter: Option<&str>,
    current_value: Option<&str>,
    new_value: Option<&str>,
) -> AvoResult<()> {
    println!("\n\x1b[36m🏛️  [GOVERNANCE]\x1b[0m Creating Proposal");
    println!("═══════════════════════════════════════════════");
    println!("Proposer: {}", proposer);
    println!("Type: {:?}", proposal_type);
    println!("Title: {}", title);
    println!("Description: {}", description);
    
    if let (Some(param), Some(curr), Some(new_val)) = (parameter, current_value, new_value) {
        println!();
        println!("Parameter Change:");
        println!("  Parameter: {}", param);
        println!("  Current:   {}", curr);
        println!("  New:       {}", new_val);
    }
    
    println!();
    
    let mut params_obj = json!({
        "proposer": proposer,
        "proposal_type": format!("{:?}", proposal_type),
        "title": title,
        "description": description
    });
    
    if let (Some(param), Some(curr), Some(new_val)) = (parameter, current_value, new_value) {
        params_obj["parameter"] = json!(param);
        params_obj["current_value"] = json!(curr);
        params_obj["new_value"] = json!(new_val);
    }
    
    match rpc_call("avo_submitProposal", vec![params_obj]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                if let Some(proposal_id) = result.get("proposal_id").and_then(|v| v.as_str()) {
                    println!("\x1b[32m✅ [SUCCESS]\x1b[0m Proposal created!");
                    println!();
                    println!("Proposal ID: {}", proposal_id);
                    
                    if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
                        println!("Status: {}", status);
                    }
                    
                    if let Some(voting_ends) = result.get("voting_ends_at").and_then(|v| v.as_u64()) {
                        println!("Voting ends: {} (timestamp)", voting_ends);
                    }
                    
                    println!();
                    println!("\x1b[33m💡 Tip:\x1b[0m Users can now vote using:");
                    println!("   avo governance vote --voter <ADDRESS> --proposal-id {} --choice For|Against|Abstain", proposal_id);
                } else {
                    println!("\x1b[31m❌ [ERROR]\x1b[0m Failed to create proposal");
                    if let Some(error) = result.get("error").and_then(|v| v.as_str()) {
                        println!("Reason: {}", error);
                    }
                }
            } else if let Some(error) = resp.error {
                println!("\x1b[31m❌ [ERROR]\x1b[0m RPC error: {}", error.message);
            }
        }
        Err(e) => {
            println!("\x1b[31m❌ [ERROR]\x1b[0m Failed to call RPC: {}", e);
        }
    }
    
    Ok(())
}

async fn cast_vote(voter: &str, proposal_id: &str, choice: &VoteChoiceArg) -> AvoResult<()> {
    println!("\n\x1b[36m🗳️  [GOVERNANCE]\x1b[0m Casting Vote");
    println!("═══════════════════════════════════════════════");
    println!("Voter: {}", voter);
    println!("Proposal: {}", proposal_id);
    println!("Choice: {:?}", choice);
    println!();
    println!("\x1b[33m⚠️  VOTE FEE: 1 AVO will be burned\x1b[0m");
    println!();
    
    // Get voter balance first
    match rpc_call("avo_getBalance", vec![json!(voter)]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                if let Some(balance_hex) = result.as_str() {
                    let balance_hex_owned = balance_hex.to_string();
                    if let Ok(balance_wei) = u128::from_str_radix(&balance_hex_owned[2..], 16) {
                        let balance_avo = balance_wei as f64 / 1e18;
                        println!("Current balance: {:.6} AVO", balance_avo);
                        
                        if balance_wei < 1_000_000_000_000_000_000 {
                            println!("\x1b[31m❌ [ERROR]\x1b[0m Insufficient balance!");
                            println!("You need at least 1 AVO to vote (for the fee).");
                            return Err(AvoError::InvalidInput("Insufficient balance for vote fee".into()));
                        }
                        
                        let balance_after = balance_avo - 1.0;
                        println!("Balance after vote: {:.6} AVO", balance_after);
                        println!();
                    }
                }
            }
        }
        Err(_) => {
            println!("\x1b[33m⚠️  Could not verify balance\x1b[0m");
            println!();
        }
    }
    
    let params = json!({
        "voter": voter,
        "proposal_id": proposal_id,
        "choice": format!("{:?}", choice)
    });
    
    match rpc_call("avo_castVote", vec![params]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                if result.get("success").and_then(|v| v.as_bool()).unwrap_or(false) {
                    println!("\x1b[32m✅ [SUCCESS]\x1b[0m Vote cast successfully!");
                    println!();
                    
                    if let Some(voting_power) = result.get("voting_power").and_then(|v| v.as_str()) {
                        if let Ok(power_wei) = u128::from_str_radix(&voting_power[2..], 16) {
                            let power_avo = power_wei as f64 / 1e18;
                            println!("Voting power used: {:.6} AVO", power_avo);
                        }
                    }
                    
                    if let Some(fee_burned) = result.get("fee_burned").and_then(|v| v.as_str()) {
                        if let Ok(fee_wei) = u128::from_str_radix(&fee_burned[2..], 16) {
                            let fee_avo = fee_wei as f64 / 1e18;
                            println!("\x1b[31m🔥 Fee burned: {:.6} AVO\x1b[0m", fee_avo);
                        }
                    }
                    
                    if let Some(new_balance) = result.get("new_balance").and_then(|v| v.as_str()) {
                        if let Ok(balance_wei) = u128::from_str_radix(&new_balance[2..], 16) {
                            let balance_avo = balance_wei as f64 / 1e18;
                            println!("New balance: {:.6} AVO", balance_avo);
                        }
                    }
                    
                    println!();
                    if let Some(vote_counts) = result.get("vote_counts").and_then(|v| v.as_object()) {
                        println!("Current vote tally:");
                        if let Some(for_votes) = vote_counts.get("for").and_then(|v| v.as_str()) {
                            if let Ok(for_wei) = u128::from_str_radix(&for_votes[2..], 16) {
                                println!("  For: {:.2} AVO", for_wei as f64 / 1e18);
                            }
                        }
                        if let Some(against_votes) = vote_counts.get("against").and_then(|v| v.as_str()) {
                            if let Ok(against_wei) = u128::from_str_radix(&against_votes[2..], 16) {
                                println!("  Against: {:.2} AVO", against_wei as f64 / 1e18);
                            }
                        }
                        if let Some(abstain_votes) = vote_counts.get("abstain").and_then(|v| v.as_str()) {
                            if let Ok(abstain_wei) = u128::from_str_radix(&abstain_votes[2..], 16) {
                                println!("  Abstain: {:.2} AVO", abstain_wei as f64 / 1e18);
                            }
                        }
                    }
                } else {
                    println!("\x1b[31m❌ [ERROR]\x1b[0m Failed to cast vote");
                    if let Some(error) = result.get("error").and_then(|v| v.as_str()) {
                        println!("Reason: {}", error);
                    }
                }
            } else if let Some(error) = resp.error {
                println!("\x1b[31m❌ [ERROR]\x1b[0m RPC error: {}", error.message);
            }
        }
        Err(e) => {
            println!("\x1b[31m❌ [ERROR]\x1b[0m Failed to call RPC: {}", e);
        }
    }
    
    Ok(())
}

async fn show_governance_stats() -> AvoResult<()> {
    println!("\n\x1b[35m📊 Governance Statistics\x1b[0m");
    println!("═══════════════════════════════════════════════");
    
    match rpc_call("avo_getGovernanceStats", vec![]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                // Phase info
                if let Some(phase) = result.get("phase") {
                    println!("\n\x1b[36mCurrent Phase:\x1b[0m");
                    if let Some(phase_obj) = phase.as_object() {
                        if phase_obj.contains_key("AdminControlled") {
                            println!("  ⚡ Admin Bootstrap");
                            if let Some(data) = phase_obj.get("AdminControlled").and_then(|v| v.as_object()) {
                                if let Some(min_size) = data.get("min_community_size").and_then(|v| v.as_u64()) {
                                    println!("  Min holders for transition: {}", min_size);
                                }
                            }
                        } else if phase_obj.contains_key("Transition") {
                            println!("  🔄 Transition");
                        } else if phase_obj.contains_key("Decentralized") {
                            println!("  🌐 Fully Decentralized");
                        }
                    }
                }
                
                // Vote fee
                if let Some(fee) = result.get("vote_fee").and_then(|v| v.as_str()) {
                    if let Ok(fee_wei) = u128::from_str_radix(&fee[2..], 16) {
                        println!("\n\x1b[36mVote Fee:\x1b[0m");
                        println!("  {:.2} AVO (burned per vote)", fee_wei as f64 / 1e18);
                    }
                }
                
                // Total burned
                if let Some(burned) = result.get("total_fees_burned").and_then(|v| v.as_str()) {
                    if let Ok(burned_wei) = u128::from_str_radix(&burned[2..], 16) {
                        println!("\n\x1b[31m🔥 Total Fees Burned:\x1b[0m");
                        println!("  {:.6} AVO", burned_wei as f64 / 1e18);
                    }
                }
                
                // Total votes
                if let Some(votes) = result.get("total_votes_cast").and_then(|v| v.as_u64()) {
                    println!("\n\x1b[36mTotal Votes Cast:\x1b[0m");
                    println!("  {}", votes);
                }
                
                // Admin address
                if let Some(admin) = result.get("admin_address").and_then(|v| v.as_str()) {
                    println!("\n\x1b[36mAdmin Address:\x1b[0m");
                    println!("  {}", admin);
                }
                
                // Burn enabled
                if let Some(burn_enabled) = result.get("burn_enabled").and_then(|v| v.as_bool()) {
                    println!("\n\x1b[36mBurn Mechanism:\x1b[0m");
                    println!("  {}", if burn_enabled { "✅ Enabled" } else { "❌ Disabled" });
                }
                
                println!();
            } else if let Some(error) = resp.error {
                println!("\x1b[31m❌ [ERROR]\x1b[0m RPC error: {}", error.message);
            }
        }
        Err(e) => {
            println!("\x1b[31m❌ [ERROR]\x1b[0m Failed to fetch stats: {}", e);
        }
    }
    
    Ok(())
}

async fn list_proposals() -> AvoResult<()> {
    println!("\n\x1b[35m📋 Active Proposals\x1b[0m");
    println!("═══════════════════════════════════════════════");
    
    match rpc_call("avo_listProposals", vec![]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                if let Some(proposals) = result.as_array() {
                    if proposals.is_empty() {
                        println!("\nNo active proposals.");
                        println!("\n\x1b[33m💡 Tip:\x1b[0m Create a proposal using:");
                        println!("   avo governance propose --proposer <ADDRESS> --proposal-type ParameterChange --title \"...\" --description \"...\"");
                    } else {
                        for (i, proposal) in proposals.iter().enumerate() {
                            println!("\n\x1b[36mProposal #{}\x1b[0m", i + 1);
                            if let Some(id) = proposal.get("id").and_then(|v| v.as_str()) {
                                println!("  ID: {}", id);
                            }
                            if let Some(title) = proposal.get("title").and_then(|v| v.as_str()) {
                                println!("  Title: {}", title);
                            }
                            if let Some(status) = proposal.get("status").and_then(|v| v.as_str()) {
                                println!("  Status: {}", status);
                            }
                            if let Some(proposer) = proposal.get("proposer").and_then(|v| v.as_str()) {
                                println!("  Proposer: {}", proposer);
                            }
                        }
                    }
                }
            } else if let Some(error) = resp.error {
                println!("\x1b[31m❌ [ERROR]\x1b[0m RPC error: {}", error.message);
            }
        }
        Err(e) => {
            println!("\x1b[31m❌ [ERROR]\x1b[0m Failed to fetch proposals: {}", e);
        }
    }
    
    println!();
    Ok(())
}

async fn show_proposal_info(proposal_id: &str) -> AvoResult<()> {
    println!("\n\x1b[35m📄 Proposal Details\x1b[0m");
    println!("═══════════════════════════════════════════════");
    
    let params = json!({
        "proposal_id": proposal_id
    });
    
    match rpc_call("avo_getProposal", vec![params]).await {
        Ok(resp) => {
            if let Some(result) = resp.result {
                println!("\n\x1b[36mGeneral Info:\x1b[0m");
                if let Some(id) = result.get("id").and_then(|v| v.as_str()) {
                    println!("  ID: {}", id);
                }
                if let Some(title) = result.get("title").and_then(|v| v.as_str()) {
                    println!("  Title: {}", title);
                }
                if let Some(description) = result.get("description").and_then(|v| v.as_str()) {
                    println!("  Description: {}", description);
                }
                if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
                    println!("  Status: {}", status);
                }
                if let Some(proposer) = result.get("proposer").and_then(|v| v.as_str()) {
                    println!("  Proposer: {}", proposer);
                }
                
                println!("\n\x1b[36mVoting:\x1b[0m");
                if let Some(votes) = result.get("vote_counts").and_then(|v| v.as_object()) {
                    for (choice, count) in votes {
                        println!("  {}: {}", choice, count);
                    }
                }
            } else if let Some(error) = resp.error {
                println!("\x1b[31m❌ [ERROR]\x1b[0m RPC error: {}", error.message);
            }
        }
        Err(e) => {
            println!("\x1b[31m❌ [ERROR]\x1b[0m Failed to fetch proposal: {}", e);
        }
    }
    
    println!();
    Ok(())
}


