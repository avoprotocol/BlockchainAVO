# AVO Protocol

**High-Performance Blockchain with Flow Consensus**

## 📖 Description

AVO Protocol is a modular blockchain built in Rust, optimized for high performance and security. It implements an innovative Flow consensus mechanism with rotating validators and support for sharding.

## ✨ Key Features

- ⚡ **High Performance**: +1000 TPS with throughput optimizations
- ⚡ **High Performance**: +500000 TPS (no-load, tx-only)
- 🤝 **Flow Consensus**: Efficient consensus mechanism with validators
- 🔐 **Advanced Security**: Elliptic-curve cryptography and digital signatures
- 💾 **RocksDB Storage**: Efficient state persistence
- 🌐 **Complete APIs**: JSON-RPC over HTTP and WebSocket
- 🔗 **Sharding**: Experimental support for data partitioning
- 💰 **Native AVO Token**: Token system with mint/burn

## 🏗️ Project Architecture

```
PROTOCOL AVO/
├── avo-core/           # Core blockchain logic
│   ├── consensus/      # Flow Consensus
│   ├── crypto/         # Cryptography
│   ├── state/          # State management
│   ├── storage/        # RocksDB
│   └── transaction/    # Transactions
│
├── avo-node/           # Full P2P node
│   └── src/
│       ├── config.rs   # Configuration
│       └── node.rs     # Node logic
│
├── avo-cli/            # Command-line interface
│   └── src/
│       └── main.rs     # CLI tools
│
├── blockchain-explorer/ # Web explorer (React)
│   └── src/
│
├── keys/               # Generated wallets
├── data/               # Blockchain data
└── config.toml         # Global configuration
```

## 🚀 Installation and Build

### Requirements

- Rust 1.70+
- Node.js 18+ (for the explorer)
- Git

### Build the Project

```bash
# Clone the repository
git clone https://github.com/avoprotocol/avo-protocol.git
cd avo-protocol

# Build all modules
cargo build --release --all

# Run tests
cargo test --all
```

## 🎯 Quick Usage

### 1️⃣ Start the Node

```bash

# Or directly
.\target\release\avo-node.exe
```

The node will start at:
- **HTTP RPC**: http://127.0.0.1:9545
- **WebSocket**: ws://127.0.0.1:8545

### 2️⃣ Blockchain Explorer

```bash
cd blockchain-explorer
npm install
npm start
```

Open http://localhost:3000 in your browser.

### 3️⃣ Use the CLI

```bash
# Generate a wallet
.\target\release\avo.exe wallet generate

# View balance
.\target\release\avo.exe wallet balance <address>

# Send transaction
.\target\release\avo.exe tx send --from <wallet_file> --to <address> --amount 100
```

## 📊 Components

### avo-core

Core blockchain logic:
- Block and transaction structure
- Flow consensus mechanism
- State and account management
- Storage with RocksDB
- Cryptographic validation

### avo-node

Full P2P node:
- RPC server (HTTP + WebSocket)
- Network synchronization
- Block and transaction propagation
- Validator management

### avo-cli

Command-line tools:
- Wallet management
- Transaction sending
- Administrative commands
- State queries

### blockchain-explorer

Web interface to visualize:
- Dashboard with real-time metrics
- Recent blocks and transactions
- Top accounts with balances
- Network and consensus statistics

## ⚙️ Configuration

Edit `config.toml` to customize:

```toml
[network]
listen_addr = "127.0.0.1:9944"

[rpc]
http_enabled = true
http_port = 9545
ws_enabled = true
ws_port = 8545

[storage]
data_dir = "./data"
```

## 🔑 Wallet Management

Wallets are stored in `keys/`:

```bash
# Generate new wallet
avo.exe wallet generate

# Generated file: keys/wallet_0xADDRESS.json
# Run all tests
cargo test --all


# Specific module tests
cargo test -p avo-core
cargo test -p avo-cli
cargo test -p avo-node
```

**Developed with ❤️ by MDERRAMUS**
