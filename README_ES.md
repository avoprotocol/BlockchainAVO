# AVO Protocol

**Blockchain de Alto Rendimiento con Flow Consensus**

## 📖 Descripción

AVO Protocol es un blockchain modular construido en Rust, optimizado para alto rendimiento y seguridad. Implementa un mecanismo de consenso Flow innovador con validadores rotativos y soporte para sharding.

## ✨ Características Principales

- ⚡ **Alto Rendimiento**: +1000 TPS con optimizaciones de throughput
- ⚡ **Alto Rendimiento**: +500000 TPS sin carga solo tx
- 🤝 **Flow Consensus**: Mecanismo de consenso eficiente con validadores
- 🔐 **Seguridad Avanzada**: Criptografía de curva elíptica y firmas digitales
- 💾 **Almacenamiento RocksDB**: Persistencia eficiente del estado
- 🌐 **APIs Completas**: JSON-RPC sobre HTTP y WebSocket
- 🔗 **Sharding**: Soporte experimental para particionado de datos
- 💰 **Token Nativo AVO**: Sistema de tokens con mint/burn

## 🏗️ Arquitectura del Proyecto

```
PROTOCOL AVO/
├── avo-core/           # Lógica central del blockchain
│   ├── consensus/      # Flow Consensus
│   ├── crypto/         # Criptografía
│   ├── state/          # Gestión de estado
│   ├── storage/        # RocksDB
│   └── transaction/    # Transacciones
│
├── avo-node/           # Nodo completo P2P
│   └── src/
│       ├── config.rs   # Configuración
│       └── node.rs     # Lógica del nodo
│
├── avo-cli/            # Interfaz de línea de comandos
│   └── src/
│       └── main.rs     # CLI tools
│
├── blockchain-explorer/ # Explorador web (React)
│   └── src/
│
├── keys/               # Wallets generadas
├── data/               # Datos del blockchain
└── config.toml         # Configuración global
```

## 🚀 Instalación y Compilación

### Requisitos

- Rust 1.70+ 
- Node.js 18+ (para el explorador)
- Git

### Compilar el Proyecto

```bash
# Clonar el repositorio
git clone https://github.com/avoprotocol/avo-protocol.git
cd avo-protocol

# Compilar todos los módulos
cargo build --release --all

# Ejecutar tests
cargo test --all
```

## 🎯 Uso Rápido

### 1️⃣ Iniciar el Nodo

```bash

# O directamente
.\target\release\avo-node.exe
```

El nodo iniciará en:
- **HTTP RPC**: http://127.0.0.1:9545
- **WebSocket**: ws://127.0.0.1:8545

### 2️⃣ Explorador de Blockchain

```bash
cd blockchain-explorer
npm install
npm start
```

Abre http://localhost:3000 en tu navegador.

### 3️⃣ Usar el CLI

```bash
# Generar una wallet
.\target\release\avo.exe wallet generate

# Ver balance
.\target\release\avo.exe wallet balance <address>

# Enviar transacción
.\target\release\avo.exe tx send --from <wallet_file> --to <address> --amount 100
```

## 📊 Componentes

### avo-core

Lógica central del blockchain:
- Estructura de bloques y transacciones
- Mecanismo de consenso Flow
- Gestión de estado y cuentas
- Almacenamiento con RocksDB
- Validación criptográfica

### avo-node

Nodo P2P completo:
- Servidor RPC (HTTP + WebSocket)
- Sincronización de red
- Propagación de bloques y transacciones
- Gestión de validadores

### avo-cli

Herramientas de línea de comandos:
- Gestión de wallets
- Envío de transacciones
- Comandos administrativos 
- Consultas de estado

### blockchain-explorer

Interfaz web para visualizar:
- Dashboard con métricas en tiempo real
- Bloques y transacciones recientes
- Top Accounts con balances
- Estadísticas de red y consenso

## ⚙️ Configuración

Edita `config.toml` para personalizar:

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

## 🔑 Gestión de Wallets

Las wallets se guardan en `keys/`:

```bash
# Generar nueva wallet
avo.exe wallet generate

# Archivo generado: keys/wallet_0xADDRESS.json
```

## 📡 API JSON-RPC

### Métodos Disponibles

```javascript
// Balance de cuenta
avo_getBalance(address)

// Lista de wallets
avo_listWallets()

// Total supply
avo_getTotalSupply()

// Estadísticas de cuentas
avo_getAccountStats()

// Bloques recientes
avo_getRecentBlocks(count)

// Transacciones recientes
avo_getRecentTransactions(count)

// Métricas de red
avo_getNetworkStats()
```

### Ejemplo de Uso

```bash
curl -X POST http://127.0.0.1:9545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "avo_getTotalSupply",
    "params": [],
    "id": 1
  }'
```

## 🧪 Tests

```bash
# Ejecutar todos los tests
cargo test --all

# Tests con output detallado
cargo test --all -- --nocapture

# Test de módulo específico
cargo test -p avo-core
```

## 📈 Métricas de Rendimiento

- **TPS Real**: >1000 transacciones por segundo
- **Latencia**: ~1.5s confirmación de bloque
- **Storage**: RocksDB optimizado
- **Sharding**: 4 shards por defecto


Copyright (c) 2025 AVO Protocol

## 🔗 Enlaces

- **GitHub**: https://github.com/avoprotocol/avo-protocol


---

**Desarrollado con  por MDERRAMUS**
