use anyhow::anyhow;
use avo_core::consensus::FlowConsensus;
use avo_core::state::storage::{AvocadoStorage, StorageConfig};
use avo_core::types::Hash;
use avo_core::vm::avo_vm::{AvoVM, BytecodeType, VMConfig, VMContext, U256};
use chrono::Utc;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use warp::Filter;

#[derive(Clone)]
pub struct RpcServer {
    port: u16,
    chain_id: String,
    gas_price: String,
    consensus: Option<Arc<FlowConsensus>>,
    vm: Arc<AvoVM>,
    block_number: Arc<RwLock<u64>>,
}

impl RpcServer {
    pub fn new(port: u16) -> Self {
        const CONTRACT_STORAGE_PATH: &str = "./data/node_storage/contracts";

        let storage = match AvocadoStorage::new(StorageConfig::with_path(CONTRACT_STORAGE_PATH)) {
            Ok(storage) => {
                info!(
                    "✅ Contract storage initialized at {}",
                    CONTRACT_STORAGE_PATH
                );
                Some(Arc::new(storage))
            }
            Err(err) => {
                warn!(
                    "⚠️ Persistent contract storage unavailable ({}). Falling back to in-memory storage.",
                    err
                );
                None
            }
        };

        let vm = match storage.clone() {
            Some(storage) => Arc::new(AvoVM::new_with_storage(VMConfig::default(), storage)),
            None => Arc::new(AvoVM::default()),
        };

        Self {
            port,
            chain_id: "0x539".to_string(),       // 1337 en decimal
            gas_price: "0x3b9aca00".to_string(), // 1 gwei
            consensus: None,
            vm,
            block_number: Arc::new(RwLock::new(0)),
        }
    }

    pub fn set_consensus(&mut self, consensus: Arc<FlowConsensus>) {
        self.consensus = Some(consensus);
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("🚀 Starting RPC server on port {}", self.port);

        if let Err(err) = self.vm.preload_contracts().await {
            warn!(
                "⚠️ Unable to preload contracts from persistent storage: {}",
                err
            );
        }

        // Configuración CORS para permitir conexiones desde navegadores
        let cors = warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type", "authorization"])
            .allow_methods(vec!["GET", "POST", "OPTIONS"]);

        // Endpoint para manejar solicitudes JSON-RPC
        let rpc = warp::path::end()
            .and(warp::post())
            .and(warp::body::json())
            .and(with_rpc_server(self.clone()))
            .and_then(handle_rpc_request)
            .with(cors);

        // Endpoint de salud para verificación
        let health = warp::path("health")
            .and(warp::get())
            .map(|| warp::reply::with_status("OK", warp::http::StatusCode::OK));

        let routes = rpc.or(health);

        info!("✅ RPC server listening on http://0.0.0.0:{}", self.port);
        info!("📡 Chain ID: {}", self.chain_id);
        let current_block = *self.block_number.read().await;
        info!("🔗 Block Number: {}", current_block);
        info!("⛽ Gas Price: {}", self.gas_price);

        warp::serve(routes).run(([0, 0, 0, 0], self.port)).await;

        Ok(())
    }
}

fn with_rpc_server(
    server: RpcServer,
) -> impl Filter<Extract = (RpcServer,), Error = Infallible> + Clone {
    warp::any().map(move || server.clone())
}

async fn handle_rpc_request(
    request: Value,
    server: RpcServer,
) -> Result<impl warp::Reply, Infallible> {
    info!(
        "📨 Received RPC request: {}",
        serde_json::to_string_pretty(&request).unwrap_or_default()
    );

    let response = match process_rpc_request(request, &server).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("❌ Error processing RPC request: {}", e);
            json!({
                "jsonrpc": "2.0",
                "error": {
                    "code": -32603,
                    "message": "Internal error"
                },
                "id": null
            })
        }
    };

    info!(
        "📤 Sending response: {}",
        serde_json::to_string_pretty(&response).unwrap_or_default()
    );

    Ok(warp::reply::json(&response))
}

async fn process_rpc_request(
    request: Value,
    server: &RpcServer,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let method = request["method"].as_str().ok_or("Missing method")?;
    let id = request["id"].clone();

    let result = match method {
        "eth_chainId" => {
            info!("🔗 Chain ID requested");
            json!(server.chain_id)
        }
        "eth_blockNumber" => {
            info!("📦 Block number requested");
            // Obtener el número de bloque real del consenso
            let block_number = if let Some(consensus) = &server.consensus {
                if let Ok(Some(latest_block_data)) =
                    consensus.storage.get_state("latest_block_number").await
                {
                    let latest_block_str = String::from_utf8_lossy(&latest_block_data);
                    latest_block_str
                        .parse::<u64>()
                        .unwrap_or_else(|_| *server.block_number.read().await)
                } else {
                    *server.block_number.read().await
                }
            } else {
                *server.block_number.read().await
            };
            json!(format!("0x{:x}", block_number))
        }
        "eth_gasPrice" => {
            info!("⛽ Gas price requested");
            json!(server.gas_price)
        }
        "net_version" => {
            info!("🌐 Network version requested");
            json!("1337")
        }
        "eth_accounts" => {
            info!("👤 Accounts requested");
            json!([])
        }
        "eth_getBalance" => {
            info!("💰 Balance requested");
            json!("0x56bc75e2d630fffff") // Balance alto para testing
        }
        "eth_getTransactionCount" => {
            info!("📋 Transaction count requested");
            json!("0x0")
        }
        "eth_estimateGas" => {
            info!("⛽ Gas estimation requested");
            json!("0x5208") // 21000 gas (transferencia simple)
        }
        "eth_sendTransaction" => {
            warn!("🚫 Transaction sending not implemented yet");
            return Err("Method not implemented".into());
        }
        "avo_sendCrossShardTransaction" => {
            info!("💸 Cross-shard transaction requested");
            let params = request["params"].as_array().ok_or("Missing params")?;
            if params.is_empty() {
                return Err("Transaction params required".into());
            }

            let tx_params = &params[0];
            let from = tx_params["from"].as_str().ok_or("Missing from address")?;
            let to = tx_params["to"].as_str().ok_or("Missing to address")?;
            let value = tx_params["value"].as_str().ok_or("Missing value")?;

            // Convert value string to u128
            let value_u128: u128 = value.parse().map_err(|_| "Invalid value format")?;

            // Check if genesis account has sufficient balance
            let is_genesis = from == "0xE84f43cBc43BFa79Ddf1a612bC4323Da6682103f";
            if !is_genesis && value_u128 > 0 {
                return Err(format!(
                    "Insufficient balance: {} AVO required, 0 AVO available",
                    value_u128 as f64 / 1_000_000_000_000_000_000.0
                )
                .into());
            }

            // Generate transaction hash
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            from.hash(&mut hasher);
            to.hash(&mut hasher);
            value.hash(&mut hasher);
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
                .hash(&mut hasher);
            let tx_hash = format!("0x{:x}", hasher.finish());

            info!(
                "✅ Transaction accepted: {} AVO from {} to {}",
                value_u128 as f64 / 1_000_000_000_000_000_000.0,
                from,
                to
            );

            json!({
                "transactionHash": tx_hash,
                "status": "pending",
                "blockNumber": null
            })
        }
        "eth_call" => {
            info!("📞 Contract call requested");
            json!("0x")
        }
        "eth_getCode" => {
            info!("📜 Contract code requested");
            json!("0x")
        }
        "eth_getLogs" => {
            info!("📝 Logs requested");
            json!([])
        }
        "eth_getBlockByNumber" => {
            info!("📦 Block by number requested");
            let current_block = *server.block_number.read().await;
            let block = json!({
                "number": format!("0x{:x}", current_block),
                "hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                "timestamp": format!("0x{:x}", chrono::Utc::now().timestamp()),
                "gasLimit": "0x1c9c380",
                "gasUsed": "0x0",
                "transactions": []
            });
            block
        }
        "web3_clientVersion" => {
            info!("🔧 Client version requested");
            json!("AVO-Protocol/1.0.0")
        }
        "avo_deployContract" => handle_deploy_contract(&request, server).await?,
        "avo_callContract" => handle_call_contract(&request, server).await?,
        "avo_queryContract" => handle_query_contract(&request, server).await?,
        _ => {
            warn!("❓ Unknown method: {}", method);
            return Err(format!("Method {} not supported", method).into());
        }
    };

    Ok(json!({
        "jsonrpc": "2.0",
        "result": result,
        "id": id
    }))
}

async fn handle_deploy_contract(
    request: &Value,
    server: &RpcServer,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let params = request["params"]
        .as_array()
        .ok_or_else(|| anyhow!("Missing params"))?;
    let payload = params
        .get(0)
        .ok_or_else(|| anyhow!("Missing deployment payload"))?;

    let from = payload
        .get("from")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing 'from' address"))?;
    let bytecode_hex = payload
        .get("bytecode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing contract bytecode"))?;

    let constructor_args = payload
        .get("constructorArgs")
        .and_then(|v| v.as_str())
        .unwrap_or("0x");

    let gas_limit = parse_optional_u64(payload.get("gasLimit"))?.unwrap_or(30_000_000);
    let gas_price = parse_optional_u64(payload.get("gasPrice"))?.unwrap_or(1_000_000_000);
    let value_raw = parse_optional_u128(payload.get("value"))?.unwrap_or(0);
    let shard_id = parse_optional_u64(payload.get("shard"))?.unwrap_or(0) as u32;

    if gas_limit == 0 {
        return Err(anyhow!("gasLimit must be greater than zero").into());
    }

    let bytecode = decode_hex_payload(bytecode_hex, "bytecode")?;
    if bytecode.is_empty() {
        return Err(anyhow!("Contract bytecode cannot be empty").into());
    }

    let constructor_data = decode_hex_payload(constructor_args, "constructorArgs")?;
    let sender = parse_eth_address(from)?;
    let tx_hash = random_hash();

    let prospective_block = {
        let guard = server.block_number.read().await;
        *guard + 1
    };

    let context = VMContext {
        tx_hash,
        sender,
        recipient: None,
        gas_limit,
        gas_price,
        value: u256_from_u128(value_raw),
        block_number: prospective_block,
        block_timestamp: Utc::now().timestamp().max(0) as u64,
        chain_id: 0x539,
        shard_id,
    };

    let (contract_address_bytes, vm_result) = server
        .vm
        .deploy_contract(context, bytecode.clone(), constructor_data.clone())
        .await?;

    if !vm_result.success {
        let error_text = vm_result
            .error
            .unwrap_or_else(|| "Contract deployment failed without specific error".to_string());
        return Err(anyhow!(error_text).into());
    }

    {
        let mut guard = server.block_number.write().await;
        *guard = prospective_block;
    }

    let contract_snapshot = match server.vm.get_contract(&contract_address_bytes).await {
        Some(info) => serde_json::to_value(&info)?,
        None => json!({}),
    };

    Ok(json!({
        "contractAddress": format_address(&contract_address_bytes),
        "txHash": format_hash(&tx_hash),
        "gasUsed": vm_result.gas_used,
        "returnData": format_bytes(&vm_result.return_data),
        "stateChanges": vm_result.state_changes,
        "events": vm_result.events,
        "bytecodeSize": bytecode.len(),
        "constructorData": format_bytes(&constructor_data),
        "value": value_raw,
        "shard": shard_id,
        "blockNumber": prospective_block,
        "contract": contract_snapshot,
    }))
}

async fn handle_call_contract(
    request: &Value,
    server: &RpcServer,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let params = request["params"]
        .as_array()
        .ok_or_else(|| anyhow!("Missing params"))?;
    let payload = params
        .get(0)
        .ok_or_else(|| anyhow!("Missing call payload"))?;

    let from = payload
        .get("from")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing 'from' address"))?;
    let contract_addr = payload
        .get("contract")
        .or_else(|| payload.get("contractAddress"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing contract address"))?;

    let data_hex = payload.get("data").and_then(|v| v.as_str()).unwrap_or("0x");

    let gas_limit = parse_optional_u64(payload.get("gasLimit"))?.unwrap_or(5_000_000);
    let gas_price = parse_optional_u64(payload.get("gasPrice"))?.unwrap_or(1_000_000_000);
    let value_raw = parse_optional_u128(payload.get("value"))?.unwrap_or(0);

    if gas_limit == 0 {
        return Err(anyhow!("gasLimit must be greater than zero").into());
    }

    let sender = parse_eth_address(from)?;
    let contract_address = parse_eth_address(contract_addr)?;
    let call_data = decode_hex_payload(data_hex, "data")?;

    let contract_info = server
        .vm
        .get_contract(&contract_address)
        .await
        .ok_or_else(|| anyhow!("Contract not found"))?;

    let bytecode = match contract_info.bytecode.clone() {
        BytecodeType::EVM(bytes) | BytecodeType::WASM(bytes) => bytes,
        BytecodeType::Native(name) => {
            return Err(anyhow!(
                "Native contract '{}' cannot be executed via avo_callContract",
                name
            )
            .into())
        }
    };

    let block_number = {
        let mut guard = server.block_number.write().await;
        *guard += 1;
        *guard
    };

    let tx_hash = random_hash();
    let shard_id = parse_optional_u64(payload.get("shard"))?.unwrap_or(0) as u32;

    let context = VMContext {
        tx_hash,
        sender,
        recipient: Some(contract_address),
        gas_limit,
        gas_price,
        value: u256_from_u128(value_raw),
        block_number,
        block_timestamp: Utc::now().timestamp().max(0) as u64,
        chain_id: 0x539,
        shard_id,
    };

    let vm_result = server
        .vm
        .execute_transaction(context, bytecode, call_data.clone())
        .await?;

    Ok(json!({
        "txHash": format_hash(&tx_hash),
        "success": vm_result.success,
        "returnData": format_bytes(&vm_result.return_data),
        "gasUsed": vm_result.gas_used,
        "error": vm_result.error,
        "events": vm_result.events,
        "stateChanges": vm_result.state_changes,
        "blockNumber": block_number,
        "value": value_raw,
    }))
}

async fn handle_query_contract(
    request: &Value,
    server: &RpcServer,
) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
    let params = request["params"]
        .as_array()
        .ok_or_else(|| anyhow!("Missing params"))?;
    let payload = params
        .get(0)
        .ok_or_else(|| anyhow!("Missing query payload"))?;

    let contract_addr = payload
        .get("contract")
        .or_else(|| payload.get("contractAddress"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing contract address"))?;

    let contract_address = parse_eth_address(contract_addr)?;

    let contract_info = server
        .vm
        .get_contract(&contract_address)
        .await
        .ok_or_else(|| anyhow!("Contract not found"))?;

    Ok(serde_json::to_value(&contract_info)?)
}

fn decode_hex_payload(
    value: &str,
    field: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let cleaned = value.trim();
    if cleaned.is_empty() || cleaned == "0x" {
        return Ok(Vec::new());
    }
    let stripped = cleaned.trim_start_matches("0x");
    let decoded =
        hex::decode(stripped).map_err(|e| anyhow!("Invalid hex in '{}': {}", field, e))?;
    Ok(decoded)
}

fn parse_eth_address(address: &str) -> Result<[u8; 20], Box<dyn std::error::Error + Send + Sync>> {
    let stripped = address.trim().trim_start_matches("0x");
    if stripped.len() != 40 {
        return Err(anyhow!("Invalid address length: expected 20 bytes").into());
    }
    let bytes = hex::decode(stripped).map_err(|e| anyhow!("Invalid address hex: {}", e))?;
    let mut result = [0u8; 20];
    result.copy_from_slice(&bytes);
    Ok(result)
}

fn format_address(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

fn format_bytes(data: &[u8]) -> String {
    if data.is_empty() {
        "0x".to_string()
    } else {
        format!("0x{}", hex::encode(data))
    }
}

fn format_hash(hash: &Hash) -> String {
    format!("0x{}", hex::encode(hash))
}

fn random_hash() -> Hash {
    let mut hash = [0u8; 32];
    OsRng.fill_bytes(&mut hash);
    hash
}

fn u256_from_u128(value: u128) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[16..].copy_from_slice(&value.to_be_bytes());
    U256(bytes)
}

fn parse_optional_u64(
    value: Option<&Value>,
) -> Result<Option<u64>, Box<dyn std::error::Error + Send + Sync>> {
    match value {
        None => Ok(None),
        Some(v) => {
            if let Some(num) = v.as_u64() {
                Ok(Some(num))
            } else if let Some(s) = v.as_str() {
                if s.starts_with("0x") {
                    u64::from_str_radix(s.trim_start_matches("0x"), 16)
                        .map(Some)
                        .map_err(|e| anyhow!("Invalid hex number: {}", e).into())
                } else {
                    s.parse::<u64>()
                        .map(Some)
                        .map_err(|e| anyhow!("Invalid numeric string: {}", e).into())
                }
            } else {
                Err(anyhow!("Unsupported numeric format").into())
            }
        }
    }
}

fn parse_optional_u128(
    value: Option<&Value>,
) -> Result<Option<u128>, Box<dyn std::error::Error + Send + Sync>> {
    match value {
        None => Ok(None),
        Some(v) => {
            if let Some(num) = v.as_u64() {
                Ok(Some(num as u128))
            } else if let Some(num) = v.as_u128() {
                Ok(Some(num))
            } else if let Some(s) = v.as_str() {
                if s.starts_with("0x") {
                    u128::from_str_radix(s.trim_start_matches("0x"), 16)
                        .map(Some)
                        .map_err(|e| anyhow!("Invalid hex number: {}", e).into())
                } else {
                    s.parse::<u128>()
                        .map(Some)
                        .map_err(|e| anyhow!("Invalid numeric string: {}", e).into())
                }
            } else {
                Err(anyhow!("Unsupported numeric format").into())
            }
        }
    }
}
