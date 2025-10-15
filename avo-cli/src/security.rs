//! # Security Helper Module for CLI
//! 
//! Funciones para firmar operaciones con Ed25519 y manejar nonces

use ed25519_dalek::{Signature, Signer, SigningKey};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

/// Estructura para mensaje firmado
pub struct SignedOperation {
    pub address: String,
    pub nonce: u64,
    #[allow(dead_code)] // Usado en Web3 frontend, no en CLI actual
    pub operation: String,
    pub data: String,
    #[allow(dead_code)] // Usado en Web3 frontend, no en CLI actual
    pub timestamp: u64,
    pub signature: String,
    pub public_key: String,
}

/// Crear mensaje a firmar (formato compatible con backend)
fn create_signing_message(
    address: &str,
    nonce: u64,
    operation: &str,
    data: &str,
    timestamp: u64,
) -> String {
    format!(
        "AVO_PROTOCOL\nAddress: {}\nNonce: {}\nOperation: {}\nData: {}\nTimestamp: {}",
        address, nonce, operation, data, timestamp
    )
}

/// Obtener nonce desde el RPC
pub async fn get_nonce(address: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "avo_getNonce",
        "params": [address],
        "id": 1,
    });

    let response = client
        .post("http://127.0.0.1:9545")
        .json(&request_body)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    if let Some(result) = response.get("result") {
        if let Some(nonce) = result.get("next_nonce").and_then(|v| v.as_u64()) {
            return Ok(nonce);
        }
    }

    Err("Failed to get nonce from RPC".into())
}

/// Firmar una operación con Ed25519
pub fn sign_operation(
    address: &str,
    nonce: u64,
    operation: &str,
    data: &str,
    private_key_hex: &str,
) -> Result<SignedOperation, Box<dyn std::error::Error>> {
    // 1. Decodificar private key
    let private_key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))?;
    
    // Ed25519 private key debe ser 32 bytes
    if private_key_bytes.len() != 32 {
        return Err(format!(
            "Invalid private key length: expected 32 bytes, got {}",
            private_key_bytes.len()
        )
        .into());
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&private_key_bytes);
    
    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key = signing_key.verifying_key();

    // 2. Crear timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();

    // 3. Crear mensaje
    let message = create_signing_message(address, nonce, operation, data, timestamp);
    let message_bytes = message.as_bytes();

    // 4. Firmar
    let signature: Signature = signing_key.sign(message_bytes);

    // 5. Convertir a hex
    let signature_hex = format!("0x{}", hex::encode(signature.to_bytes()));
    let public_key_hex = format!("0x{}", hex::encode(verifying_key.to_bytes()));

    Ok(SignedOperation {
        address: address.to_string(),
        nonce,
        operation: operation.to_string(),
        data: data.to_string(),
        timestamp,
        signature: signature_hex,
        public_key: public_key_hex,
    })
}

/// Preparar parámetros firmados para RPC call
pub fn prepare_signed_params(signed_op: &SignedOperation) -> Vec<Value> {
    vec![
        Value::String(signed_op.data.clone()),        // position_id u otro dato
        Value::String(signed_op.address.clone()),     // caller_address
        Value::Number(signed_op.nonce.into()),        // nonce
        Value::String(signed_op.signature.clone()),   // signature
        Value::String(signed_op.public_key.clone()),  // public_key
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signing_message_format() {
        let message = create_signing_message(
            "0x1234",
            5,
            "unstake",
            "position_123",
            1234567890,
        );
        
        assert!(message.contains("AVO_PROTOCOL"));
        assert!(message.contains("Address: 0x1234"));
        assert!(message.contains("Nonce: 5"));
        assert!(message.contains("Operation: unstake"));
        assert!(message.contains("Data: position_123"));
        assert!(message.contains("Timestamp: 1234567890"));
    }

    #[test]
    fn test_sign_operation() {
        // Private key de prueba (32 bytes)
        let private_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        
        let result = sign_operation(
            "0xTestAddress",
            1,
            "unstake",
            "B_0x123_1234567",
            private_key,
        );
        
        assert!(result.is_ok());
        let signed = result.unwrap();
        assert_eq!(signed.nonce, 1);
        assert!(signed.signature.starts_with("0x"));
        assert!(signed.public_key.starts_with("0x"));
        assert_eq!(signed.signature.len(), 130); // 0x + 128 hex chars (64 bytes)
        assert_eq!(signed.public_key.len(), 66); // 0x + 64 hex chars (32 bytes)
    }
}
