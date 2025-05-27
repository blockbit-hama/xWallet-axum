/**
* filename: error.rs
* author: HAMA
* date: 2025. 5. 27.
* description: Axum용 통합 에러 처리 (이더리움 + 비트코인)
**/

use axum::{
  extract::rejection::JsonRejection,
  http::StatusCode,
  response::{IntoResponse, Response},
  Json,
};
use serde::{Deserialize, Serialize};
use tracing::error;

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum WalletError {
  // ========================================
  // 니모닉 관련 오류
  // ========================================
  #[error("Invalid mnemonic: {0}")]
  InvalidMnemonic(String),
  
  #[error("Failed to generate mnemonic")]
  MnemonicGenerationFailed,
  
  #[error("Unsupported word count: {0}")]
  UnsupportedWordCount(usize),
  
  // ========================================
  // 계정/주소 관련 오류
  // ========================================
  #[error("Invalid private key: {0}")]
  InvalidPrivateKey(String),
  
  #[error("Invalid address: {0}")]
  InvalidAddress(String),
  
  #[error("Failed to create account")]
  AccountCreationFailed,
  
  #[error("Invalid derivation path: {0}")]
  InvalidDerivationPath(String),
  
  #[error("Invalid public key: {0}")]
  InvalidPublicKey(String),
  
  // ========================================
  // 트랜잭션 관련 오류
  // ========================================
  #[error("Transaction creation failed: {0}")]
  TransactionCreationFailed(String),
  
  #[error("Signing error: {0}")]
  SigningError(String),
  
  #[error("Invalid nonce")]
  InvalidNonce,
  
  #[error("Insufficient funds")]
  InsufficientFunds,
  
  #[error("Gas estimation failed")]
  GasEstimationFailed,
  
  // ========================================
  // 서명 관련 오류
  // ========================================
  #[error("Signature verification failed: {0}")]
  SignatureVerificationFailed(String),
  
  #[error("Message signing failed")]
  MessageSigningFailed,
  
  // ========================================
  // HD 지갑 관련 오류
  // ========================================
  #[error("HD wallet creation failed")]
  HDWalletCreationFailed,
  
  #[error("Wallet creation failed: {0}")]
  WalletCreationFailed(String),
  
  #[error("Key derivation failed: {0}")]
  KeyDerivationFailed(String),
  
  // ========================================
  // 키스토어 관련 오류
  // ========================================
  #[error("Keystore error: {0}")]
  KeystoreError(String),
  
  #[error("Keystore decryption failed")]
  KeystoreDecryptionFailed,
  
  #[error("Invalid password")]
  InvalidPassword,
  
  // ========================================
  // 단위 변환 오류
  // ========================================
  #[error("Unit conversion error: {0}")]
  UnitConversionError(String),
  
  #[error("Invalid unit: {0}")]
  InvalidUnit(String),
  
  // ========================================
  // 네트워크 관련 오류
  // ========================================
  #[error("Network error: {0}")]
  NetworkError(String),
  
  #[error("Connection failed: {0}")]
  ConnectionFailed(String),
  
  #[error("RPC error: {0}")]
  RpcError(String),
  
  #[error("Invalid network: {0}")]
  InvalidNetwork(String),
  
  // ========================================
  // 비트코인 관련 오류
  // ========================================
  #[error("Bitcoin error: {0}")]
  BitcoinError(String),
  
  #[error("Bitcoin address generation failed: {0}")]
  BitcoinAddressGenerationFailed(String),
  
  #[error("Bitcoin descriptor creation failed: {0}")]
  BitcoinDescriptorCreationFailed(String),
  
  #[error("Bitcoin BIP32 error: {0}")]
  BitcoinBip32Error(String),
  
  #[error("Bitcoin BIP39 error: {0}")]
  BitcoinBip39Error(String),
  
  #[error("Bitcoin Secp256k1 error: {0}")]
  BitcoinSecp256k1Error(String),
  
  // ========================================
  // 이더리움 관련 오류
  // ========================================
  #[error("Ethereum error: {0}")]
  EthereumError(String),
  
  #[error("Web3 error: {0}")]
  Web3Error(String),
  
  // ========================================
  // 일반적인 오류
  // ========================================
  #[error("Invalid input: {0}")]
  InvalidInput(String),
  
  #[error("Serialization error: {0}")]
  SerializationError(String),
  
  #[error("Internal error: {0}")]
  InternalError(String),
  
  #[error("Validation error: {0}")]
  ValidationError(String),
  
  #[error("Parse error: {0}")]
  ParseError(String),
}

/// HTTP 응답용 에러 구조체
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
  pub success: bool,
  pub error: ErrorDetail,
  pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
  pub error: String,
  pub message: String,
  pub code: u16,
}

impl WalletError {
  /// WalletError를 ErrorResponse로 변환
  pub fn to_error_response(&self) -> ErrorResponse {
    let (error_type, message, code) = match self {
      // 니모닉 관련
      WalletError::InvalidMnemonic(msg) => ("InvalidMnemonic", msg.clone(), 400),
      WalletError::MnemonicGenerationFailed => ("MnemonicGenerationFailed", "Failed to generate mnemonic".to_string(), 500),
      WalletError::UnsupportedWordCount(count) => ("UnsupportedWordCount", format!("Unsupported word count: {}", count), 400),
      
      // 계정/주소 관련
      WalletError::InvalidPrivateKey(msg) => ("InvalidPrivateKey", msg.clone(), 400),
      WalletError::InvalidAddress(addr) => ("InvalidAddress", format!("Invalid address: {}", addr), 400),
      WalletError::AccountCreationFailed => ("AccountCreationFailed", "Failed to create account".to_string(), 500),
      WalletError::InvalidDerivationPath(path) => ("InvalidDerivationPath", format!("Invalid derivation path: {}", path), 400),
      WalletError::InvalidPublicKey(msg) => ("InvalidPublicKey", msg.clone(), 400),
      
      // 트랜잭션 관련
      WalletError::TransactionCreationFailed(msg) => ("TransactionCreationFailed", msg.clone(), 400),
      WalletError::SigningError(msg) => ("SigningError", msg.clone(), 400),
      WalletError::InvalidNonce => ("InvalidNonce", "Invalid transaction nonce".to_string(), 400),
      WalletError::InsufficientFunds => ("InsufficientFunds", "Insufficient funds for transaction".to_string(), 400),
      WalletError::GasEstimationFailed => ("GasEstimationFailed", "Failed to estimate gas".to_string(), 400),
      
      // 서명 관련
      WalletError::SignatureVerificationFailed(msg) => ("SignatureVerificationFailed", msg.clone(), 400),
      WalletError::MessageSigningFailed => ("MessageSigningFailed", "Failed to sign message".to_string(), 500),
      
      // HD 지갑 관련
      WalletError::HDWalletCreationFailed => ("HDWalletCreationFailed", "Failed to create HD wallet".to_string(), 500),
      WalletError::WalletCreationFailed(msg) => ("WalletCreationFailed", msg.clone(), 500),
      WalletError::KeyDerivationFailed(msg) => ("KeyDerivationFailed", msg.clone(), 500),
      
      // 키스토어 관련
      WalletError::KeystoreError(msg) => ("KeystoreError", msg.clone(), 400),
      WalletError::KeystoreDecryptionFailed => ("KeystoreDecryptionFailed", "Failed to decrypt keystore".to_string(), 400),
      WalletError::InvalidPassword => ("InvalidPassword", "Invalid password provided".to_string(), 400),
      
      // 단위 변환
      WalletError::UnitConversionError(msg) => ("UnitConversionError", msg.clone(), 400),
      WalletError::InvalidUnit(unit) => ("InvalidUnit", format!("Invalid unit: {}", unit), 400),
      
      // 네트워크 관련
      WalletError::NetworkError(msg) => ("NetworkError", msg.clone(), 500),
      WalletError::ConnectionFailed(msg) => ("ConnectionFailed", msg.clone(), 503),
      WalletError::RpcError(msg) => ("RpcError", msg.clone(), 502),
      WalletError::InvalidNetwork(msg) => ("InvalidNetwork", msg.clone(), 400),
      
      // 비트코인 관련
      WalletError::BitcoinError(msg) => ("BitcoinError", msg.clone(), 400),
      WalletError::BitcoinAddressGenerationFailed(msg) => ("BitcoinAddressGenerationFailed", msg.clone(), 500),
      WalletError::BitcoinDescriptorCreationFailed(msg) => ("BitcoinDescriptorCreationFailed", msg.clone(), 500),
      WalletError::BitcoinBip32Error(msg) => ("BitcoinBip32Error", msg.clone(), 400),
      WalletError::BitcoinBip39Error(msg) => ("BitcoinBip39Error", msg.clone(), 400),
      WalletError::BitcoinSecp256k1Error(msg) => ("BitcoinSecp256k1Error", msg.clone(), 400),
      
      // 이더리움 관련
      WalletError::EthereumError(msg) => ("EthereumError", msg.clone(), 400),
      WalletError::Web3Error(msg) => ("Web3Error", msg.clone(), 400),
      
      // 일반적인 오류
      WalletError::InvalidInput(msg) => ("InvalidInput", msg.clone(), 400),
      WalletError::SerializationError(msg) => ("SerializationError", msg.clone(), 500),
      WalletError::InternalError(msg) => ("InternalError", msg.clone(), 500),
      WalletError::ValidationError(msg) => ("ValidationError", msg.clone(), 400),
      WalletError::ParseError(msg) => ("ParseError", msg.clone(), 400),
    };
    
    ErrorResponse {
      success: false,
      error: ErrorDetail {
        error: error_type.to_string(),
        message,
        code,
      },
      timestamp: chrono::Utc::now().to_rfc3339(),
    }
  }
  
  /// HTTP 상태 코드 매핑
  pub fn status_code(&self) -> StatusCode {
    match self {
      // 400 Bad Request
      WalletError::InvalidMnemonic(_) |
      WalletError::UnsupportedWordCount(_) |
      WalletError::InvalidPrivateKey(_) |
      WalletError::InvalidAddress(_) |
      WalletError::InvalidDerivationPath(_) |
      WalletError::InvalidPublicKey(_) |
      WalletError::TransactionCreationFailed(_) |
      WalletError::SigningError(_) |
      WalletError::InvalidNonce |
      WalletError::InsufficientFunds |
      WalletError::GasEstimationFailed |
      WalletError::SignatureVerificationFailed(_) |
      WalletError::KeystoreError(_) |
      WalletError::KeystoreDecryptionFailed |
      WalletError::InvalidPassword |
      WalletError::UnitConversionError(_) |
      WalletError::InvalidUnit(_) |
      WalletError::InvalidNetwork(_) |
      WalletError::BitcoinError(_) |
      WalletError::BitcoinBip32Error(_) |
      WalletError::BitcoinBip39Error(_) |
      WalletError::BitcoinSecp256k1Error(_) |
      WalletError::EthereumError(_) |
      WalletError::Web3Error(_) |
      WalletError::InvalidInput(_) |
      WalletError::ValidationError(_) |
      WalletError::ParseError(_) => StatusCode::BAD_REQUEST,
      
      // 502 Bad Gateway
      WalletError::RpcError(_) => StatusCode::BAD_GATEWAY,
      
      // 503 Service Unavailable
      WalletError::ConnectionFailed(_) => StatusCode::SERVICE_UNAVAILABLE,
      
      // 500 Internal Server Error (기본값)
      _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
  }
}

// Axum IntoResponse 구현
impl IntoResponse for WalletError {
  fn into_response(self) -> Response {
    error!("API Error: {}", self);
    
    let error_response = self.to_error_response();
    let status_code = self.status_code();
    
    (status_code, Json(error_response)).into_response()
  }
}

// ========================================
// 다른 에러 타입들로부터 WalletError로 변환
// ========================================

impl From<serde_json::Error> for WalletError {
  fn from(err: serde_json::Error) -> Self {
    WalletError::SerializationError(err.to_string())
  }
}

impl From<std::io::Error> for WalletError {
  fn from(err: std::io::Error) -> Self {
    WalletError::InternalError(err.to_string())
  }
}

impl From<reqwest::Error> for WalletError {
  fn from(err: reqwest::Error) -> Self {
    if err.is_connect() {
      WalletError::ConnectionFailed(err.to_string())
    } else if err.is_timeout() {
      WalletError::NetworkError(format!("Request timeout: {}", err))
    } else {
      WalletError::NetworkError(err.to_string())
    }
  }
}

// JSON 파싱 에러 처리
impl From<JsonRejection> for WalletError {
  fn from(rejection: JsonRejection) -> Self {
    WalletError::InvalidInput(format!("JSON parsing error: {}", rejection))
  }
}

// 비트코인 관련 에러 변환
impl From<crate::model::bitcoin_wallet::BitcoinWalletError> for WalletError {
  fn from(err: crate::model::bitcoin_wallet::BitcoinWalletError) -> Self {
    use crate::model::bitcoin_wallet::BitcoinWalletError as BWE;
    
    match err {
      BWE::InvalidMnemonic(msg) => WalletError::InvalidMnemonic(msg),
      BWE::InvalidPrivateKey(msg) => WalletError::InvalidPrivateKey(msg),
      BWE::InvalidAddress(msg) => WalletError::InvalidAddress(msg),
      BWE::InvalidDerivationPath(msg) => WalletError::InvalidDerivationPath(msg),
      BWE::InvalidPublicKey(msg) => WalletError::InvalidPublicKey(msg),
      BWE::InvalidNetwork(msg) => WalletError::InvalidNetwork(msg),
      BWE::KeyDerivationFailed(msg) => WalletError::KeyDerivationFailed(msg),
      BWE::AddressGenerationFailed(msg) => WalletError::BitcoinAddressGenerationFailed(msg),
      BWE::DescriptorCreationFailed(msg) => WalletError::BitcoinDescriptorCreationFailed(msg),
      BWE::Secp256k1Error(msg) => WalletError::BitcoinSecp256k1Error(msg),
      BWE::Bip32Error(msg) => WalletError::BitcoinBip32Error(msg),
      BWE::Bip39Error(msg) => WalletError::BitcoinBip39Error(msg),
      BWE::InternalError(msg) => WalletError::InternalError(msg),
    }
  }
}

// ========================================
// 간편한 에러 생성 함수들
// ========================================

/// 니모닉 관련 에러
pub fn invalid_mnemonic(msg: &str) -> WalletError {
  WalletError::InvalidMnemonic(msg.to_string())
}

/// 개인키 관련 에러
pub fn invalid_private_key(msg: &str) -> WalletError {
  WalletError::InvalidPrivateKey(msg.to_string())
}

/// 주소 관련 에러
pub fn invalid_address(addr: &str) -> WalletError {
  WalletError::InvalidAddress(addr.to_string())
}

/// 트랜잭션 관련 에러
pub fn transaction_failed(msg: &str) -> WalletError {
  WalletError::TransactionCreationFailed(msg.to_string())
}

/// 네트워크 관련 에러
pub fn network_error(msg: &str) -> WalletError {
  WalletError::NetworkError(msg.to_string())
}

/// 내부 에러
pub fn internal_error(msg: &str) -> WalletError {
  WalletError::InternalError(msg.to_string())
}

/// 비트코인 관련 에러
pub fn bitcoin_error(msg: &str) -> WalletError {
  WalletError::BitcoinError(msg.to_string())
}

/// 이더리움 관련 에러
pub fn ethereum_error(msg: &str) -> WalletError {
  WalletError::EthereumError(msg.to_string())
}

/// 검증 에러
pub fn validation_error(msg: &str) -> WalletError {
  WalletError::ValidationError(msg.to_string())
}

/// 파싱 에러
pub fn parse_error(msg: &str) -> WalletError {
  WalletError::ParseError(msg.to_string())
}