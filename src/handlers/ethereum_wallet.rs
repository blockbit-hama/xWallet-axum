/**
* filename: handlers/ethereum_wallet.rs
* author: HAMA
* date: 2025. 5. 23.
* description: Axum용 이더리움 지갑 HTTP 핸들러 (기존 warp 코드를 axum으로 변환)
**/

use axum::{Json, response::IntoResponse};
use axum::extract::State;
use tracing::{info, error, instrument};
use crate::AppState;
use crate::services::ethereum_wallet::EthereumWalletService;
use crate::model::ethereum_wallet::*;
use crate::error::WalletError;
use crate::response::success_response;

// ========================================
// 니모닉 관련 핸들러
// ========================================

/// 니모닉 생성 핸들러
#[instrument]
pub async fn generate_mnemonic(
  State(app_state): State<AppState>,
  Json(request): Json<MnemonicRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating mnemonic with {} words", request.word_count);
  
  match app_state.ethereum_service.generate_mnemonic(request.word_count) {
    Ok(response) => {
      info!("Mnemonic generated successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to generate mnemonic: {}", e);
      Err(e)
    }
  }
}

/// 니모닉 검증 핸들러
#[instrument]
pub async fn validate_mnemonic(
  State(app_state): State<AppState>,
  Json(request): Json<MnemonicValidationRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Validating mnemonic");
  
  match app_state.ethereum_service.validate_mnemonic(&request.mnemonic) {
    Ok(response) => {
      info!("Mnemonic validation completed: {}", response.valid);
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to validate mnemonic: {}", e);
      Err(e)
    }
  }
}

// ========================================
// 계정 생성 관련 핸들러
// ========================================

/// 계정 생성 핸들러
#[instrument]
pub async fn create_account(
  State(app_state): State<AppState>,
  Json(request): Json<AccountRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating account for path: {}", request.path);
  
  match app_state.ethereum_service.create_account(request) {
    Ok(response) => {
      info!("Account created successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create account: {}", e);
      Err(e)
    }
  }
}

/// 다중 계정 생성 핸들러
#[instrument]
pub async fn create_multiple_accounts(
  State(app_state): State<AppState>,
  Json(request): Json<MultipleAccountsRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating {} accounts for account index {}", request.count, request.account_index);
  
  match app_state.ethereum_service.create_multiple_accounts(request) {
    Ok(response) => {
      info!("Multiple accounts created successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create multiple accounts: {}", e);
      Err(e)
    }
  }
}

/// 개인키로부터 계정 생성 핸들러
#[instrument]
pub async fn create_account_from_private_key(
  State(app_state): State<AppState>,
  Json(request): Json<PrivateKeyRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating account from private key");
  
  match app_state.ethereum_service.create_account_from_private_key(request) {
    Ok(response) => {
      info!("Account created from private key successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create account from private key: {}", e);
      Err(e)
    }
  }
}

/// 랜덤 계정 생성 핸들러
#[instrument]
pub async fn create_random_account(
  State(app_state): State<AppState>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating random account");
  
  match app_state.ethereum_service.create_random_account() {
    Ok(response) => {
      info!("Random account created successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create random account: {}", e);
      Err(e)
    }
  }
}

// ========================================
// HD 지갑 관련 핸들러
// ========================================

/// HD 지갑 생성 핸들러
#[instrument]
pub async fn create_hd_wallet(
  State(app_state): State<AppState>,
  Json(request): Json<HdWalletRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating HD wallet");
  
  match app_state.ethereum_service.create_hd_wallet(request) {
    Ok(response) => {
      info!("HD wallet created successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create HD wallet: {}", e);
      Err(e)
    }
  }
}

/// 다중 계정 지갑 생성 핸들러
#[instrument]
pub async fn create_multi_account_wallet(
  State(app_state): State<AppState>,
  Json(request): Json<MultiAccountWalletRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating multi-account wallet with {} accounts", request.accounts.len());
  
  match app_state.ethereum_service.create_multi_account_wallet(request) {
    Ok(response) => {
      info!("Multi-account wallet created successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create multi-account wallet: {}", e);
      Err(e)
    }
  }
}

/// HD 지갑에 계정 추가 핸들러
#[instrument]
pub async fn add_account_to_wallet(
  State(app_state): State<AppState>,
  Json(request): Json<AddAccountRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Adding account to HD wallet");
  
  match app_state.ethereum_service.add_account_to_hd_wallet(request) {
    Ok(response) => {
      info!("Account added to HD wallet successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to add account to HD wallet: {}", e);
      Err(e)
    }
  }
}

/// 주소 생성 핸들러
#[instrument]
pub async fn generate_addresses(
  State(app_state): State<AppState>,
  Json(request): Json<GenerateAddressesRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Generating {} addresses for account {}", request.count, request.account_index);
  
  match app_state.ethereum_service.generate_addresses(request) {
    Ok(response) => {
      info!("Addresses generated successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to generate addresses: {}", e);
      Err(e)
    }
  }
}

/// 키스토어 생성 핸들러
#[instrument]
pub async fn create_keystore(
  State(app_state): State<AppState>,
  Json(request): Json<CreateKeystoreRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating keystore for address: {}", request.address);
  
  match app_state.ethereum_service.create_keystore(request) {
    Ok(response) => {
      info!("Keystore created successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create keystore: {}", e);
      Err(e)
    }
  }
}

// ========================================
// 서명 관련 핸들러
// ========================================

/// 메시지 서명 핸들러
#[instrument]
pub async fn sign_message(
  State(app_state): State<AppState>,
  Json(request): Json<SignMessageRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Signing message");
  
  match app_state.ethereum_service.sign_message(request) {
    Ok(response) => {
      info!("Message signed successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to sign message: {}", e);
      Err(e)
    }
  }
}

/// 서명 검증 핸들러
#[instrument]
pub async fn verify_signature(
  State(app_state): State<AppState>,
  Json(request): Json<VerifySignatureRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Verifying signature");
  
  match app_state.ethereum_service.verify_signature(request) {
    Ok(response) => {
      info!("Signature verification completed: {}", response.valid);
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to verify signature: {}", e);
      Err(e)
    }
  }
}

// ========================================
// 트랜잭션 관련 핸들러
// ========================================

/// 트랜잭션 생성 핸들러
#[instrument]
pub async fn create_transaction(
  State(app_state): State<AppState>,
  Json(request): Json<CreateTransactionRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating transaction to: {}", request.to);
  
  match app_state.ethereum_service.create_transaction(request) {
    Ok(response) => {
      info!("Transaction created successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create transaction: {}", e);
      Err(e)
    }
  }
}

/// 트랜잭션 서명 핸들러
#[instrument]
pub async fn sign_transaction(
  State(app_state): State<AppState>,
  Json(request): Json<SignTransactionRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Signing transaction: {}", request.transaction_hash);
  
  match app_state.ethereum_service.sign_transaction(request) {
    Ok(response) => {
      info!("Transaction signed successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to sign transaction: {}", e);
      Err(e)
    }
  }
}

/// Sepolia 네트워크로 트랜잭션 전송 핸들러
#[instrument]
pub async fn send_transaction(
  State(app_state): State<AppState>,
  Json(request): Json<SendTransactionRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Sending transaction to Sepolia network: {}", request.to);
  
  match app_state.ethereum_service.send_transaction(request).await {
    Ok(response) => {
      info!("Transaction sent successfully: {}", response.transaction_hash);
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to send transaction: {}", e);
      Err(e)
    }
  }
}

/// Raw 트랜잭션 전송 핸들러
#[instrument]
pub async fn send_raw_transaction(
  State(app_state): State<AppState>,
  Json(request): Json<SendRawTransactionRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Sending raw transaction to Sepolia network");
  
  match app_state.ethereum_service.send_raw_transaction(&request.signed_transaction).await {
    Ok(response) => {
      let raw_response = SendRawTransactionResponse {
        transaction_hash: response.transaction_hash,
        status: response.status,
      };
      
      info!("Raw transaction sent successfully: {}", raw_response.transaction_hash);
      Ok(success_response(raw_response))
    }
    Err(e) => {
      error!("Failed to send raw transaction: {}", e);
      Err(e)
    }
  }
}

/// 가스 추정 핸들러
#[instrument]
pub async fn estimate_gas(
  State(app_state): State<AppState>,
  Json(request): Json<EstimateGasRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Estimating gas for transaction to: {}", request.to);
  
  match app_state.ethereum_service.estimate_gas(request).await {
    Ok(response) => {
      info!("Gas estimation completed: {} (recommended: {})",
                      response.estimated_gas, response.gas_limit_recommended);
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to estimate gas: {}", e);
      Err(e)
    }
  }
}

/// 수수료 계산 핸들러
#[instrument]
pub async fn calculate_fee(
  State(app_state): State<AppState>,
  Json(request): Json<CalculateFeeRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Calculating fee for gas_limit: {}, gas_price: {} Gwei",
              request.gas_limit, request.gas_price_gwei);
  
  match app_state.ethereum_service.calculate_fee(request).await {
    Ok(response) => {
      info!("Fee calculation completed successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to calculate fee: {}", e);
      Err(e)
    }
  }
}

/// 네트워크 상태 확인 핸들러
#[instrument]
pub async fn get_network_status(
  State(app_state): State<AppState>) -> Result<impl IntoResponse, WalletError> {
  info!("Checking Sepolia network status");
  
  match app_state.ethereum_service.get_network_status().await {
    Ok(response) => {
      info!("Network status retrieved successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to get network status: {}", e);
      Err(e)
    }
  }
}

// ========================================
// 유틸리티 관련 핸들러
// ========================================

/// 단위 변환 핸들러
#[instrument]
pub async fn convert_units(
  State(app_state): State<AppState>,
  Json(request): Json<ConversionRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Converting {} {} to {}", request.value, request.from_unit, request.to_unit);
  
  match app_state.ethereum_service.convert_units(request) {
    Ok(response) => {
      info!("Unit conversion completed successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to convert units: {}", e);
      Err(e)
    }
  }
}

/// 주소 검증 핸들러
#[instrument]
pub async fn validate_address(
  State(app_state): State<AppState>,
  Json(request): Json<ValidateAddressRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Validating address: {}", request.address);
  
  match app_state.ethereum_service.validate_address(request) {
    Ok(response) => {
      info!("Address validation completed: valid={}, checksum_valid={}",
                      response.valid, response.checksum_valid);
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to validate address: {}", e);
      Err(e)
    }
  }
}

/// 주소 정보 조회 핸들러
#[instrument]
pub async fn get_address_info(
  State(app_state): State<AppState>,
  Json(request): Json<AddressInfoRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Getting address info for: {}", request.address);
  
  match app_state.ethereum_service.get_address_info(request) {
    Ok(response) => {
      info!("Address info retrieved successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to get address info: {}", e);
      Err(e)
    }
  }
}