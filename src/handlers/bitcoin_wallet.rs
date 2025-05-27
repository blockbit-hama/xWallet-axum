/**
* filename: handlers/bitcoin_wallet.rs
* author: HAMA
* date: 2025. 5. 27.
* description: Axum용 비트코인 지갑 HTTP 핸들러 (기존 warp 코드를 axum으로 변환)
**/

use axum::{Json, response::IntoResponse};
use tracing::{info, error, instrument};
use crate::services::bitcoin_wallet::BitcoinWalletService;
use crate::model::bitcoin_wallet::*;
use crate::error::WalletError;
use crate::response::success_response;

// ========================================
// 니모닉 관련 핸들러
// ========================================

/// 비트코인 니모닉 생성 핸들러
#[instrument]
pub async fn generate_mnemonic(Json(request): Json<BitcoinMnemonicRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating Bitcoin mnemonic with {} words", request.word_count);
  
  let service = BitcoinWalletService::new();
  match service.generate_mnemonic(request.word_count) {
    Ok(response) => {
      info!("Bitcoin mnemonic generated successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to generate Bitcoin mnemonic: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// 비트코인 니모닉 검증 핸들러
#[instrument]
pub async fn validate_mnemonic(Json(request): Json<BitcoinMnemonicValidationRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Validating Bitcoin mnemonic");
  
  let service = BitcoinWalletService::new();
  match service.validate_mnemonic(&request.mnemonic) {
    Ok(response) => {
      info!("Bitcoin mnemonic validation completed: {}", response.valid);
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to validate Bitcoin mnemonic: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// 니모닉에서 시드 생성 핸들러
#[instrument]
pub async fn mnemonic_to_seed(Json(request): Json<BitcoinMnemonicToSeedRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Converting Bitcoin mnemonic to seed");
  
  let service = BitcoinWalletService::new();
  match service.mnemonic_to_seed(&request.mnemonic, request.passphrase.as_deref()) {
    Ok(response) => {
      info!("Bitcoin mnemonic to seed conversion completed");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to convert Bitcoin mnemonic to seed: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// 니모닉에서 확장 개인키 생성 핸들러
#[instrument]
pub async fn mnemonic_to_xprv(Json(request): Json<BitcoinMnemonicToXprvRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Converting Bitcoin mnemonic to xprv for network: {:?}", request.network);
  
  let service = BitcoinWalletService::new();
  match service.mnemonic_to_xprv(&request.mnemonic, request.network) {
    Ok(response) => {
      info!("Bitcoin mnemonic to xprv conversion completed");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to convert Bitcoin mnemonic to xprv: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

// ========================================
// 키 관련 핸들러
// ========================================

/// 자식 키 파생 핸들러
#[instrument]
pub async fn derive_child_key(Json(request): Json<BitcoinDeriveChildKeyRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Deriving Bitcoin child key for path: {}", request.derivation_path);
  
  let service = BitcoinWalletService::new();
  match service.derive_child_key(&request.parent_xprv, &request.derivation_path) {
    Ok(response) => {
      info!("Bitcoin child key derived successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to derive Bitcoin child key: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// 확장 개인키에서 WIF 추출 핸들러
#[instrument]
pub async fn xprv_to_wif(Json(request): Json<BitcoinXprvToWifRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Converting Bitcoin xprv to WIF for path: {}", request.derivation_path);
  
  let service = BitcoinWalletService::new();
  match service.xprv_to_wif(&request.xprv, &request.derivation_path, request.network) {
    Ok(response) => {
      info!("Bitcoin xprv to WIF conversion completed");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to convert Bitcoin xprv to WIF: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// WIF에서 공개키 추출 핸들러
#[instrument]
pub async fn wif_to_public_key(Json(request): Json<BitcoinWifToPublicKeyRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Converting Bitcoin WIF to public key");
  
  let service = BitcoinWalletService::new();
  match service.wif_to_public_key(&request.private_key_wif) {
    Ok(response) => {
      info!("Bitcoin WIF to public key conversion completed");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to convert Bitcoin WIF to public key: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

// ========================================
// 주소 관련 핸들러
// ========================================

/// WIF에서 주소 생성 핸들러
#[instrument]
pub async fn address_from_wif(Json(request): Json<BitcoinAddressFromWifRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating Bitcoin address from WIF for network: {:?}", request.network);
  
  let service = BitcoinWalletService::new();
  match service.address_from_wif(&request.private_key_wif, request.network, request.address_type) {
    Ok(response) => {
      info!("Bitcoin address created from WIF successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create Bitcoin address from WIF: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// 확장 개인키에서 주소 생성 핸들러
#[instrument]
pub async fn address_from_xprv(Json(request): Json<BitcoinAddressFromXprvRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating Bitcoin address from xprv for path: {}", request.derivation_path);
  
  let service = BitcoinWalletService::new();
  match service.address_from_xprv(&request.xprv, &request.derivation_path, request.network, request.address_type) {
    Ok(response) => {
      info!("Bitcoin address created from xprv successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create Bitcoin address from xprv: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// 니모닉에서 주소 생성 핸들러
#[instrument]
pub async fn address_from_mnemonic(Json(request): Json<BitcoinAddressFromMnemonicRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating Bitcoin address from mnemonic for path: {}", request.derivation_path);
  
  let service = BitcoinWalletService::new();
  match service.address_from_mnemonic(&request.mnemonic, &request.derivation_path, request.network, request.address_type) {
    Ok(response) => {
      info!("Bitcoin address created from mnemonic successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create Bitcoin address from mnemonic: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// 공개키에서 주소 생성 핸들러
#[instrument]
pub async fn address_from_public_key(Json(request): Json<BitcoinAddressFromPublicKeyRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating Bitcoin address from public key for network: {:?}", request.network);
  
  let service = BitcoinWalletService::new();
  match service.address_from_public_key(&request.public_key_hex, request.network, request.address_type) {
    Ok(response) => {
      info!("Bitcoin address created from public key successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create Bitcoin address from public key: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

// ========================================
// BIP-84 관련 핸들러
// ========================================

/// BIP-84 디스크립터 생성 핸들러
#[instrument]
pub async fn create_bip84_descriptors(Json(request): Json<BitcoinBip84DescriptorsRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Creating BIP-84 descriptors for network: {:?}", request.network);
  
  let service = BitcoinWalletService::new();
  match service.create_bip84_descriptors(&request.mnemonic, request.network) {
    Ok(response) => {
      info!("BIP-84 descriptors created successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to create BIP-84 descriptors: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// BIP-84 주소 생성 핸들러
#[instrument]
pub async fn get_bip84_address(Json(request): Json<BitcoinBip84AddressRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Getting BIP-84 address for index: {}, change: {}", request.index, request.is_change);
  
  let service = BitcoinWalletService::new();
  match service.get_bip84_address(&request.mnemonic, request.network, request.is_change, request.index) {
    Ok(response) => {
      info!("BIP-84 address retrieved successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to get BIP-84 address: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// BIP-84 다음 주소 생성 핸들러
#[instrument]
pub async fn get_bip84_next_address(Json(request): Json<BitcoinBip84NextAddressRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Getting next BIP-84 address, change: {}", request.is_change);
  
  let service = BitcoinWalletService::new();
  match service.get_bip84_next_address(&request.mnemonic, request.network, request.is_change, request.current_index) {
    Ok(response) => {
      info!("Next BIP-84 address retrieved successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to get next BIP-84 address: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// BIP-84 다중 주소 생성 핸들러
#[instrument]
pub async fn get_bip84_multiple_addresses(Json(request): Json<BitcoinBip84MultipleAddressesRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Getting multiple BIP-84 addresses: {} external, {} internal", request.external_count, request.internal_count);
  
  let service = BitcoinWalletService::new();
  match service.get_bip84_multiple_addresses(&request.mnemonic, request.network, request.external_count, request.internal_count, request.start_index) {
    Ok(response) => {
      info!("Multiple BIP-84 addresses retrieved successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to get multiple BIP-84 addresses: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

// ========================================
// 유틸리티 관련 핸들러
// ========================================

/// 개인키 검증 핸들러
#[instrument]
pub async fn validate_private_key(Json(request): Json<BitcoinValidatePrivateKeyRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Validating Bitcoin private key for network: {:?}", request.expected_network);
  
  let service = BitcoinWalletService::new();
  match service.validate_private_key(&request.private_key_wif, request.expected_network) {
    Ok(response) => {
      info!("Bitcoin private key validation completed: valid={}, network_match={}", response.valid, response.network_match);
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to validate Bitcoin private key: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// 주소 검증 핸들러
#[instrument]
pub async fn validate_address(Json(request): Json<BitcoinValidateAddressRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Validating Bitcoin address: {}", request.address);
  
  let service = BitcoinWalletService::new();
  match service.validate_address(&request.address, request.expected_network) {
    Ok(response) => {
      info!("Bitcoin address validation completed: valid={}, network_match={}", response.valid, response.network_match);
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to validate Bitcoin address: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

/// 네트워크 정보 조회 핸들러
#[instrument]
pub async fn get_network_info(Json(request): Json<BitcoinNetworkInfoRequest>) -> Result<impl IntoResponse, WalletError> {
  info!("Getting Bitcoin network info for: {:?}", request.network);
  
  let service = BitcoinWalletService::new();
  match service.get_network_info(request.network) {
    Ok(response) => {
      info!("Bitcoin network info retrieved successfully");
      Ok(success_response(response))
    }
    Err(e) => {
      error!("Failed to get Bitcoin network info: {}", e);
      Err(WalletError::BitcoinError(e.to_string()))
    }
  }
}

// ========================================
// 헬스체크 핸들러
// ========================================

/// 비트코인 지갑 헬스체크 핸들러
#[instrument]
pub async fn health_check() -> Result<impl IntoResponse, WalletError> {
  info!("Bitcoin wallet health check requested");
  
  let health_data = serde_json::json!({
    "status": "ok",
    "service": "Bitcoin Wallet Service",
    "version": "1.0.0",
    "timestamp": chrono::Utc::now().to_rfc3339(),
    "uptime": std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap_or_default()
      .as_secs()
  });
  
  Ok(success_response(health_data))
}