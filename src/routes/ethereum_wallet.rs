/**
* filename : ethereum_wallet
* author : HAMA
* date: 2025. 5. 27.
* description: 
**/

/**
* filename: routes/ethereum_wallet.rs
* author: HAMA
* date: 2025. 5. 23.
* description: Axum 기반 이더리움 지갑 API 라우트
**/

use axum::{
  routing::{get, post},
  Router,
  Json,
};

use crate::handlers::ethereum_wallet;

/// 이더리움 지갑 관련 모든 라우트 구성
pub fn ethereum_routes() -> Router {
  Router::new()
    // ========================================
    // 니모닉 관련 라우트
    // ========================================
    .route(
      "/api/v1/mnemonic/generate",
      post(ethereum_wallet::generate_mnemonic)
    )
    .route(
      "/api/v1/mnemonic/validate",
      post(ethereum_wallet::validate_mnemonic)
    )
    
    // ========================================
    // 계정 생성 관련 라우트
    // ========================================
    .route(
      "/api/v1/account/create",
      post(ethereum_wallet::create_account)
    )
    .route(
      "/api/v1/account/create-multiple",
      post(ethereum_wallet::create_multiple_accounts)
    )
    .route(
      "/api/v1/account/from-private-key",
      post(ethereum_wallet::create_account_from_private_key)
    )
    .route(
      "/api/v1/account/random",
      post(ethereum_wallet::create_random_account)
    )
    
    // ========================================
    // HD 지갑 관련 라우트
    // ========================================
    .route(
      "/api/v1/wallet/hd/create",
      post(ethereum_wallet::create_hd_wallet)
    )
    .route(
      "/api/v1/wallet/multi-account/create",
      post(ethereum_wallet::create_multi_account_wallet)
    )
    .route(
      "/api/v1/wallet/add-account",
      post(ethereum_wallet::add_account_to_wallet)
    )
    .route(
      "/api/v1/wallet/generate-addresses",
      post(ethereum_wallet::generate_addresses)
    )
    .route(
      "/api/v1/wallet/keystore/create",
      post(ethereum_wallet::create_keystore)
    )
    
    // ========================================
    // 서명 관련 라우트
    // ========================================
    .route(
      "/api/v1/sign/message",
      post(ethereum_wallet::sign_message)
    )
    .route(
      "/api/v1/sign/verify",
      post(ethereum_wallet::verify_signature)
    )
    
    // ========================================
    // 트랜잭션 관련 라우트
    // ========================================
    .route(
      "/api/v1/transaction/create",
      post(ethereum_wallet::create_transaction)
    )
    .route(
      "/api/v1/transaction/sign",
      post(ethereum_wallet::sign_transaction)
    )
    .route(
      "/api/v1/transaction/send",
      post(ethereum_wallet::send_transaction)
    )
    .route(
      "/api/v1/transaction/send-raw",
      post(ethereum_wallet::send_raw_transaction)
    )
    .route(
      "/api/v1/transaction/estimate-gas",
      post(ethereum_wallet::estimate_gas)
    )
    .route(
      "/api/v1/transaction/calculate-fee",
      post(ethereum_wallet::calculate_fee)
    )
    .route(
      "/api/v1/network/status",
      get(ethereum_wallet::get_network_status)
    )
    
    // ========================================
    // 유틸리티 관련 라우트
    // ========================================
    .route(
      "/api/v1/utils/convert-units",
      post(ethereum_wallet::convert_units)
    )
    .route(
      "/api/v1/utils/validate-address",
      post(ethereum_wallet::validate_address)
    )
    .route(
      "/api/v1/utils/address-info",
      post(ethereum_wallet::get_address_info)
    )
}

/// API 문서화를 위한 엔드포인트 정보
pub fn get_ethereum_api_endpoints() -> Vec<ApiEndpoint> {
  vec![
    // 니모닉 관련
    ApiEndpoint::new("POST", "/api/v1/mnemonic/generate", "니모닉 생성"),
    ApiEndpoint::new("POST", "/api/v1/mnemonic/validate", "니모닉 검증"),
    
    // 계정 생성 관련
    ApiEndpoint::new("POST", "/api/v1/account/create", "계정 생성"),
    ApiEndpoint::new("POST", "/api/v1/account/create-multiple", "다중 계정 생성"),
    ApiEndpoint::new("POST", "/api/v1/account/from-private-key", "개인키로 계정 생성"),
    ApiEndpoint::new("POST", "/api/v1/account/random", "랜덤 계정 생성"),
    
    // HD 지갑 관련
    ApiEndpoint::new("POST", "/api/v1/wallet/hd/create", "HD 지갑 생성"),
    ApiEndpoint::new("POST", "/api/v1/wallet/multi-account/create", "다중 계정 지갑 생성"),
    ApiEndpoint::new("POST", "/api/v1/wallet/add-account", "계정 추가"),
    ApiEndpoint::new("POST", "/api/v1/wallet/generate-addresses", "주소 생성"),
    ApiEndpoint::new("POST", "/api/v1/wallet/keystore/create", "키스토어 생성"),
    
    // 서명 관련
    ApiEndpoint::new("POST", "/api/v1/sign/message", "메시지 서명"),
    ApiEndpoint::new("POST", "/api/v1/sign/verify", "서명 검증"),
    
    // 트랜잭션 관련
    ApiEndpoint::new("POST", "/api/v1/transaction/create", "트랜잭션 생성"),
    ApiEndpoint::new("POST", "/api/v1/transaction/sign", "트랜잭션 서명"),
    ApiEndpoint::new("POST", "/api/v1/transaction/send", "🔥 Sepolia 트랜잭션 전송"),
    ApiEndpoint::new("POST", "/api/v1/transaction/send-raw", "Raw 트랜잭션 전송"),
    ApiEndpoint::new("POST", "/api/v1/transaction/estimate-gas", "가스 추정"),
    ApiEndpoint::new("POST", "/api/v1/transaction/calculate-fee", "수수료 계산"),
    ApiEndpoint::new("GET", "/api/v1/network/status", "네트워크 상태"),
    
    // 유틸리티 관련
    ApiEndpoint::new("POST", "/api/v1/utils/convert-units", "단위 변환"),
    ApiEndpoint::new("POST", "/api/v1/utils/validate-address", "주소 검증"),
    ApiEndpoint::new("POST", "/api/v1/utils/address-info", "주소 정보"),
  ]
}

/// API 엔드포인트 정보
#[derive(Debug, Clone)]
pub struct ApiEndpoint {
  pub method: String,
  pub path: String,
  pub description: String,
}

impl ApiEndpoint {
  pub fn new(method: &str, path: &str, description: &str) -> Self {
    Self {
      method: method.to_string(),
      path: path.to_string(),
      description: description.to_string(),
    }
  }
}