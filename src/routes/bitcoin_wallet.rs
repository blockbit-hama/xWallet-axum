/**
* filename: routes/bitcoin_wallet.rs
* author: HAMA
* date: 2025. 5. 27.
* description: Axum 기반 비트코인 지갑 API 라우트
**/

use axum::{
  routing::{get, post},
  Router,
};

use crate::handlers::bitcoin_wallet;

/// 비트코인 지갑 관련 모든 라우트 구성
pub fn bitcoin_routes() -> Router {
  Router::new()
    // ========================================
    // 니모닉 관련 라우트
    // ========================================
    .route(
      "/api/v1/bitcoin/mnemonic/generate",
      post(bitcoin_wallet::generate_mnemonic)
    )
    .route(
      "/api/v1/bitcoin/mnemonic/validate",
      post(bitcoin_wallet::validate_mnemonic)
    )
    .route(
      "/api/v1/bitcoin/mnemonic/to-seed",
      post(bitcoin_wallet::mnemonic_to_seed)
    )
    .route(
      "/api/v1/bitcoin/mnemonic/to-xprv",
      post(bitcoin_wallet::mnemonic_to_xprv)
    )
    
    // ========================================
    // 키 관련 라우트
    // ========================================
    .route(
      "/api/v1/bitcoin/key/derive-child",
      post(bitcoin_wallet::derive_child_key)
    )
    .route(
      "/api/v1/bitcoin/key/xprv-to-wif",
      post(bitcoin_wallet::xprv_to_wif)
    )
    .route(
      "/api/v1/bitcoin/key/wif-to-public",
      post(bitcoin_wallet::wif_to_public_key)
    )
    
    // ========================================
    // 주소 관련 라우트
    // ========================================
    .route(
      "/api/v1/bitcoin/address/from-wif",
      post(bitcoin_wallet::address_from_wif)
    )
    .route(
      "/api/v1/bitcoin/address/from-xprv",
      post(bitcoin_wallet::address_from_xprv)
    )
    .route(
      "/api/v1/bitcoin/address/from-mnemonic",
      post(bitcoin_wallet::address_from_mnemonic)
    )
    .route(
      "/api/v1/bitcoin/address/from-public-key",
      post(bitcoin_wallet::address_from_public_key)
    )
    
    // ========================================
    // BIP-84 관련 라우트
    // ========================================
    .route(
      "/api/v1/bitcoin/bip84/descriptors/create",
      post(bitcoin_wallet::create_bip84_descriptors)
    )
    .route(
      "/api/v1/bitcoin/bip84/address",
      post(bitcoin_wallet::get_bip84_address)
    )
    .route(
      "/api/v1/bitcoin/bip84/next-address",
      post(bitcoin_wallet::get_bip84_next_address)
    )
    .route(
      "/api/v1/bitcoin/bip84/multiple-addresses",
      post(bitcoin_wallet::get_bip84_multiple_addresses)
    )
    
    // ========================================
    // 유틸리티 관련 라우트
    // ========================================
    .route(
      "/api/v1/bitcoin/utils/validate-private-key",
      post(bitcoin_wallet::validate_private_key)
    )
    .route(
      "/api/v1/bitcoin/utils/validate-address",
      post(bitcoin_wallet::validate_address)
    )
    .route(
      "/api/v1/bitcoin/utils/network-info",
      post(bitcoin_wallet::get_network_info)
    )
    
    // ========================================
    // 헬스체크
    // ========================================
    .route(
      "/api/v1/bitcoin/health",
      get(bitcoin_wallet::health_check)
    )
}

/// API 문서화를 위한 엔드포인트 정보
pub fn get_bitcoin_api_endpoints() -> Vec<ApiEndpoint> {
  vec![
    // 니모닉 관련
    ApiEndpoint::new("POST", "/api/v1/bitcoin/mnemonic/generate", "비트코인 니모닉 생성"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/mnemonic/validate", "비트코인 니모닉 검증"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/mnemonic/to-seed", "니모닉에서 시드 생성"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/mnemonic/to-xprv", "니모닉에서 확장 개인키 생성"),
    
    // 키 관련
    ApiEndpoint::new("POST", "/api/v1/bitcoin/key/derive-child", "자식 키 파생"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/key/xprv-to-wif", "확장 개인키에서 WIF 추출"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/key/wif-to-public", "WIF에서 공개키 추출"),
    
    // 주소 관련
    ApiEndpoint::new("POST", "/api/v1/bitcoin/address/from-wif", "WIF에서 주소 생성"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/address/from-xprv", "확장 개인키에서 주소 생성"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/address/from-mnemonic", "니모닉에서 주소 생성"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/address/from-public-key", "공개키에서 주소 생성"),
    
    // BIP-84 관련
    ApiEndpoint::new("POST", "/api/v1/bitcoin/bip84/descriptors/create", "BIP-84 디스크립터 생성"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/bip84/address", "BIP-84 주소 생성"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/bip84/next-address", "BIP-84 다음 주소 생성"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/bip84/multiple-addresses", "BIP-84 다중 주소 생성"),
    
    // 유틸리티 관련
    ApiEndpoint::new("POST", "/api/v1/bitcoin/utils/validate-private-key", "개인키 검증"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/utils/validate-address", "주소 검증"),
    ApiEndpoint::new("POST", "/api/v1/bitcoin/utils/network-info", "네트워크 정보 조회"),
    
    // 헬스체크
    ApiEndpoint::new("GET", "/api/v1/bitcoin/health", "비트코인 지갑 헬스체크"),
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