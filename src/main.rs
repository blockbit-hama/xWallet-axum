/**
* filename: main.rs
* author: HAMA
* date: 2025. 5. 27.
* description: Axum 0.8.4 기반 통합 이더리움 + 비트코인 지갑 API 서버 (업데이트)
**/

use axum::{
    http::{
        header::{CONTENT_TYPE, AUTHORIZATION},
        HeaderValue, Method,
    },
    routing::get,
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod error;
mod response;

mod routes;
mod handlers;
mod model;
mod services;

#[derive(Clone, Debug)]
pub struct AppState {
    pub ethereum_service: Arc<EthereumWalletService>,
    pub bitcoin_service: Arc<BitcoinWalletService>,  // 나중에 추가
}

use routes::{
    ethereum_wallet::ethereum_routes,
    bitcoin_wallet::bitcoin_routes  // 비트코인 라우트 추가
};
use crate::config::Config;
use crate::services::bitcoin_wallet::BitcoinWalletService;
use crate::services::ethereum_wallet::EthereumWalletService;

/// 헬스체크 핸들러
async fn health_check() -> axum::response::Json<serde_json::Value> {
    axum::response::Json(serde_json::json!({
        "status": "ok",
        "service": "Crypto Wallet API",
        "version": "1.0.0",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "uptime": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }))
}

/// 애플리케이션 라우터 구성
fn create_app(app_state: AppState) -> Router {
    // CORS 설정
    let cors = CorsLayer::new()
      .allow_origin("*".parse::<HeaderValue>().unwrap())
      .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
      .allow_headers([CONTENT_TYPE, AUTHORIZATION]);
    
    // 트레이싱 레이어
    let trace_layer = TraceLayer::new_for_http()
      .make_span_with(DefaultMakeSpan::default().include_headers(true));
    
    // 라우터 구성
    Router::new()
      .route("/health", get(health_check))
      .merge(ethereum_routes())
      .merge(bitcoin_routes())  // 비트코인 라우트 활성화
      .layer(
          ServiceBuilder::new()
            .layer(trace_layer)
            .layer(cors)
      )
      .with_state(app_state)
}

/// 로깅 초기화
fn init_logging(log_level: &str) {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| {
        format!("xWallet={},axum={},tower_http={}", log_level, log_level, log_level)
    });
    
    tracing_subscriber::registry()
      .with(
          tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| filter.into()),
      )
      .with(tracing_subscriber::fmt::layer())
      .init();
}

/// Graceful shutdown 시그널 처리
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
          .await
          .expect("failed to install Ctrl+C handler");
    };
    
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
          .expect("failed to install signal handler")
          .recv()
          .await;
    };
    
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    
    tracing::info!("Received shutdown signal, shutting down gracefully...");
}

/// API 정보 출력
fn print_api_info(config: &Config) {
    let base_url = format!("http://{}:{}", config.host, config.port);
    
    tracing::info!("📚 사용 가능한 API 엔드포인트:");
    tracing::info!("┌─────────────────────────────────────────────────────────┐");
    tracing::info!("│ 🟡 ETHEREUM WALLET ENDPOINTS                           │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ 🔐 니모닉 & 계정                                        │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ POST {}/api/v1/mnemonic/generate              │", base_url);
    tracing::info!("│ POST {}/api/v1/mnemonic/validate              │", base_url);
    tracing::info!("│ POST {}/api/v1/account/create                 │", base_url);
    tracing::info!("│ POST {}/api/v1/account/create-multiple        │", base_url);
    tracing::info!("│ POST {}/api/v1/account/from-private-key       │", base_url);
    tracing::info!("│ POST {}/api/v1/account/random                 │", base_url);
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ 💼 HD 지갑                                              │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ POST {}/api/v1/wallet/hd/create               │", base_url);
    tracing::info!("│ POST {}/api/v1/wallet/multi-account/create    │", base_url);
    tracing::info!("│ POST {}/api/v1/wallet/add-account             │", base_url);
    tracing::info!("│ POST {}/api/v1/wallet/generate-addresses      │", base_url);
    tracing::info!("│ POST {}/api/v1/wallet/keystore/create         │", base_url);
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ ✍️  서명                                                 │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ POST {}/api/v1/sign/message                   │", base_url);
    tracing::info!("│ POST {}/api/v1/sign/verify                    │", base_url);
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ 🚀 트랜잭션 (SEPOLIA)                                   │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ POST {}/api/v1/transaction/create             │", base_url);
    tracing::info!("│ POST {}/api/v1/transaction/sign               │", base_url);
    tracing::info!("│ POST {}/api/v1/transaction/send               │", base_url);
    tracing::info!("│ POST {}/api/v1/transaction/send-raw           │", base_url);
    tracing::info!("│ POST {}/api/v1/transaction/estimate-gas       │", base_url);
    tracing::info!("│ POST {}/api/v1/transaction/calculate-fee      │", base_url);
    tracing::info!("│ GET  {}/api/v1/network/status                 │", base_url);
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ 🛠️  유틸리티                                             │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ POST {}/api/v1/utils/convert-units            │", base_url);
    tracing::info!("│ POST {}/api/v1/utils/validate-address         │", base_url);
    tracing::info!("│ POST {}/api/v1/utils/address-info             │", base_url);
    tracing::info!("└─────────────────────────────────────────────────────────┘");
    
    tracing::info!("┌─────────────────────────────────────────────────────────┐");
    tracing::info!("│ 🟠 BITCOIN WALLET ENDPOINTS                            │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ 🔐 니모닉 & 키                                          │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ POST {}/api/v1/bitcoin/mnemonic/generate      │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/mnemonic/validate      │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/mnemonic/to-seed       │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/mnemonic/to-xprv       │", base_url);
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ 🔑 키 관리                                              │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ POST {}/api/v1/bitcoin/key/derive-child       │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/key/xprv-to-wif        │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/key/wif-to-public      │", base_url);
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ 🏠 주소 생성                                            │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ POST {}/api/v1/bitcoin/address/from-wif       │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/address/from-xprv      │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/address/from-mnemonic  │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/address/from-public-key│", base_url);
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ 🔄 BIP-84 (네이티브 세그윗)                            │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ POST {}/api/v1/bitcoin/bip84/descriptors/create│", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/bip84/address          │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/bip84/next-address     │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/bip84/multiple-addresses│", base_url);
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ 🛠️  유틸리티                                             │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ POST {}/api/v1/bitcoin/utils/validate-private-key│", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/utils/validate-address │", base_url);
    tracing::info!("│ POST {}/api/v1/bitcoin/utils/network-info     │", base_url);
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ ❤️  헬스                                                │");
    tracing::info!("├─────────────────────────────────────────────────────────┤");
    tracing::info!("│ GET  {}/api/v1/bitcoin/health                 │", base_url);
    tracing::info!("│ GET  {}/health                                │", base_url);
    tracing::info!("└─────────────────────────────────────────────────────────┘");
    tracing::info!("");
    tracing::info!("💡 빠른 테스트 명령어:");
    tracing::info!("   curl {}/health", base_url);
    tracing::info!("   curl {}/api/v1/network/status", base_url);
    tracing::info!("   curl {}/api/v1/bitcoin/health", base_url);
    tracing::info!("");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 환경 변수 로드
    dotenv::dotenv().ok();
    
    // 설정 로드
    let config = Config::new()?;
    
    // 로깅 초기화
    init_logging(&config.log_level);
    
    // 시작 메시지
    tracing::info!("🚀 Crypto Wallet API Server (Axum 0.8.4) 시작 중...");
    tracing::info!("📋 설정 로드됨:");
    tracing::info!("   - 호스트: {}", config.host);
    tracing::info!("   - 포트: {}", config.port);
    tracing::info!("   - 로그 레벨: {}", config.log_level);
    tracing::info!("🌐 서버 실행 주소: http://{}:{}", config.host, config.port);
    tracing::info!("📖 헬스체크: http://{}:{}/health", config.host, config.port);
    
    // API 정보 출력
    print_api_info(&config);
    
    // 서비스를 한 번만 생성
    let ethereum_service = Arc::new(EthereumWalletService::new());
    let bitcoin_service = Arc::new(BitcoinWalletService::new());
    
    let app_state = AppState {
        ethereum_service,
        bitcoin_service,
    };
    
    // 애플리케이션 생성
    let app = create_app(app_state);
    
    // 서버 주소 설정
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
      .parse()
      .expect("잘못된 서버 주소");
    
    tracing::info!("🎯 서버가 {}에서 실행 중입니다", addr);
    tracing::info!("🔥 요청을 받을 준비가 완료되었습니다!");
    
    // TCP 리스너 생성
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    // 서버 실행 (Graceful shutdown 포함)
    axum::serve(listener, app)
      .with_graceful_shutdown(shutdown_signal())
      .await
      .unwrap();
    
    tracing::info!("서버가 완전히 종료되었습니다");
    
    Ok(())
}