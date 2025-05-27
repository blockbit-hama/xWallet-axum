/**
* filename: config.rs
* author: HAMA
* date: 2025. 5. 23.
* description: 애플리케이션 설정 관리
**/

/// 애플리케이션 설정
#[derive(Debug, Clone)]
pub struct Config {
  pub host: String,
  pub port: u16,
  pub log_level: String,
}

impl Config {
  /// 환경 변수 또는 기본값으로 설정 생성
  pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
    Ok(Config {
      host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
      port: std::env::var("PORT")
        .unwrap_or_else(|_| "3030".to_string())
        .parse()
        .unwrap_or(3030),
      log_level: std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
    })
  }
}