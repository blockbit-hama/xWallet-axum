/**
* filename : response
* author : HAMA
* date: 2025. 5. 27.
* description: 
**/

/**
* filename: response.rs
* author: HAMA
* date: 2025. 5. 23.
* description: Axum용 응답 유틸리티
**/

use axum::{
  http::StatusCode,
  response::{IntoResponse, Json},
};
use chrono::Utc;
use serde::Serialize;

/// 성공 응답 구조체
#[derive(Debug, Serialize)]
pub struct SuccessResponse<T> {
  pub success: bool,
  pub data: T,
  pub timestamp: String,
}

impl<T: Serialize> SuccessResponse<T> {
  pub fn new(data: T) -> Self {
    Self {
      success: true,
      data,
      timestamp: Utc::now().to_rfc3339(),
    }
  }
}

/// 성공 응답 생성
pub fn success_response<T: Serialize>(data: T) -> Json<SuccessResponse<T>> {
  Json(SuccessResponse::new(data))
}

/// 상태 코드와 함께 성공 응답 생성
pub fn success_response_with_status<T: Serialize>(data: T, status: StatusCode) -> impl IntoResponse {
  (status, Json(SuccessResponse::new(data)))
}

/// 단순한 메시지 응답 생성
pub fn message_response(message: &str) -> Json<serde_json::Value> {
  Json(serde_json::json!({
        "success": true,
        "message": message,
        "timestamp": Utc::now().to_rfc3339()
    }))
}

/// 빈 성공 응답 (삭제 작업 등에 사용)
pub fn empty_success_response() -> Json<serde_json::Value> {
  Json(serde_json::json!({
        "success": true,
        "timestamp": Utc::now().to_rfc3339()
    }))
}

/// 헬스체크 응답
pub fn health_response(service_name: &str, version: &str) -> Json<serde_json::Value> {
  Json(serde_json::json!({
        "status": "ok",
        "service": service_name,
        "version": version,
        "timestamp": Utc::now().to_rfc3339(),
        "uptime": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }))
}

/// 페이지네이션이 포함된 성공 응답
#[derive(Serialize)]
pub struct PaginatedResponse<T> {
  pub success: bool,
  pub data: Vec<T>,
  pub pagination: PaginationInfo,
  pub timestamp: String,
}

#[derive(Serialize)]
pub struct PaginationInfo {
  pub page: u32,
  pub per_page: u32,
  pub total: u64,
  pub total_pages: u32,
}

pub fn paginated_response<T: Serialize>(
  data: Vec<T>,
  page: u32,
  per_page: u32,
  total: u64,
) -> Json<PaginatedResponse<T>> {
  let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
  
  let response = PaginatedResponse {
    success: true,
    data,
    pagination: PaginationInfo {
      page,
      per_page,
      total,
      total_pages,
    },
    timestamp: Utc::now().to_rfc3339(),
  };
  
  Json(response)
}

/// 검증 에러 응답 (여러 필드 에러)
#[derive(Serialize)]
pub struct ValidationError {
  pub field: String,
  pub message: String,
}

pub fn validation_error_response(errors: Vec<ValidationError>) -> impl IntoResponse {
  let response = serde_json::json!({
        "success": false,
        "error": {
            "error": "ValidationError",
            "message": "Request validation failed",
            "code": 400,
            "validation_errors": errors
        },
        "timestamp": Utc::now().to_rfc3339()
    });
  
  (StatusCode::BAD_REQUEST, Json(response))
}