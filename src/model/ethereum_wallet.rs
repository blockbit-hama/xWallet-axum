/**
* filename: types/ethereum_wallet.rs
* author: HAMA
* date: 2025. 5. 23.
* description: 완전한 이더리움 지갑 관련 타입 정의 (WalletError는 error.rs로 분리됨)
**/

use serde::{Deserialize, Serialize};

// ========================================
// 니모닉 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct MnemonicRequest {
  pub word_count: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MnemonicResponse {
  pub mnemonic: String,
  pub word_count: usize,
  pub language: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MnemonicValidationRequest {
  pub mnemonic: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MnemonicValidationResponse {
  pub valid: bool,
  pub message: String,
}

// ========================================
// 계정 생성 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct AccountRequest {
  pub mnemonic: String,
  pub path: String,
  pub password: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccountResponse {
  pub address: String,
  pub private_key: String,
  pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MultipleAccountsRequest {
  pub mnemonic: String,
  pub account_index: u32,
  pub count: u32,
  pub password: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MultipleAccountsResponse {
  pub accounts: Vec<AccountInfo>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AccountInfo {
  pub index: u32,
  pub address: String,
  pub private_key: String,
  pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrivateKeyRequest {
  pub private_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrivateKeyResponse {
  pub address: String,
  pub private_key: String,
}

// ========================================
// HD 지갑 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct HdWalletRequest {
  pub mnemonic: String,
  pub password: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HdWalletResponse {
  pub wallet_id: String,
  pub mnemonic: String,
  pub master_address: String,
  pub accounts_created: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MultiAccountWalletRequest {
  pub mnemonic: String,
  pub password: Option<String>,
  pub accounts: Vec<AccountCreationInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccountCreationInfo {
  pub account_index: u32,
  pub name: String,
  pub address_count: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MultiAccountWalletResponse {
  pub wallet_id: String,
  pub accounts: Vec<AccountDetail>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccountDetail {
  pub account_index: u32,
  pub name: String,
  pub addresses: Vec<AddressDetail>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AddressDetail {
  pub index: u32,
  pub address: String,
  pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AddAccountRequest {
  pub mnemonic: String,
  pub password: Option<String>,
  pub account_index: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AddAccountResponse {
  pub account_index: u32,
  pub account: AccountResponse,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GenerateAddressesRequest {
  pub mnemonic: String,
  pub password: Option<String>,
  pub account_index: u32,
  pub count: u32,
  pub start_index: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GenerateAddressesResponse {
  pub addresses: Vec<AddressInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AddressInfo {
  pub index: u32,
  pub address: String,
  pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateKeystoreRequest {
  pub address: String,
  pub private_key: String,
  pub password: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateKeystoreResponse {
  pub keystore_json: String,
  pub address: String,
}

// ========================================
// 서명 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct SignMessageRequest {
  pub private_key: String,
  pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignMessageResponse {
  pub signature: String,
  pub message_hash: String,
  pub signer_address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifySignatureRequest {
  pub message: String,
  pub signature: String,
  pub address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifySignatureResponse {
  pub valid: bool,
  pub recovered_address: String,
}

// ========================================
// 트랜잭션 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateTransactionRequest {
  pub to: String,
  pub value_ether: Option<f64>,
  pub value_wei: Option<String>,
  pub gas_limit: Option<u64>,
  pub gas_price_gwei: Option<u64>,
  pub gas_price_wei: Option<String>,
  pub nonce: u64,
  pub data: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateTransactionResponse {
  pub transaction: TransactionInfo,
  pub hash: String,
  pub fee_info: FeeInfo,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TransactionInfo {
  pub to: String,
  pub value: String,
  pub gas_limit: String,
  pub gas_price: String,
  pub nonce: String,
  pub data: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FeeInfo {
  pub gas_limit: String,
  pub gas_price: String,
  pub total_fee_wei: String,
  pub total_fee_ether: String,
  pub total_fee_gwei: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignTransactionRequest {
  pub transaction_hash: String,
  pub private_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SignTransactionResponse {
  pub signature: String,
  pub signed_transaction: String,
  pub transaction_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SendTransactionRequest {
  pub to: String,
  pub private_key: String,
  pub value_ether: Option<f64>,
  pub value_wei: Option<String>,
  pub gas_limit: Option<u64>,
  pub gas_price_gwei: Option<u64>,
  pub nonce: Option<u64>,
  pub data: Option<String>,
  pub wait_for_confirmation: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SendTransactionResponse {
  pub transaction_hash: String,
  pub status: String, // "pending" or "confirmed"
  pub block_number: Option<String>,
  pub gas_used: Option<String>,
  pub effective_gas_price: Option<String>,
  pub from: String,
  pub to: String,
  pub value: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SendRawTransactionRequest {
  pub signed_transaction: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SendRawTransactionResponse {
  pub transaction_hash: String,
  pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EstimateGasRequest {
  pub to: String,
  pub value: Option<String>,
  pub data: Option<String>,
  pub from: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EstimateGasResponse {
  pub estimated_gas: String,
  pub gas_limit_recommended: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CalculateFeeRequest {
  pub gas_limit: u64,
  pub gas_price_gwei: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CalculateFeeResponse {
  pub gas_limit: String,
  pub gas_price_wei: String,
  pub gas_price_gwei: String,
  pub total_fee_wei: String,
  pub total_fee_ether: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NetworkStatusResponse {
  pub network: String,
  pub chain_id: u64,
  pub latest_block: u64,
  pub rpc_url: String,
  pub status: String,
}

// ========================================
// 유틸리티 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct ConversionRequest {
  pub value: String,
  pub from_unit: String,
  pub to_unit: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ConversionResponse {
  pub original_value: String,
  pub original_unit: String,
  pub converted_value: String,
  pub converted_unit: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ValidateAddressRequest {
  pub address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ValidateAddressResponse {
  pub valid: bool,
  pub checksum_valid: bool,
  pub address_type: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AddressInfoRequest {
  pub address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AddressInfoResponse {
  pub address: String,
  pub checksum_address: String,
  pub lowercase_address: String,
  pub valid: bool,
}