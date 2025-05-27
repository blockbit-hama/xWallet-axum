/**
* filename: types/bitcoin_wallet.rs
* author: HAMA
* date: 2025. 5. 27.
* description: Axum용 비트코인 지갑 타입 정의 (Warp 의존성 제거)
**/

use serde::{Deserialize, Serialize};

// ========================================
// 네트워크 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum NetworkType {
  #[serde(rename = "mainnet")]
  Mainnet,
  #[serde(rename = "testnet")]
  Testnet,
  #[serde(rename = "testnet4")]
  Testnet4,
  #[serde(rename = "regtest")]
  Regtest,
  #[serde(rename = "signet")]
  Signet,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum AddressType {
  #[serde(rename = "p2pkh")]
  P2PKH,      // Legacy
  #[serde(rename = "p2wpkh")]
  P2WPKH,     // Native SegWit
  #[serde(rename = "p2sh_p2wpkh")]
  P2SH_P2WPKH, // Wrapped SegWit
}

// ========================================
// 니모닉 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinMnemonicRequest {
  pub word_count: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinMnemonicResponse {
  pub mnemonic: String,
  pub word_count: usize,
  pub language: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinMnemonicValidationRequest {
  pub mnemonic: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinMnemonicValidationResponse {
  pub valid: bool,
  pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinMnemonicToSeedRequest {
  pub mnemonic: String,
  pub passphrase: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinMnemonicToSeedResponse {
  pub seed_hex: String,
  pub seed_length: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinMnemonicToXprvRequest {
  pub mnemonic: String,
  pub network: NetworkType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinMnemonicToXprvResponse {
  pub xprv: String,
  pub network: NetworkType,
}

// ========================================
// 키 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinDeriveChildKeyRequest {
  pub parent_xprv: String,
  pub derivation_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinDeriveChildKeyResponse {
  pub child_xprv: String,
  pub derivation_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinXprvToWifRequest {
  pub xprv: String,
  pub derivation_path: String,
  pub network: NetworkType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinXprvToWifResponse {
  pub wif: String,
  pub network: NetworkType,
  pub derivation_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinWifToPublicKeyRequest {
  pub private_key_wif: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinWifToPublicKeyResponse {
  pub public_key_hex: String,
  pub compressed: bool,
}

// ========================================
// 주소 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinAddressFromWifRequest {
  pub private_key_wif: String,
  pub network: NetworkType,
  pub address_type: Option<AddressType>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinAddressFromWifResponse {
  pub address: String,
  pub address_type: AddressType,
  pub network: NetworkType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinAddressFromXprvRequest {
  pub xprv: String,
  pub derivation_path: String,
  pub network: NetworkType,
  pub address_type: Option<AddressType>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinAddressFromXprvResponse {
  pub address: String,
  pub address_type: AddressType,
  pub network: NetworkType,
  pub derivation_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinAddressFromMnemonicRequest {
  pub mnemonic: String,
  pub derivation_path: String,
  pub network: NetworkType,
  pub address_type: Option<AddressType>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinAddressFromMnemonicResponse {
  pub address: String,
  pub address_type: AddressType,
  pub network: NetworkType,
  pub derivation_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinAddressFromPublicKeyRequest {
  pub public_key_hex: String,
  pub network: NetworkType,
  pub address_type: AddressType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinAddressFromPublicKeyResponse {
  pub address: String,
  pub address_type: AddressType,
  pub network: NetworkType,
}

// ========================================
// BIP-84 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinBip84DescriptorsRequest {
  pub mnemonic: String,
  pub network: NetworkType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinBip84DescriptorsResponse {
  pub external_descriptor: String,
  pub internal_descriptor: String,
  pub network: NetworkType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinBip84AddressRequest {
  pub mnemonic: String,
  pub network: NetworkType,
  pub is_change: bool,
  pub index: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinBip84AddressResponse {
  pub address: String,
  pub derivation_path: String,
  pub network: NetworkType,
  pub is_change: bool,
  pub index: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinBip84GeneratorRequest {
  pub mnemonic: String,
  pub network: NetworkType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinBip84GeneratorResponse {
  pub generator_id: String,
  pub network: NetworkType,
  pub external_index: u32,
  pub internal_index: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinBip84NextAddressRequest {
  pub mnemonic: String,
  pub network: NetworkType,
  pub is_change: bool,
  pub current_index: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinBip84NextAddressResponse {
  pub address: String,
  pub derivation_path: String,
  pub network: NetworkType,
  pub is_change: bool,
  pub index: u32,
  pub next_index: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinBip84MultipleAddressesRequest {
  pub mnemonic: String,
  pub network: NetworkType,
  pub external_count: u32,
  pub internal_count: u32,
  pub start_index: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinBip84MultipleAddressesResponse {
  pub external_addresses: Vec<BitcoinAddressInfo>,
  pub internal_addresses: Vec<BitcoinAddressInfo>,
  pub network: NetworkType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinAddressInfo {
  pub address: String,
  pub derivation_path: String,
  pub index: u32,
  pub is_change: bool,
}

// ========================================
// 유틸리티 관련 타입
// ========================================

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinValidatePrivateKeyRequest {
  pub private_key_wif: String,
  pub expected_network: NetworkType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinValidatePrivateKeyResponse {
  pub valid: bool,
  pub network_match: bool,
  pub detected_network: Option<NetworkType>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinValidateAddressRequest {
  pub address: String,
  pub expected_network: NetworkType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinValidateAddressResponse {
  pub valid: bool,
  pub network_match: bool,
  pub address_type: Option<AddressType>,
  pub detected_network: Option<NetworkType>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinNetworkInfoRequest {
  pub network: NetworkType,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BitcoinNetworkInfoResponse {
  pub network: NetworkType,
  pub name: String,
  pub bech32_hrp: String,
  pub pubkey_hash: u8,
  pub script_hash: u8,
  pub wif: u8,
}

// ========================================
// 에러 관련 타입 (Axum용으로 수정)
// ========================================

#[derive(Debug, thiserror::Error)]
pub enum BitcoinWalletError {
  #[error("Invalid mnemonic: {0}")]
  InvalidMnemonic(String),
  
  #[error("Invalid private key: {0}")]
  InvalidPrivateKey(String),
  
  #[error("Invalid address: {0}")]
  InvalidAddress(String),
  
  #[error("Invalid derivation path: {0}")]
  InvalidDerivationPath(String),
  
  #[error("Invalid public key: {0}")]
  InvalidPublicKey(String),
  
  #[error("Invalid network: {0}")]
  InvalidNetwork(String),
  
  #[error("Key derivation failed: {0}")]
  KeyDerivationFailed(String),
  
  #[error("Address generation failed: {0}")]
  AddressGenerationFailed(String),
  
  #[error("Descriptor creation failed: {0}")]
  DescriptorCreationFailed(String),
  
  #[error("Secp256k1 error: {0}")]
  Secp256k1Error(String),
  
  #[error("BIP32 error: {0}")]
  Bip32Error(String),
  
  #[error("BIP39 error: {0}")]
  Bip39Error(String),
  
  #[error("Internal error: {0}")]
  InternalError(String),
}