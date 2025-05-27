/**
* filename : ethereum_wallet
* author : HAMA
* date: 2025. 5. 27.
* description: 
**/

/**
* filename: services/ethereum_wallet.rs
* author: HAMA
* date: 2025. 5. 23.
* description: 모든 이더리움 지갑 관련 비즈니스 로직을 통합한 최종 서비스
**/

use std::str::FromStr;
use alloy::hex;
use alloy::signers::local::{MnemonicBuilder, PrivateKeySigner};
use alloy::signers::local::coins_bip39::{English, Mnemonic};
use alloy::primitives::{Address, U256, B256};
use alloy::signers::{Signer, SignerSync};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::network::{TransactionBuilder as AlloyTxBuilder, EthereumWallet};
use alloy::rpc::types::TransactionRequest;
use rand::thread_rng;
use uuid::Uuid;
use crate::error::WalletError;
use crate::model::ethereum_wallet::*;

/// 통합 이더리움 지갑 서비스 - 모든 지갑/트랜잭션 기능 제공
pub struct EthereumWalletService {
  sepolia_rpc_url: String,
  chain_id: u64,
}

impl EthereumWalletService {
  pub fn new() -> Self {
    Self {
      sepolia_rpc_url: "https://sepolia.infura.io/v3/9366572d83da40e4b827a664e6194e06".to_string(),
      chain_id: 11155111, // Sepolia chain ID
    }
  }
  
  // ========================================
  // 니모닉 관련 기능
  // ========================================
  
  /// 니모닉 생성
  pub fn generate_mnemonic(&self, word_count: usize) -> Result<MnemonicResponse, WalletError> {
    if ![12, 15, 18, 21, 24].contains(&word_count) {
      return Err(WalletError::InvalidMnemonic(
        format!("Invalid word count: {}. Must be 12, 15, 18, 21, or 24", word_count)
      ));
    }
    
    let mnemonic = Mnemonic::<English>::new_with_count(&mut thread_rng(), word_count)
      .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
    
    Ok(MnemonicResponse {
      mnemonic: mnemonic.to_phrase(),
      word_count,
      language: "English".to_string(),
    })
  }
  
  /// 니모닉 검증
  pub fn validate_mnemonic(&self, mnemonic: &str) -> Result<MnemonicValidationResponse, WalletError> {
    let is_valid = match Mnemonic::<English>::new_from_phrase(mnemonic) {
      Ok(_) => true,
      Err(_) => false,
    };
    
    Ok(MnemonicValidationResponse {
      valid: is_valid,
      message: if is_valid {
        "Mnemonic is valid".to_string()
      } else {
        "Mnemonic is invalid".to_string()
      },
    })
  }
  
  // ========================================
  // 계정 생성 관련 기능
  // ========================================
  
  /// 단일 계정 생성 (니모닉 + 경로)
  pub fn create_account(&self, request: AccountRequest) -> Result<AccountResponse, WalletError> {
    let signer = self.create_signer_from_mnemonic(
      &request.mnemonic,
      request.password.as_deref().unwrap_or(""),
      &request.path
    )?;
    
    Ok(AccountResponse {
      address: self.format_address(&signer.address()),
      private_key: self.format_private_key(&signer),
      path: request.path,
    })
  }
  
  /// 다중 계정 생성
  pub fn create_multiple_accounts(&self, request: MultipleAccountsRequest) -> Result<MultipleAccountsResponse, WalletError> {
    let mut accounts = Vec::new();
    let password = request.password.as_deref().unwrap_or("");
    
    for i in 0..request.count {
      let path = self.generate_ethereum_path(request.account_index, 0, i);
      let signer = self.create_signer_from_mnemonic(&request.mnemonic, password, &path)?;
      
      accounts.push(AccountInfo {
        index: i,
        address: self.format_address(&signer.address()),
        private_key: self.format_private_key(&signer),
        path,
      });
    }
    
    Ok(MultipleAccountsResponse { accounts })
  }
  
  /// 개인키로부터 계정 생성
  pub fn create_account_from_private_key(&self, request: PrivateKeyRequest) -> Result<PrivateKeyResponse, WalletError> {
    let signer = self.create_signer_from_private_key(&request.private_key)?;
    
    Ok(PrivateKeyResponse {
      address: self.format_address(&signer.address()),
      private_key: self.format_private_key(&signer),
    })
  }
  
  /// 랜덤 계정 생성
  pub fn create_random_account(&self) -> Result<serde_json::Value, WalletError> {
    let mnemonic_response = self.generate_mnemonic(12)?;
    let path = self.generate_ethereum_path(0, 0, 0);
    let signer = self.create_signer_from_mnemonic(&mnemonic_response.mnemonic, "", &path)?;
    
    Ok(serde_json::json!({
            "mnemonic": mnemonic_response.mnemonic,
            "address": self.format_address(&signer.address()),
            "private_key": self.format_private_key(&signer),
            "path": path
        }))
  }
  
  // ========================================
  // HD 지갑 관련 기능
  // ========================================
  
  /// HD 지갑 생성
  pub fn create_hd_wallet(&self, request: HdWalletRequest) -> Result<HdWalletResponse, WalletError> {
    // 니모닉 검증
    let validation = self.validate_mnemonic(&request.mnemonic)?;
    if !validation.valid {
      return Err(WalletError::InvalidMnemonic("Invalid mnemonic phrase".to_string()));
    }
    
    // 마스터 계정 생성 (m/44'/60'/0'/0/0)
    let master_path = self.generate_ethereum_path(0, 0, 0);
    let master_signer = self.create_signer_from_mnemonic(
      &request.mnemonic,
      request.password.as_deref().unwrap_or(""),
      &master_path
    )?;
    
    Ok(HdWalletResponse {
      wallet_id: Uuid::new_v4().to_string(),
      mnemonic: request.mnemonic,
      master_address: self.format_address(&master_signer.address()),
      accounts_created: 1,
    })
  }
  
  /// 다중 계정 지갑 생성
  pub fn create_multi_account_wallet(&self, request: MultiAccountWalletRequest) -> Result<MultiAccountWalletResponse, WalletError> {
    let password = request.password.as_deref().unwrap_or("");
    let wallet_id = Uuid::new_v4().to_string();
    let mut accounts = Vec::new();
    
    // 니모닉 검증
    let validation = self.validate_mnemonic(&request.mnemonic)?;
    if !validation.valid {
      return Err(WalletError::InvalidMnemonic("Invalid mnemonic phrase".to_string()));
    }
    
    for account_info in request.accounts {
      let mut addresses = Vec::new();
      
      for i in 0..account_info.address_count {
        let path = self.generate_ethereum_path(account_info.account_index, 0, i);
        let signer = self.create_signer_from_mnemonic(&request.mnemonic, password, &path)?;
        
        addresses.push(AddressDetail {
          index: i,
          address: self.format_address(&signer.address()),
          path,
        });
      }
      
      accounts.push(AccountDetail {
        account_index: account_info.account_index,
        name: account_info.name,
        addresses,
      });
    }
    
    Ok(MultiAccountWalletResponse {
      wallet_id,
      accounts,
    })
  }
  
  /// HD 지갑에 계정 추가
  pub fn add_account_to_hd_wallet(&self, request: AddAccountRequest) -> Result<AddAccountResponse, WalletError> {
    let path = self.generate_ethereum_path(request.account_index, 0, 0);
    let account = self.create_account(AccountRequest {
      mnemonic: request.mnemonic,
      password: request.password,
      path,
    })?;
    
    Ok(AddAccountResponse {
      account_index: request.account_index,
      account,
    })
  }
  
  /// 다중 주소 생성
  pub fn generate_addresses(&self, request: GenerateAddressesRequest) -> Result<GenerateAddressesResponse, WalletError> {
    let mut addresses = Vec::new();
    let password = request.password.as_deref().unwrap_or("");
    
    for i in 0..request.count {
      let address_index = request.start_index.unwrap_or(0) + i;
      let path = self.generate_ethereum_path(request.account_index, 0, address_index);
      let signer = self.create_signer_from_mnemonic(&request.mnemonic, password, &path)?;
      
      addresses.push(AddressInfo {
        index: address_index,
        address: self.format_address(&signer.address()),
        path,
      });
    }
    
    Ok(GenerateAddressesResponse { addresses })
  }
  
  /// 키스토어 생성
  pub fn create_keystore(&self, request: CreateKeystoreRequest) -> Result<CreateKeystoreResponse, WalletError> {
    // 간단한 키스토어 JSON 생성 (실제 구현에서는 적절한 암호화 필요)
    let keystore_json = format!(
      r#"{{
                "version": 3,
                "id": "{}",
                "address": "{}",
                "crypto": {{
                    "ciphertext": "{}",
                    "cipherparams": {{
                        "iv": "placeholder_iv"
                    }},
                    "cipher": "aes-128-ctr",
                    "kdf": "scrypt",
                    "kdfparams": {{
                        "dklen": 32,
                        "salt": "placeholder_salt",
                        "n": 262144,
                        "r": 8,
                        "p": 1
                    }},
                    "mac": "placeholder_mac"
                }}
            }}"#,
      Uuid::new_v4(),
      request.address.strip_prefix("0x").unwrap_or(&request.address),
      base64::encode(&request.private_key) // 실제로는 AES 암호화 필요
    );
    
    Ok(CreateKeystoreResponse {
      keystore_json,
      address: request.address,
    })
  }
  
  // ========================================
  // 서명 관련 기능
  // ========================================
  
  /// 메시지 서명
  pub fn sign_message(&self, request: SignMessageRequest) -> Result<SignMessageResponse, WalletError> {
    let signer = self.create_signer_from_private_key(&request.private_key)?;
    let (signature, message_hash) = self.sign_message_internal(&signer, &request.message)?;
    
    Ok(SignMessageResponse {
      signature,
      message_hash,
      signer_address: self.format_address(&signer.address()),
    })
  }
  
  /// 서명 검증
  pub fn verify_signature(&self, request: VerifySignatureRequest) -> Result<VerifySignatureResponse, WalletError> {
    let (is_valid, recovered_address) = self.verify_signature_internal(
      &request.message,
      &request.signature,
      &request.address
    )?;
    
    Ok(VerifySignatureResponse {
      valid: is_valid,
      recovered_address,
    })
  }
  
  /// 해시 서명
  pub fn sign_hash(&self, signer: &PrivateKeySigner, hash: B256) -> Result<alloy::primitives::Signature, WalletError> {
    signer.sign_hash_sync(&hash)
      .map_err(|e| WalletError::SignatureVerificationFailed(e.to_string()))
  }
  
  // ========================================
  // 트랜잭션 관련 기능
  // ========================================
  
  /// 트랜잭션 생성 및 시뮬레이션
  pub fn create_transaction(&self, request: CreateTransactionRequest) -> Result<CreateTransactionResponse, WalletError> {
    let to_address = Address::from_str(&request.to)
      .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
    
    // 값 변환
    let value = self.parse_value(request.value_ether, request.value_wei.as_deref())?;
    
    // 가스 설정
    let gas_limit = request.gas_limit.unwrap_or(21000);
    let gas_price = self.parse_gas_price(request.gas_price_gwei, request.gas_price_wei.as_deref())?;
    
    // 데이터 변환
    let data = self.parse_data(request.data.as_deref())?;
    
    // 트랜잭션 객체 생성
    let transaction = EthereumTransaction {
      to: to_address,
      value,
      gas_limit: U256::from(gas_limit),
      gas_price,
      nonce: U256::from(request.nonce),
      data,
    };
    
    // 응답 생성
    Ok(CreateTransactionResponse {
      transaction: transaction.to_transaction_info(),
      hash: transaction.calculate_hash(),
      fee_info: transaction.calculate_fee_info()?,
    })
  }
  
  /// 실제 네트워크로 트랜잭션 전송
  pub async fn send_transaction(&self, request: SendTransactionRequest) -> Result<SendTransactionResponse, WalletError> {
    // Signer 생성
    let signer = self.create_signer_from_private_key(&request.private_key)?;
    let wallet = EthereumWallet::from(signer.clone());
    let from_address = signer.address();
    
    // Provider 생성
    let provider = ProviderBuilder::new()
      .wallet(wallet)
      .connect_http(self.sepolia_rpc_url.parse()
        .map_err(|e| WalletError::NetworkError(format!("Invalid RPC URL: {}", e)))?);
    
    // 트랜잭션 요청 구성
    let tx_request = self.build_transaction_request(&request, from_address, &provider).await?;
    
    // 트랜잭션 전송
    let pending_tx = provider.send_transaction(tx_request).await
      .map_err(|e| WalletError::NetworkError(format!("Failed to send transaction: {}", e)))?;
    
    let tx_hash = format!("0x{}", hex::encode(pending_tx.tx_hash().as_slice()));
    
    // 확인 대기 (옵션)
    let receipt = if request.wait_for_confirmation.unwrap_or(false) {
      Some(pending_tx.get_receipt().await
        .map_err(|e| WalletError::NetworkError(format!("Failed to get receipt: {}", e)))?)
    } else {
      None
    };
    
    Ok(SendTransactionResponse {
      transaction_hash: tx_hash,
      status: if receipt.is_some() { "confirmed".to_string() } else { "pending".to_string() },
      block_number: receipt.as_ref().and_then(|r| r.block_number).map(|n| n.to_string()),
      gas_used: receipt.as_ref().map(|r| r.gas_used.to_string()),
      effective_gas_price: receipt.as_ref().and_then(|r| Some(r.effective_gas_price)).map(|p| p.to_string()),
      from: format!("{:?}", from_address),
      to: request.to,
      value: self.parse_value(request.value_ether, request.value_wei.as_deref())?.to_string(),
    })
  }
  
  /// Raw 트랜잭션 전송
  pub async fn send_raw_transaction(&self, signed_transaction: &str) -> Result<SendTransactionResponse, WalletError> {
    let provider = ProviderBuilder::new()
      .connect_http(self.sepolia_rpc_url.parse()
        .map_err(|e| WalletError::NetworkError(format!("Invalid RPC URL: {}", e)))?);
    
    let tx_bytes = hex::decode(signed_transaction.strip_prefix("0x").unwrap_or(signed_transaction))
      .map_err(|e| WalletError::TransactionCreationFailed(format!("Invalid transaction hex: {}", e)))?;
    
    let pending_tx = provider.send_raw_transaction(&tx_bytes).await
      .map_err(|e| WalletError::NetworkError(format!("Failed to send raw transaction: {}", e)))?;
    
    let tx_hash = format!("0x{}", hex::encode(pending_tx.tx_hash().as_slice()));
    
    Ok(SendTransactionResponse {
      transaction_hash: tx_hash,
      status: "pending".to_string(),
      block_number: None,
      gas_used: None,
      effective_gas_price: None,
      from: "unknown".to_string(),
      to: "unknown".to_string(),
      value: "unknown".to_string(),
    })
  }
  
  /// 트랜잭션 서명
  pub fn sign_transaction(&self, request: SignTransactionRequest) -> Result<SignTransactionResponse, WalletError> {
    let signer = self.create_signer_from_private_key(&request.private_key)?;
    
    // 실제 구현에서는 트랜잭션 객체를 파싱하여 서명
    // 여기서는 간단한 예제로 메시지 서명
    let message = format!("Transaction hash: {}", request.transaction_hash);
    let (signature, _) = self.sign_message_internal(&signer, &message)?;
    
    Ok(SignTransactionResponse {
      signature: signature.clone(),
      signed_transaction: format!("signed_{}", request.transaction_hash),
      transaction_hash: request.transaction_hash,
    })
  }
  
  /// 네트워크 기반 가스 추정
  pub async fn estimate_gas(&self, request: EstimateGasRequest) -> Result<EstimateGasResponse, WalletError> {
    let provider = ProviderBuilder::new()
      .connect_http(self.sepolia_rpc_url.parse()
        .map_err(|e| WalletError::NetworkError(format!("Invalid RPC URL: {}", e)))?);
    
    let to_addr = Address::from_str(&request.to)
      .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
    
    let from_addr = if let Some(from) = &request.from {
      Address::from_str(from)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?
    } else {
      Address::ZERO
    };
    
    let value = if let Some(v) = &request.value {
      U256::from_str(v).unwrap_or(U256::ZERO)
    } else {
      U256::ZERO
    };
    
    let mut tx_request = TransactionRequest::default()
      .with_from(from_addr)
      .with_to(to_addr)
      .with_value(value);
    
    if let Some(data_hex) = &request.data {
      let data = self.parse_data(Some(data_hex))?;
      tx_request = tx_request.with_input(data);
    }
    
    let gas_estimate = provider.estimate_gas(tx_request).await
      .map_err(|e| WalletError::NetworkError(format!("Failed to estimate gas: {}", e)))?;
    
    let recommended = (gas_estimate as f64 * 1.2) as u64;
    
    Ok(EstimateGasResponse {
      estimated_gas: gas_estimate.to_string(),
      gas_limit_recommended: recommended.to_string(),
    })
  }
  
  /// 수수료 계산
  pub async fn calculate_fee(&self, request: CalculateFeeRequest) -> Result<CalculateFeeResponse, WalletError> {
    let gas_price_wei = U256::from(request.gas_price_gwei) * U256::from(1_000_000_000u64);
    let total_fee_wei = U256::from(request.gas_limit) * gas_price_wei;
    let total_fee_ether = self.wei_to_ether(total_fee_wei)?;
    
    Ok(CalculateFeeResponse {
      gas_limit: request.gas_limit.to_string(),
      gas_price_wei: gas_price_wei.to_string(),
      gas_price_gwei: request.gas_price_gwei.to_string(),
      total_fee_wei: total_fee_wei.to_string(),
      total_fee_ether,
    })
  }
  
  /// 네트워크 상태 확인
  pub async fn get_network_status(&self) -> Result<NetworkStatusResponse, WalletError> {
    let provider = ProviderBuilder::new()
      .connect_http(self.sepolia_rpc_url.parse()
        .map_err(|e| WalletError::NetworkError(format!("Invalid RPC URL: {}", e)))?);
    
    let block_number = provider.get_block_number().await
      .map_err(|e| WalletError::NetworkError(format!("Failed to get block number: {}", e)))?;
    
    let chain_id = provider.get_chain_id().await
      .map_err(|e| WalletError::NetworkError(format!("Failed to get chain ID: {}", e)))?;
    
    Ok(NetworkStatusResponse {
      network: "Sepolia".to_string(),
      chain_id,
      latest_block: block_number,
      rpc_url: self.sepolia_rpc_url.clone(),
      status: "connected".to_string(),
    })
  }
  
  // ========================================
  // 유틸리티 기능
  // ========================================
  
  /// 단위 변환
  pub fn convert_units(&self, request: ConversionRequest) -> Result<ConversionResponse, WalletError> {
    let converted_value = self.convert_units_internal(&request.value, &request.from_unit, &request.to_unit)?;
    
    Ok(ConversionResponse {
      original_value: request.value,
      original_unit: request.from_unit,
      converted_value,
      converted_unit: request.to_unit,
    })
  }
  
  /// 주소 검증
  pub fn validate_address(&self, request: ValidateAddressRequest) -> Result<ValidateAddressResponse, WalletError> {
    let is_valid = self.is_valid_address(&request.address);
    let checksum_valid = if is_valid {
      self.is_checksum_valid(&request.address)
    } else {
      false
    };
    
    Ok(ValidateAddressResponse {
      valid: is_valid,
      checksum_valid,
      address_type: "Ethereum".to_string(),
    })
  }
  
  /// 주소 정보 조회
  pub fn get_address_info(&self, request: AddressInfoRequest) -> Result<AddressInfoResponse, WalletError> {
    let is_valid = self.is_valid_address(&request.address);
    
    if is_valid {
      let addr = Address::from_str(&request.address)
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
      
      Ok(AddressInfoResponse {
        address: request.address,
        checksum_address: format!("{:?}", addr),
        lowercase_address: format!("{:#x}", addr),
        valid: true,
      })
    } else {
      Ok(AddressInfoResponse {
        address: request.address,
        checksum_address: "Invalid address".to_string(),
        lowercase_address: "Invalid address".to_string(),
        valid: false,
      })
    }
  }
  
  // ========================================
  // Private 헬퍼 메서드들
  // ========================================
  
  fn create_signer_from_mnemonic(&self, mnemonic: &str, password: &str, path: &str) -> Result<PrivateKeySigner, WalletError> {
    MnemonicBuilder::<English>::default()
      .phrase(mnemonic)
      .derivation_path(path)
      .map_err(|e| WalletError::InvalidDerivationPath(e.to_string()))?
      .password(password)
      .build()
      .map_err(|e| WalletError::WalletCreationFailed(e.to_string()))
  }
  
  fn create_signer_from_private_key(&self, private_key_hex: &str) -> Result<PrivateKeySigner, WalletError> {
    let hex_str = private_key_hex.strip_prefix("0x").unwrap_or(private_key_hex);
    let bytes = hex::decode(hex_str)
      .map_err(|e| WalletError::InvalidPrivateKey(format!("Invalid hex: {}", e)))?;
    
    if bytes.len() != 32 {
      return Err(WalletError::InvalidPrivateKey("Private key must be exactly 32 bytes".to_string()));
    }
    
    let private_key_bytes = alloy::primitives::FixedBytes::<32>::from_slice(&bytes);
    PrivateKeySigner::from_bytes(&private_key_bytes)
      .map_err(|e| WalletError::InvalidPrivateKey(e.to_string()))
  }
  
  fn generate_ethereum_path(&self, account: u32, change: u32, address_index: u32) -> String {
    format!("m/44'/60'/{}'/{}/{}", account, change, address_index)
  }
  
  fn format_address(&self, address: &Address) -> String {
    format!("{:?}", address)
  }
  
  fn format_private_key(&self, signer: &PrivateKeySigner) -> String {
    let private_key_bytes = signer.to_field_bytes();
    format!("0x{}", hex::encode(private_key_bytes))
  }
  
  fn sign_message_internal(&self, signer: &PrivateKeySigner, message: &str) -> Result<(String, String), WalletError> {
    let message_bytes = message.as_bytes();
    let signature = signer.sign_message_sync(message_bytes)
      .map_err(|e| WalletError::SignatureVerificationFailed(e.to_string()))?;
    
    let message_hash = alloy::primitives::keccak256(
      format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message).as_bytes()
    );
    
    Ok((
      format!("0x{}", hex::encode(signature.as_bytes())),
      format!("0x{}", hex::encode(message_hash))
    ))
  }
  
  fn verify_signature_internal(&self, message: &str, signature: &str, expected_address: &str) -> Result<(bool, String), WalletError> {
    let signature_bytes = hex::decode(signature.strip_prefix("0x").unwrap_or(signature))
      .map_err(|e| WalletError::SignatureVerificationFailed(format!("Invalid signature hex: {}", e)))?;
    
    if signature_bytes.len() != 65 {
      return Err(WalletError::SignatureVerificationFailed("Signature must be 65 bytes".to_string()));
    }
    
    let signature = alloy::primitives::Signature::try_from(signature_bytes.as_slice())
      .map_err(|e| WalletError::SignatureVerificationFailed(e.to_string()))?;
    
    let message_hash = alloy::primitives::keccak256(
      format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message).as_bytes()
    );
    
    let recovered_address = signature.recover_address_from_prehash(&message_hash)
      .map_err(|e| WalletError::SignatureVerificationFailed(e.to_string()))?;
    
    let expected_addr = Address::from_str(expected_address)
      .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
    
    let is_valid = recovered_address == expected_addr;
    Ok((is_valid, format!("{:?}", recovered_address)))
  }
  
  fn parse_value(&self, ether: Option<f64>, wei: Option<&str>) -> Result<U256, WalletError> {
    if let Some(ether_value) = ether {
      Ok(U256::from((ether_value * 1e18) as u64))
    } else if let Some(wei_str) = wei {
      U256::from_str(wei_str)
        .map_err(|e| WalletError::TransactionCreationFailed(format!("Invalid wei value: {}", e)))
    } else {
      Ok(U256::ZERO)
    }
  }
  
  fn parse_gas_price(&self, gwei: Option<u64>, wei: Option<&str>) -> Result<U256, WalletError> {
    if let Some(gwei_value) = gwei {
      Ok(U256::from(gwei_value) * U256::from(1_000_000_000u64))
    } else if let Some(wei_str) = wei {
      U256::from_str(wei_str)
        .map_err(|e| WalletError::TransactionCreationFailed(format!("Invalid gas price: {}", e)))
    } else {
      Ok(U256::from(20_000_000_000u64)) // 기본값 20 Gwei
    }
  }
  
  fn parse_data(&self, data_hex: Option<&str>) -> Result<Vec<u8>, WalletError> {
    if let Some(hex_str) = data_hex {
      hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
        .map_err(|e| WalletError::TransactionCreationFailed(format!("Invalid data hex: {}", e)))
    } else {
      Ok(Vec::new())
    }
  }
  
  async fn build_transaction_request(
    &self,
    request: &SendTransactionRequest,
    from: Address,
    provider: &impl Provider,
  ) -> Result<TransactionRequest, WalletError> {
    let to_address = Address::from_str(&request.to)
      .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
    
    let value = self.parse_value(request.value_ether, request.value_wei.as_deref())?;
    
    let nonce = if let Some(n) = request.nonce {
      n
    } else {
      provider.get_transaction_count(from).await
        .map_err(|e| WalletError::NetworkError(format!("Failed to get nonce: {}", e)))?
    };
    
    let (max_fee_per_gas, max_priority_fee_per_gas) = if let Some(gas_price_gwei) = request.gas_price_gwei {
      let gas_price = gas_price_gwei as u128 * 1_000_000_000u128;
      (gas_price, 2_000_000_000u128)
    } else {
      let fees = provider.estimate_eip1559_fees().await
        .map_err(|e| WalletError::NetworkError(format!("Failed to estimate fees: {}", e)))?;
      (fees.max_fee_per_gas, fees.max_priority_fee_per_gas)
    };
    
    let gas_limit = request.gas_limit.unwrap_or(21000);
    
    let mut tx_request = TransactionRequest::default()
      .with_to(to_address)
      .with_from(from)
      .with_value(value)
      .with_nonce(nonce)
      .with_chain_id(self.chain_id)
      .with_gas_limit(gas_limit)
      .with_max_fee_per_gas(max_fee_per_gas)
      .with_max_priority_fee_per_gas(max_priority_fee_per_gas);
    
    if let Some(data_hex) = &request.data {
      let data = self.parse_data(Some(data_hex))?;
      tx_request = tx_request.with_input(data);
    }
    
    Ok(tx_request)
  }
  
  fn convert_units_internal(&self, value: &str, from_unit: &str, to_unit: &str) -> Result<String, WalletError> {
    let value_f64: f64 = value.parse()
      .map_err(|e| WalletError::UnitConversionError(format!("Invalid number: {}", e)))?;
    
    // Wei로 변환
    let wei_value = match from_unit.to_lowercase().as_str() {
      "wei" => U256::from_str(value)
        .map_err(|e| WalletError::UnitConversionError(e.to_string()))?,
      "gwei" => {
        let gwei_value = value_f64 as u64;
        U256::from(gwei_value) * U256::from(10).pow(U256::from(9))
      },
      "ether" | "eth" => {
        let wei_amount = value_f64 * 1e18;
        U256::from(wei_amount as u64)
      },
      _ => return Err(WalletError::UnitConversionError(format!("Unsupported unit: {}", from_unit))),
    };
    
    // 목표 단위로 변환
    match to_unit.to_lowercase().as_str() {
      "wei" => Ok(wei_value.to_string()),
      "gwei" => {
        let gwei_divisor = U256::from(10).pow(U256::from(9));
        Ok((wei_value / gwei_divisor).to_string())
      },
      "ether" | "eth" => {
        let ether_divisor = U256::from(10).pow(U256::from(18));
        let ether_part = wei_value / ether_divisor;
        let remainder = wei_value % ether_divisor;
        let ether_value = ether_part.to::<u64>() as f64 + (remainder.to::<u64>() as f64 / 1e18);
        Ok(ether_value.to_string())
      },
      _ => Err(WalletError::UnitConversionError(format!("Unsupported unit: {}", to_unit))),
    }
  }
  
  fn wei_to_ether(&self, wei: U256) -> Result<String, WalletError> {
    let ether_value = wei.to::<u128>() as f64 / 1e18;
    Ok(format!("{:.18}", ether_value))
  }
  
  fn is_valid_address(&self, address: &str) -> bool {
    Address::from_str(address).is_ok()
  }
  
  fn is_checksum_valid(&self, address: &str) -> bool {
    if let Ok(addr) = Address::from_str(address) {
      let checksum_addr = format!("{:?}", addr);
      checksum_addr == address
    } else {
      false
    }
  }
}

/// 간소화된 트랜잭션 구조체
#[derive(Debug, Clone)]
pub struct EthereumTransaction {
  pub to: Address,
  pub value: U256,
  pub gas_limit: U256,
  pub gas_price: U256,
  pub nonce: U256,
  pub data: Vec<u8>,
}

impl EthereumTransaction {
  pub fn calculate_hash(&self) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    format!("{:?}", self).hash(&mut hasher);
    let hash_u64 = hasher.finish();
    
    format!("0x{:016x}{:016x}", hash_u64, hash_u64)
  }
  
  pub fn to_transaction_info(&self) -> TransactionInfo {
    TransactionInfo {
      to: format!("{:?}", self.to),
      value: self.value.to_string(),
      gas_limit: self.gas_limit.to_string(),
      gas_price: self.gas_price.to_string(),
      nonce: self.nonce.to_string(),
      data: hex::encode(&self.data),
    }
  }
  
  pub fn calculate_fee_info(&self) -> Result<FeeInfo, WalletError> {
    let total_fee_wei = self.gas_limit * self.gas_price;
    let total_fee_ether = total_fee_wei.to::<u128>() as f64 / 1e18;
    let total_fee_gwei = total_fee_wei.to::<u128>() as f64 / 1e9;
    
    Ok(FeeInfo {
      gas_limit: self.gas_limit.to_string(),
      gas_price: self.gas_price.to_string(),
      total_fee_wei: total_fee_wei.to_string(),
      total_fee_ether: format!("{:.18}", total_fee_ether),
      total_fee_gwei: format!("{:.9}", total_fee_gwei),
    })
  }
}