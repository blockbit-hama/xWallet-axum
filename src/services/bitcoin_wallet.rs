/**
* filename: services/bitcoin_wallet.rs
* author: HAMA
* date: 2025. 5. 23.
* description: 비트코인 지갑 서비스 - BDK와 BIP39를 사용한 완전한 구현
**/

use std::str::FromStr;
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv};
use bdk_wallet::bitcoin::{Address, CompressedPublicKey, Network, PrivateKey};
use bdk_wallet::bitcoin::secp256k1::{Secp256k1};
use bdk_wallet::keys::{DerivableKey, ExtendedKey};
use bip39::{Language, Mnemonic};
use crate::model::bitcoin_wallet::*;

pub struct BitcoinWalletService;

impl BitcoinWalletService {
  pub fn new() -> Self {
    Self
  }
  
  // ========================================
  // 니모닉 관련 메서드
  // ========================================
  
  /// 지정된 단어 수에 따른 BIP-39 니모닉 문구를 생성합니다.
  pub fn generate_mnemonic(&self, word_count: usize) -> Result<BitcoinMnemonicResponse, BitcoinWalletError> {
    if ![12, 15, 18, 21, 24].contains(&word_count) {
      return Err(BitcoinWalletError::InvalidMnemonic(
        format!("잘못된 단어 수: {}. 12, 15, 18, 21, 24 중 하나여야 합니다.", word_count)
      ));
    }
    
    let mnemonic = Mnemonic::generate_in(Language::English, word_count)
      .map_err(|e| BitcoinWalletError::Bip39Error(e.to_string()))?;
    
    Ok(BitcoinMnemonicResponse {
      mnemonic: mnemonic.to_string(),
      word_count,
      language: "English".to_string(),
    })
  }
  
  /// 니모닉 문자열의 유효성을 검사합니다.
  pub fn validate_mnemonic(&self, mnemonic_str: &str) -> Result<BitcoinMnemonicValidationResponse, BitcoinWalletError> {
    match Mnemonic::parse_in(Language::English, mnemonic_str) {
      Ok(_) => Ok(BitcoinMnemonicValidationResponse {
        valid: true,
        message: "유효한 니모닉입니다.".to_string(),
      }),
      Err(e) => Ok(BitcoinMnemonicValidationResponse {
        valid: false,
        message: format!("유효하지 않은 니모닉: {}", e),
      }),
    }
  }
  
  /// 니모닉 문구로부터 시드를 생성합니다.
  pub fn mnemonic_to_seed(&self, mnemonic_str: &str, passphrase: Option<&str>) -> Result<BitcoinMnemonicToSeedResponse, BitcoinWalletError> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)
      .map_err(|e| BitcoinWalletError::Bip39Error(e.to_string()))?;
    
    let seed = mnemonic.to_seed(passphrase.unwrap_or(""));
    
    Ok(BitcoinMnemonicToSeedResponse {
      seed_hex: hex::encode(&seed),
      seed_length: seed.len(),
    })
  }
  
  /// 니모닉 문구로부터 확장 개인키(xprv)를 생성합니다.
  pub fn mnemonic_to_xprv(&self, mnemonic_str: &str, network: NetworkType) -> Result<BitcoinMnemonicToXprvResponse, BitcoinWalletError> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)
      .map_err(|e| BitcoinWalletError::Bip39Error(e.to_string()))?;
    
    let xkey: ExtendedKey = mnemonic.into_extended_key()
      .map_err(|e| BitcoinWalletError::Bip32Error(e.to_string()))?;
    
    let network_converted = self.convert_network_type(network.clone());
    let xprv = xkey.into_xprv(network_converted)
      .ok_or_else(|| BitcoinWalletError::KeyDerivationFailed("확장 개인키 변환 실패".to_string()))?;
    
    Ok(BitcoinMnemonicToXprvResponse {
      xprv: xprv.to_string(),
      network,
    })
  }
  
  // ========================================
  // 키 관련 메서드
  // ========================================
  
  /// 확장 개인키(xprv)에서 특정 경로에 따른 자식 키를 파생합니다.
  pub fn derive_child_key(&self, parent_xprv: &str, derivation_path: &str) -> Result<BitcoinDeriveChildKeyResponse, BitcoinWalletError> {
    let xprv = Xpriv::from_str(parent_xprv)
      .map_err(|e| BitcoinWalletError::InvalidPrivateKey(e.to_string()))?;
    
    let path = DerivationPath::from_str(derivation_path)
      .map_err(|e| BitcoinWalletError::InvalidDerivationPath(e.to_string()))?;
    
    let secp = Secp256k1::new();
    let child_xprv = xprv.derive_priv(&secp, &path)
      .map_err(|e| BitcoinWalletError::KeyDerivationFailed(e.to_string()))?;
    
    Ok(BitcoinDeriveChildKeyResponse {
      child_xprv: child_xprv.to_string(),
      derivation_path: derivation_path.to_string(),
    })
  }
  
  /// 확장 개인키(xprv)에서 개인키(WIF 형식)를 추출합니다.
  pub fn xprv_to_wif(&self, xprv_str: &str, derivation_path: &str, network: NetworkType) -> Result<BitcoinXprvToWifResponse, BitcoinWalletError> {
    let xprv = Xpriv::from_str(xprv_str)
      .map_err(|e| BitcoinWalletError::InvalidPrivateKey(e.to_string()))?;
    
    let path = DerivationPath::from_str(derivation_path)
      .map_err(|e| BitcoinWalletError::InvalidDerivationPath(e.to_string()))?;
    
    let secp = Secp256k1::new();
    let child_xprv = xprv.derive_priv(&secp, &path)
      .map_err(|e| BitcoinWalletError::KeyDerivationFailed(e.to_string()))?;
    
    let network_converted = self.convert_network_type(network.clone());
    let secret_key = child_xprv.private_key;
    let private_key = PrivateKey::new(secret_key, network_converted);
    
    Ok(BitcoinXprvToWifResponse {
      wif: private_key.to_wif(),
      network,
      derivation_path: derivation_path.to_string(),
    })
  }
  
  /// 개인키(WIF)에서 압축된 공개키를 생성합니다.
  pub fn wif_to_public_key(&self, private_key_wif: &str) -> Result<BitcoinWifToPublicKeyResponse, BitcoinWalletError> {
    let private_key = PrivateKey::from_wif(private_key_wif)
      .map_err(|e| BitcoinWalletError::InvalidPrivateKey(e.to_string()))?;
    
    let secp = Secp256k1::new();
    let compressed_public_key = CompressedPublicKey::from_private_key(&secp, &private_key)
      .map_err(|e| BitcoinWalletError::Secp256k1Error(e.to_string()))?;
    
    Ok(BitcoinWifToPublicKeyResponse {
      public_key_hex: compressed_public_key.to_string(),
      compressed: true,
    })
  }
  
  // ========================================
  // 주소 관련 메서드
  // ========================================
  
  /// 개인키(WIF)에서 주소를 생성합니다.
  pub fn address_from_wif(&self, private_key_wif: &str, network: NetworkType, address_type: Option<AddressType>) -> Result<BitcoinAddressFromWifResponse, BitcoinWalletError> {
    let private_key = PrivateKey::from_wif(private_key_wif)
      .map_err(|e| BitcoinWalletError::InvalidPrivateKey(e.to_string()))?;
    
    let secp = Secp256k1::new();
    let compressed_public_key = CompressedPublicKey::from_private_key(&secp, &private_key)
      .map_err(|e| BitcoinWalletError::Secp256k1Error(e.to_string()))?;
    
    let network_converted = self.convert_network_type(network.clone());
    let address_type = address_type.unwrap_or(AddressType::P2WPKH);
    
    let address = self.create_address_from_pubkey(&compressed_public_key, network_converted, &address_type)?;
    
    Ok(BitcoinAddressFromWifResponse {
      address: address.to_string(),
      address_type,
      network,
    })
  }
  
  /// 확장 개인키(xprv)에서 특정 경로에 따른 주소를 생성합니다.
  pub fn address_from_xprv(&self, xprv_str: &str, derivation_path: &str, network: NetworkType, address_type: Option<AddressType>) -> Result<BitcoinAddressFromXprvResponse, BitcoinWalletError> {
    let xprv = Xpriv::from_str(xprv_str)
      .map_err(|e| BitcoinWalletError::InvalidPrivateKey(e.to_string()))?;
    
    let path = DerivationPath::from_str(derivation_path)
      .map_err(|e| BitcoinWalletError::InvalidDerivationPath(e.to_string()))?;
    
    let secp = Secp256k1::new();
    let child_xprv = xprv.derive_priv(&secp, &path)
      .map_err(|e| BitcoinWalletError::KeyDerivationFailed(e.to_string()))?;
    
    let network_converted = self.convert_network_type(network.clone());
    let secret_key = child_xprv.private_key;
    let private_key = PrivateKey::new(secret_key, network_converted);
    
    let compressed_public_key = CompressedPublicKey::from_private_key(&secp, &private_key)
      .map_err(|e| BitcoinWalletError::Secp256k1Error(e.to_string()))?;
    
    let address_type = address_type.unwrap_or(AddressType::P2WPKH);
    let address = self.create_address_from_pubkey(&compressed_public_key, network_converted, &address_type)?;
    
    Ok(BitcoinAddressFromXprvResponse {
      address: address.to_string(),
      address_type,
      network,
      derivation_path: derivation_path.to_string(),
    })
  }
  
  /// 니모닉에서 바로 주소를 생성합니다.
  pub fn address_from_mnemonic(&self, mnemonic_str: &str, derivation_path: &str, network: NetworkType, address_type: Option<AddressType>) -> Result<BitcoinAddressFromMnemonicResponse, BitcoinWalletError> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)
      .map_err(|e| BitcoinWalletError::Bip39Error(e.to_string()))?;
    
    let xkey: ExtendedKey = mnemonic.into_extended_key()
      .map_err(|e| BitcoinWalletError::Bip32Error(e.to_string()))?;
    
    let network_converted = self.convert_network_type(network.clone());
    let xprv = xkey.into_xprv(network_converted)
      .ok_or_else(|| BitcoinWalletError::KeyDerivationFailed("확장 개인키 변환 실패".to_string()))?;
    
    let response = self.address_from_xprv(
      &xprv.to_string(),
      derivation_path,
      network.clone(),
      address_type.clone()
    )?;
    
    Ok(BitcoinAddressFromMnemonicResponse {
      address: response.address,
      address_type: response.address_type,
      network,
      derivation_path: derivation_path.to_string(),
    })
  }
  
  /// 공개키에서 주소를 생성합니다.
  pub fn address_from_public_key(&self, public_key_hex: &str, network: NetworkType, address_type: AddressType) -> Result<BitcoinAddressFromPublicKeyResponse, BitcoinWalletError> {
    let compressed_public_key = CompressedPublicKey::from_str(public_key_hex)
      .map_err(|e| BitcoinWalletError::InvalidPublicKey(e.to_string()))?;
    
    let network_converted = self.convert_network_type(network.clone());
    let address = self.create_address_from_pubkey(&compressed_public_key, network_converted, &address_type)?;
    
    Ok(BitcoinAddressFromPublicKeyResponse {
      address: address.to_string(),
      address_type,
      network,
    })
  }
  
  // ========================================
  // BIP-84 관련 메서드
  // ========================================
  
  /// 니모닉으로부터 BIP-84 호환 디스크립터를 생성합니다.
  pub fn create_bip84_descriptors(&self, mnemonic_str: &str, network: NetworkType) -> Result<BitcoinBip84DescriptorsResponse, BitcoinWalletError> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)
      .map_err(|e| BitcoinWalletError::Bip39Error(e.to_string()))?;
    
    let seed = mnemonic.to_seed("");
    let secp = Secp256k1::new();
    let network_converted = self.convert_network_type(network.clone());
    
    let network_path = match network_converted {
      Network::Bitcoin => "m/84'/0'/0'",
      _ => "m/84'/1'/0'",
    };
    
    let xprv = Xpriv::new_master(network_converted, &seed)
      .map_err(|e| BitcoinWalletError::Bip32Error(e.to_string()))?;
    
    let derivation_path = DerivationPath::from_str(network_path)
      .map_err(|e| BitcoinWalletError::InvalidDerivationPath(e.to_string()))?;
    
    let derived_xprv = xprv.derive_priv(&secp, &derivation_path)
      .map_err(|e| BitcoinWalletError::KeyDerivationFailed(e.to_string()))?;
    
    let external_descriptor = format!("wpkh({}/0/*)", derived_xprv);
    let internal_descriptor = format!("wpkh({}/1/*)", derived_xprv);
    
    Ok(BitcoinBip84DescriptorsResponse {
      external_descriptor,
      internal_descriptor,
      network,
    })
  }
  
  /// 니모닉으로부터 BIP-84 경로에 따른 주소를 생성합니다.
  pub fn get_bip84_address(&self, mnemonic_str: &str, network: NetworkType, is_change: bool, index: u32) -> Result<BitcoinBip84AddressResponse, BitcoinWalletError> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic_str)
      .map_err(|e| BitcoinWalletError::Bip39Error(e.to_string()))?;
    
    let xkey: ExtendedKey = mnemonic.into_extended_key()
      .map_err(|e| BitcoinWalletError::Bip32Error(e.to_string()))?;
    
    let network_converted = self.convert_network_type(network.clone());
    let xprv = xkey.into_xprv(network_converted)
      .ok_or_else(|| BitcoinWalletError::KeyDerivationFailed("확장 개인키 변환 실패".to_string()))?;
    
    let coin_type = match network_converted {
      Network::Bitcoin => 0,
      _ => 1,
    };
    
    let change = if is_change { 1 } else { 0 };
    let path = format!("m/84'/{}'/{}'/{}/{}", coin_type, 0, change, index);
    
    let response = self.address_from_xprv(
      &xprv.to_string(),
      &path,
      network.clone(),
      Some(AddressType::P2WPKH)
    )?;
    
    Ok(BitcoinBip84AddressResponse {
      address: response.address,
      derivation_path: path,
      network,
      is_change,
      index,
    })
  }
  
  /// BIP-84 다음 주소를 생성합니다.
  pub fn get_bip84_next_address(&self, mnemonic_str: &str, network: NetworkType, is_change: bool, current_index: Option<u32>) -> Result<BitcoinBip84NextAddressResponse, BitcoinWalletError> {
    let index = current_index.unwrap_or(0);
    let next_index = index + 1;
    
    let response = self.get_bip84_address(mnemonic_str, network.clone(), is_change, index)?;
    
    Ok(BitcoinBip84NextAddressResponse {
      address: response.address,
      derivation_path: response.derivation_path,
      network,
      is_change,
      index,
      next_index,
    })
  }
  
  /// BIP-84 다중 주소를 생성합니다.
  pub fn get_bip84_multiple_addresses(&self, mnemonic_str: &str, network: NetworkType, external_count: u32, internal_count: u32, start_index: Option<u32>) -> Result<BitcoinBip84MultipleAddressesResponse, BitcoinWalletError> {
    let start_idx = start_index.unwrap_or(0);
    let mut external_addresses = Vec::new();
    let mut internal_addresses = Vec::new();
    
    // 외부 주소 생성
    for i in 0..external_count {
      let index = start_idx + i;
      let response = self.get_bip84_address(mnemonic_str, network.clone(), false, index)?;
      
      external_addresses.push(BitcoinAddressInfo {
        address: response.address,
        derivation_path: response.derivation_path,
        index,
        is_change: false,
      });
    }
    
    // 내부 주소 생성
    for i in 0..internal_count {
      let index = start_idx + i;
      let response = self.get_bip84_address(mnemonic_str, network.clone(), true, index)?;
      
      internal_addresses.push(BitcoinAddressInfo {
        address: response.address,
        derivation_path: response.derivation_path,
        index,
        is_change: true,
      });
    }
    
    Ok(BitcoinBip84MultipleAddressesResponse {
      external_addresses,
      internal_addresses,
      network,
    })
  }
  
  // ========================================
  // 유틸리티 메서드
  // ========================================
  
  /// 개인키가 특정 네트워크에 유효한지 검사합니다.
  pub fn validate_private_key(&self, private_key_wif: &str, expected_network: NetworkType) -> Result<BitcoinValidatePrivateKeyResponse, BitcoinWalletError> {
    let private_key = PrivateKey::from_wif(private_key_wif)
      .map_err(|e| BitcoinWalletError::InvalidPrivateKey(e.to_string()))?;
    
    let expected_network_converted = self.convert_network_type(expected_network);
    let network_match = private_key.network == expected_network_converted.into();
    
    let detected_network = match private_key.network {
      bdk_wallet::bitcoin::NetworkKind::Main => Some(NetworkType::Mainnet),
      bdk_wallet::bitcoin::NetworkKind::Test => Some(NetworkType::Testnet),
    };
    
    Ok(BitcoinValidatePrivateKeyResponse {
      valid: true,
      network_match,
      detected_network,
    })
  }
  
  /// 주소가 특정 네트워크에 유효한지 검사합니다.
  pub fn validate_address(&self, address_str: &str, expected_network: NetworkType) -> Result<BitcoinValidateAddressResponse, BitcoinWalletError> {
    let address = Address::from_str(address_str)
      .map_err(|e| BitcoinWalletError::InvalidAddress(e.to_string()))?;
    
    let expected_network_converted = self.convert_network_type(expected_network);
    let network_match = address.is_valid_for_network(expected_network_converted);
    
    // BDK의 address_type() 메서드를 사용하여 주소 타입 감지
    let address_type = if let Some(addr_type) = address.assume_checked_ref().address_type() {
      match addr_type {
        bdk_wallet::bitcoin::AddressType::P2pkh => Some(AddressType::P2PKH),
        bdk_wallet::bitcoin::AddressType::P2sh => Some(AddressType::P2SH_P2WPKH),
        bdk_wallet::bitcoin::AddressType::P2wpkh => Some(AddressType::P2WPKH),
        bdk_wallet::bitcoin::AddressType::P2wsh => Some(AddressType::P2WPKH), // WSH를 WPKH로 매핑
        _ => None, // P2tr 등 다른 타입들
      }
    } else {
      // BDK에서 감지하지 못한 경우 문자열 패턴으로 감지
      if address_str.starts_with("bc1") || address_str.starts_with("tb1") || address_str.starts_with("bcrt1") {
        Some(AddressType::P2WPKH)
      } else if address_str.starts_with("3") || address_str.starts_with("2") {
        Some(AddressType::P2SH_P2WPKH)
      } else if address_str.starts_with("1") || address_str.starts_with("m") || address_str.starts_with("n") {
        Some(AddressType::P2PKH)
      } else {
        None
      }
    };
    
    // 네트워크 감지 (주소 문자열 패턴 기반)
    let detected_network = if address_str.starts_with("bc1") || address_str.starts_with("1") || address_str.starts_with("3") {
      Some(NetworkType::Mainnet)
    } else if address_str.starts_with("tb1") || address_str.starts_with("2") || address_str.starts_with("m") || address_str.starts_with("n") {
      Some(NetworkType::Testnet)
    } else if address_str.starts_with("bcrt1") {
      Some(NetworkType::Regtest)
    } else {
      None
    };
    
    Ok(BitcoinValidateAddressResponse {
      valid: true,
      network_match,
      address_type,
      detected_network,
    })
  }
  
  /// 네트워크 정보를 조회합니다.
  pub fn get_network_info(&self, network: NetworkType) -> Result<BitcoinNetworkInfoResponse, BitcoinWalletError> {
    let network_converted = self.convert_network_type(network.clone());
    
    let (name, bech32_hrp, pubkey_hash, script_hash, wif) = match network_converted {
      Network::Bitcoin => ("Bitcoin Mainnet", "bc", 0x00, 0x05, 0x80),
      Network::Testnet => ("Bitcoin Testnet", "tb", 0x6f, 0xc4, 0xef),
      Network::Regtest => ("Bitcoin Regtest", "bcrt", 0x6f, 0xc4, 0xef),
      Network::Signet => ("Bitcoin Signet", "tb", 0x6f, 0xc4, 0xef),
      _ => todo!(),
    };
    
    Ok(BitcoinNetworkInfoResponse {
      network,
      name: name.to_string(),
      bech32_hrp: bech32_hrp.to_string(),
      pubkey_hash,
      script_hash,
      wif,
    })
  }
  
  // ========================================
  // 헬퍼 메서드
  // ========================================
  
  /// NetworkType을 Network로 변환합니다.
  fn convert_network_type(&self, network_type: NetworkType) -> Network {
    match network_type {
      NetworkType::Mainnet => Network::Bitcoin,
      NetworkType::Testnet => Network::Testnet,
      NetworkType::Testnet4 => Network::Testnet4,
      NetworkType::Regtest => Network::Regtest,
      NetworkType::Signet => Network::Signet,
    }
  }
  
  /// 공개키에서 주소를 생성하는 헬퍼 메서드
  fn create_address_from_pubkey(&self, pubkey: &CompressedPublicKey, network: Network, address_type: &AddressType) -> Result<Address, BitcoinWalletError> {
    let address = match address_type {
      AddressType::P2PKH => Address::p2pkh(pubkey, network),
      AddressType::P2WPKH => Address::p2wpkh(pubkey, network),
      AddressType::P2SH_P2WPKH => Address::p2shwpkh(pubkey, network),
    };
    
    Ok(address)
  }
}

impl Default for BitcoinWalletService {
  fn default() -> Self {
    Self::new()
  }
}