/**
* filename: services/bitcoin_wallet_transaction.rs
* author: HAMA
* date: 2025. 5. 27.
* description: BDK를 사용한 비트코인 트랜잭션 서비스
**/

use bdk_wallet::file_store::Store;
use bdk_wallet::{Wallet, PersistedWallet};
use std::io::Write;

use bdk_electrum::electrum_client;
use bdk_electrum::BdkElectrumClient;
use bdk_wallet::chain::collections::HashSet;
use bdk_wallet::{KeychainKind, SignOptions};
use bdk_wallet::bitcoin::{Amount, Address, Network};
use std::str::FromStr;

use crate::model::bitcoin_wallet::BitcoinWalletError;

type WalletType = PersistedWallet<Store<bdk_wallet::ChangeSet>>;

const DB_MAGIC: &str = "bdk_wallet_electrum_example";
const STOP_GAP: usize = 50;
const BATCH_SIZE: usize = 5;
const ELECTRUM_URL: &str = "ssl://electrum.blockstream.info:60002";

pub struct BitcoinTransactionService {
  network: Network,
  external_desc: String,
  internal_desc: String,
  db_path: String,
}

impl BitcoinTransactionService {
  /// 새로운 비트코인 트랜잭션 서비스 생성
  pub fn new(
    network: Network,
    external_desc: String,
    internal_desc: String,
    db_path: String,
  ) -> Self {
    Self {
      network,
      external_desc,
      internal_desc,
      db_path,
    }
  }
  
  /// 테스트넷용 기본 서비스 생성
  pub fn testnet_default() -> Self {
    Self {
      network: Network::Testnet,
      external_desc: "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/0/*)".to_string(),
      internal_desc: "wpkh(tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L/84'/1'/0'/1/*)".to_string(),
      db_path: "bdk-electrum-example.db".to_string(),
    }
  }
  
  /// 지갑 로드 또는 생성
  fn load_or_create_wallet(&self) -> Result<(WalletType, Store<bdk_wallet::ChangeSet>), BitcoinWalletError> {
    let mut db = Store::<bdk_wallet::ChangeSet>::open_or_create_new(
      DB_MAGIC.as_bytes(),
      &self.db_path,
    ).map_err(|e| BitcoinWalletError::InternalError(format!("Database error: {}", e)))?;
    
    let wallet_opt = Wallet::load()
      .descriptor(KeychainKind::External, Some(self.external_desc.as_str()))
      .descriptor(KeychainKind::Internal, Some(self.internal_desc.as_str()))
      .extract_keys()
      .check_network(self.network)
      .load_wallet(&mut db)
      .map_err(|e| BitcoinWalletError::InternalError(format!("Wallet load error: {}", e)))?;
    
    let wallet = match wallet_opt {
      Some(wallet) => wallet,
      None => {
        Wallet::create(&self.external_desc, &self.internal_desc)
          .network(self.network)
          .create_wallet(&mut db)
          .map_err(|e| BitcoinWalletError::InternalError(format!("Wallet creation error: {}", e)))?
      },
    };
    
    Ok((wallet, db))
  }
  
  /// 새로운 주소 생성
  pub fn generate_address(&self) -> Result<String, BitcoinWalletError> {
    let (mut wallet, mut db) = self.load_or_create_wallet()?;
    
    let address = wallet.next_unused_address(KeychainKind::External);
    wallet.persist(&mut db)
      .map_err(|e| BitcoinWalletError::InternalError(format!("Persist error: {}", e)))?;
    
    Ok(address.to_string())
  }
  
  /// 지갑 동기화 및 잔액 조회
  pub fn sync_and_get_balance(&self) -> Result<Amount, BitcoinWalletError> {
    let (mut wallet, mut db) = self.load_or_create_wallet()?;
    
    // 동기화 전 잔액
    let balance_before = wallet.balance();
    println!("Wallet balance before syncing: {}", balance_before.total());
    
    // Electrum 클라이언트 생성
    let client = BdkElectrumClient::new(
      electrum_client::Client::new(ELECTRUM_URL)
        .map_err(|e| BitcoinWalletError::NetworkError(format!("Electrum connection error: {}", e)))?
    );
    
    // 트랜잭션 캐시 채우기
    client.populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));
    
    // 풀 스캔 요청 생성
    let request = wallet.start_full_scan().inspect({
      let mut stdout = std::io::stdout();
      let mut once = HashSet::<KeychainKind>::new();
      move |k, spk_i, _| {
        if once.insert(k) {
          print!("\nScanning keychain [{:?}]", k);
        }
        print!(" {:<3}", spk_i);
        stdout.flush().expect("must flush");
      }
    });
    
    // 풀 스캔 실행
    let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, false)
      .map_err(|e| BitcoinWalletError::NetworkError(format!("Sync error: {}", e)))?;
    
    println!();
    
    // 업데이트 적용
    wallet.apply_update(update)
      .map_err(|e| BitcoinWalletError::InternalError(format!("Update apply error: {}", e)))?;
    wallet.persist(&mut db)
      .map_err(|e| BitcoinWalletError::InternalError(format!("Persist error: {}", e)))?;
    
    let balance_after = wallet.balance();
    println!("Wallet balance after syncing: {}", balance_after.total());
    
    Ok(balance_after.total())
  }
  
  /// 트랜잭션 전송
  pub fn send_transaction(&self, to_address: &str, amount_sat: u64) -> Result<String, BitcoinWalletError> {
    let (mut wallet, mut db) = self.load_or_create_wallet()?;
    let send_amount = Amount::from_sat(amount_sat);
    
    // 동기화 먼저 수행
    let client = BdkElectrumClient::new(
      electrum_client::Client::new(ELECTRUM_URL)
        .map_err(|e| BitcoinWalletError::NetworkError(format!("Electrum connection error: {}", e)))?
    );
    
    client.populate_tx_cache(wallet.tx_graph().full_txs().map(|tx_node| tx_node.tx));
    
    let request = wallet.start_full_scan().inspect({
      let mut stdout = std::io::stdout();
      let mut once = HashSet::<KeychainKind>::new();
      move |k, spk_i, _| {
        if once.insert(k) {
          print!("\nScanning keychain [{:?}]", k);
        }
        print!(" {:<3}", spk_i);
        stdout.flush().expect("must flush");
      }
    });
    
    let update = client.full_scan(request, STOP_GAP, BATCH_SIZE, false)
      .map_err(|e| BitcoinWalletError::NetworkError(format!("Sync error: {}", e)))?;
    
    wallet.apply_update(update)
      .map_err(|e| BitcoinWalletError::InternalError(format!("Update apply error: {}", e)))?;
    wallet.persist(&mut db)
      .map_err(|e| BitcoinWalletError::InternalError(format!("Persist error: {}", e)))?;
    
    // 잔액 확인
    let balance = wallet.balance();
    if balance.total() < send_amount {
      return Err(BitcoinWalletError::InternalError(
        format!("Insufficient balance. Required: {}, Available: {}", send_amount, balance.total())
      ));
    }
    
    // 주소 파싱
    let address = Address::from_str(to_address)
      .map_err(|e| BitcoinWalletError::InvalidAddress(format!("Invalid address: {}", e)))?
      .require_network(self.network)
      .map_err(|e| BitcoinWalletError::InvalidAddress(format!("Address network mismatch: {}", e)))?;
    
    // 트랜잭션 빌더 생성
    let mut tx_builder = wallet.build_tx();
    tx_builder.add_recipient(address.script_pubkey(), send_amount);
    
    // PSBT 생성 및 서명
    let mut psbt = tx_builder.finish()
      .map_err(|e| BitcoinWalletError::InternalError(format!("Transaction build error: {}", e)))?;
    
    let finalized = wallet.sign(&mut psbt, SignOptions::default())
      .map_err(|e| BitcoinWalletError::SigningError(format!("Signing error: {}", e)))?;
    
    if !finalized {
      return Err(BitcoinWalletError::SigningError("Transaction signing failed".to_string()));
    }
    
    // 트랜잭션 추출 및 브로드캐스트
    let tx = psbt.extract_tx()
      .map_err(|e| BitcoinWalletError::InternalError(format!("Transaction extract error: {}", e)))?;
    
    client.transaction_broadcast(&tx)
      .map_err(|e| BitcoinWalletError::NetworkError(format!("Broadcast error: {}", e)))?;
    
    let txid = tx.compute_txid().to_string();
    println!("Tx broadcasted! Txid: {}", txid);
    
    Ok(txid)
  }
  
  /// 자기 자신에게 트랜잭션 전송 (테스트용)
  pub fn send_to_self(&self, amount_sat: u64) -> Result<String, BitcoinWalletError> {
    let (mut wallet, mut db) = self.load_or_create_wallet()?;
    
    // 새로운 주소 생성
    let address = wallet.next_unused_address(KeychainKind::External);
    wallet.persist(&mut db)
      .map_err(|e| BitcoinWalletError::InternalError(format!("Persist error: {}", e)))?;
    
    // 자기 자신에게 전송
    self.send_transaction(&address.to_string(), amount_sat)
  }
}

impl Default for BitcoinTransactionService {
  fn default() -> Self {
    Self::testnet_default()
  }
}