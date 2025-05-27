# 🚀 Multi-Chain Wallet API

완전한 멀티체인 지갑 API 서버 - Bitcoin & Ethereum 지원

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bitcoin](https://img.shields.io/badge/Bitcoin-Testnet%20%26%20Mainnet-orange.svg)](https://bitcoin.org)
[![Ethereum](https://img.shields.io/badge/Ethereum-Sepolia-blue.svg)](https://ethereum.org)

## ✨ 주요 기능

### 🟠 Bitcoin 지원
- 🔐 **니모닉 & 키 관리**: BIP39 표준 니모닉, XPRV/WIF 키 변환
- 💼 **HD 지갑**: BIP32/BIP44/BIP84 계층적 결정론적 지갑
- 📍 **주소 생성**: P2PKH, P2SH, P2WPKH (SegWit) 주소 지원
- 🔧 **유틸리티**: 키 검증, 주소 검증, 네트워크 정보
- 🌐 **네트워크**: Mainnet & Testnet 완전 지원

### 🔵 Ethereum 지원
- 🔐 **니모닉 & 계정 관리**: 생성, 검증, 다중 계정 지원
- 💼 **HD 지갑**: 계층적 결정론적 지갑 완전 지원
- ✍️ **메시지 서명**: 이더리움 표준 메시지 서명 및 검증
- 🚀 **실제 트랜잭션**: Sepolia 테스트넷에서 실제 트랜잭션 전송
- 🛠️ **유틸리티**: 단위 변환, 주소 검증, 가스 추정
- 📊 **최신 기술**: Alloy 1.0.6, EIP-1559, Rust 최신 패턴


## 🚀 빠른 시작

### 1. 설치 및 실행
프로젝트 클론
git clone <your-repo-url>
- cd multi-chain-wallet-api

환경 변수 설정 (선택적)
- cp .env.example .env

빌드 및 실행
- cargo run --release


### 1-1. Docker 설치 및 실행

이미지 빌드
- docker-compose build

서비스 시작 
- docker-compose up -d

로그 확인
- docker-compose logs -f xwallet-api

상태 확인
- docker-compose ps

개발 환경 실행
- docker-compose -f docker-compose.dev.yml up -d

프로덕션 환경 실행
- docker-compose up -d

컨테이너 내부 접속
- docker-compose exec xwallet-api sh

로그 실시간 확인
- docker-compose logs -f

서비스 재시작
- docker-compose restart xwallet-api

서비스 중지
- docker-compose down

볼륨까지 삭제
- docker-compose down -v

이미지 재빌드
- docker-compose build --no-cache


### 2. 서버 확인
헬스체크
- curl http://localhost:3030/health

Bitcoin 헬스체크
- curl http://localhost:3030/api/v1/bitcoin/health

Ethereum 네트워크 상태
- curl http://localhost:3030/api/v1/ethereum/network/status


## 📚 API 문서

### 🟠 Bitcoin API

#### 🔐 니모닉 & 키 관리
| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/api/v1/bitcoin/mnemonic/generate` | POST | 니모닉 생성 (12/24 단어) |
| `/api/v1/bitcoin/mnemonic/validate` | POST | 니모닉 검증 |
| `/api/v1/bitcoin/mnemonic/to-seed` | POST | 니모닉 → 시드 변환 |
| `/api/v1/bitcoin/mnemonic/to-xprv` | POST | 니모닉 → XPRV 변환 |

#### 🔑 키 운영
| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/api/v1/bitcoin/key/derive-child` | POST | 자식 키 파생 |
| `/api/v1/bitcoin/key/xprv-to-wif` | POST | XPRV → WIF 변환 |
| `/api/v1/bitcoin/key/wif-to-public` | POST | WIF → 공개키 변환 |

#### 📍 주소 생성
| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/api/v1/bitcoin/address/from-wif` | POST | WIF에서 주소 생성 |
| `/api/v1/bitcoin/address/from-xprv` | POST | XPRV에서 주소 생성 |
| `/api/v1/bitcoin/address/from-mnemonic` | POST | 니모닉에서 주소 생성 |
| `/api/v1/bitcoin/address/from-public-key` | POST | 공개키에서 주소 생성 |

#### 🏗️ BIP-84 운영 (SegWit)
| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/api/v1/bitcoin/bip84/descriptors/create` | POST | BIP-84 디스크립터 생성 |
| `/api/v1/bitcoin/bip84/address` | POST | BIP-84 주소 생성 |
| `/api/v1/bitcoin/bip84/next-address` | POST | 다음 BIP-84 주소 |
| `/api/v1/bitcoin/bip84/multiple-addresses` | POST | 다중 BIP-84 주소 |

#### 🛠️ 유틸리티
| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/api/v1/bitcoin/utils/validate-private-key` | POST | 개인키 검증 |
| `/api/v1/bitcoin/utils/validate-address` | POST | 주소 검증 |
| `/api/v1/bitcoin/utils/network-info` | POST | 네트워크 정보 |

### 🔵 Ethereum API

#### 🔐 니모닉 & 계정
| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/api/v1/ethereum/mnemonic/generate` | POST | 니모닉 생성 |
| `/api/v1/ethereum/mnemonic/validate` | POST | 니모닉 검증 |
| `/api/v1/ethereum/account/create` | POST | 계정 생성 |
| `/api/v1/ethereum/account/create-multiple` | POST | 다중 계정 생성 |
| `/api/v1/ethereum/account/from-private-key` | POST | 개인키로 계정 생성 |
| `/api/v1/ethereum/account/random` | POST | 랜덤 계정 생성 |

#### 💼 HD 지갑
| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/api/v1/ethereum/wallet/hd/create` | POST | HD 지갑 생성 |
| `/api/v1/ethereum/wallet/multi-account/create` | POST | 다중 계정 지갑 |
| `/api/v1/ethereum/wallet/add-account` | POST | 계정 추가 |
| `/api/v1/ethereum/wallet/generate-addresses` | POST | 주소 생성 |
| `/api/v1/ethereum/wallet/keystore/create` | POST | 키스토어 생성 |

#### 🚀 트랜잭션 (Sepolia)
| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/api/v1/ethereum/transaction/create` | POST | 트랜잭션 생성 |
| `/api/v1/ethereum/transaction/sign` | POST | 트랜잭션 서명 |
| `/api/v1/ethereum/transaction/send` | POST | **🔥 실제 전송** |
| `/api/v1/ethereum/transaction/send-raw` | POST | Raw 트랜잭션 전송 |
| `/api/v1/ethereum/transaction/estimate-gas` | POST | 가스 추정 |
| `/api/v1/ethereum/transaction/calculate-fee` | POST | 수수료 계산 |
| `/api/v1/ethereum/network/status` | GET | 네트워크 상태 |

## 💡 사용 예시

### 🟠 Bitcoin 사용 예시

#### 니모닉 생성
```bash
curl -X POST http://localhost:3030/api/v1/bitcoin/mnemonic/generate
-H "Content-Type: application/json"
-d '{"word_count": 12}'
```

#### BIP-84 SegWit 주소 생성
```bash
curl -X POST http://localhost:3030/api/v1/bitcoin/bip84/address
-H "Content-Type: application/json"
-d '{
"mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
"network": "testnet",
"is_change": false,
"index": 0
}'
```

#### 주소 검증
```bash
curl -X POST http://localhost:3030/api/v1/bitcoin/utils/validate-address
-H "Content-Type: application/json"
-d '{
"address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
"expected_network": "testnet"
}'
```

### 🔵 Ethereum 사용 예시

#### 니모닉 생성
```bash
curl -X POST http://localhost:3030/api/v1/ethereum/mnemonic/generate
-H "Content-Type: application/json"
-d '{"word_count": 12}'
```

#### 계정 생성
```bash
curl -X POST http://localhost:3030/api/v1/ethereum/account/create
-H "Content-Type: application/json"
-d '{
"mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
"path": "m/44''''/60''''/0''''/0/0",
"password": ""
}'
```

#### 🔥 실제 Sepolia 트랜잭션 전송
```bash
curl -X POST http://localhost:3030/api/v1/ethereum/transaction/send
-H "Content-Type: application/json"
-d '{
"to": "0x742d35Cc6634C0532925a3b8D6Ac6A5b2c1a5a5a",
"private_key": "0x1234567890abcdef...",
"value_ether": 0.01,
"gas_limit": 21000,
"wait_for_confirmation": true
}'
```

## 🛠️ 개발

### 로컬 개발 환경

개발 모드 실행
cargo run

테스트 실행
cargo test

Bitcoin 모듈만 테스트
cargo test bitcoin

Ethereum 모듈만 테스트
cargo test ethereum

린트 체크
cargo clippy

포맷팅
cargo fmt


### 환경 변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `HOST` | `0.0.0.0` | 서버 호스트 |
| `PORT` | `3030` | 서버 포트 |
| `LOG_LEVEL` | `info` | 로그 레벨 |
| `RUST_LOG` | `multi_chain_wallet_api=info` | 상세 로그 설정 |

## 🔒 보안 고려사항

- ⚠️ **개인키 보안**: 개인키는 메모리에서만 처리되며 저장되지 않음
- 🔐 **HTTPS 사용**: 프로덕션에서는 반드시 HTTPS 사용
- 🛡️ **API 인증**: 필요시 API 키 인증 구현 권장
- 🔄 **레이트 리미팅**: 높은 트래픽 시 레이트 리미팅 구현
- 🌐 **네트워크 분리**: Mainnet과 Testnet 환경 분리 운영

## 📦 의존성

### Bitcoin
- **Bitcoin**: 최신 Bitcoin 라이브러리
- **BIP39**: 니모닉 구문 생성 및 검증
- **Secp256k1**: 타원곡선 암호화

### Ethereum
- **Alloy 1.0.6**: 최신 이더리움 라이브러리
- **Ethers**: 이더리움 유틸리티

### 공통
- **Warp**: 고성능 웹 프레임워크
- **Tokio**: 비동기 런타임
- **Tracing**: 구조화된 로깅
- **Serde**: JSON 직렬화/역직렬화

## 🌐 지원 네트워크

| 체인 | 네트워크 | 상태 | 설명 |
|------|----------|------|------|
| Bitcoin | Mainnet | ✅ | 실제 비트코인 네트워크 |
| Bitcoin | Testnet | ✅ | 비트코인 테스트 네트워크 |
| Ethereum | Sepolia | ✅ | 이더리움 테스트 네트워크 |
| Ethereum | Mainnet | 🚧 | 개발 예정 |

## 🤝 기여

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 라이센스

MIT License. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 🆘 지원

- 📧 이메일: your-email@example.com
- 🐛 이슈: [GitHub Issues](https://github.com/your-username/multi-chain-wallet-api/issues)
- 📖 Bitcoin 문서: [Bitcoin API Documentation](https://your-bitcoin-api-docs-url.com)
- 📖 Ethereum 문서: [Ethereum API Documentation](https://your-ethereum-api-docs-url.com)

## 🗺️ 로드맵

- [x] Bitcoin Mainnet/Testnet 지원
- [x] Ethereum Sepolia 지원
- [x] BIP-84 SegWit 주소 지원
- [ ] Ethereum Mainnet 지원
- [ ] Bitcoin 트랜잭션 생성/전송
- [ ] 다중 서명 지원
- [ ] 하드웨어 지갑 연동
- [ ] Lightning Network 지원

---

⭐ 이 프로젝트가 도움이 되었다면 스타를 눌러주세요!
