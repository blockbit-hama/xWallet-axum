# 멀티스테이지 빌드를 사용하여 최적화된 이미지 생성
FROM rust:1.75-alpine AS builder

# 필요한 패키지 설치
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    pkgconfig \
    git

# 작업 디렉토리 설정
WORKDIR /app

# 의존성 캐싱을 위한 더미 프로젝트 생성
RUN USER=root cargo new --example xWallet
WORKDIR /app/xWallet

# Cargo.toml과 Cargo.lock 복사
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock

# 의존성 빌드 (캐싱 최적화)
RUN cargo build --release
RUN rm src/*.rs

# 실제 소스 코드 복사
COPY ./src ./src

# 애플리케이션 빌드
RUN rm ./target/release/deps/xWallet*
RUN cargo build --release

# 런타임 이미지
FROM alpine:latest

# 런타임 의존성 설치
RUN apk add --no-cache \
    ca-certificates \
    openssl \
    libgcc

# 비루트 사용자 생성
RUN addgroup -g 1000 appuser && \
    adduser -D -s /example/sh -u 1000 -G appuser appuser

# 작업 디렉토리 생성
WORKDIR /app

# 빌드된 바이너리 복사 (대소문자 주의!)
COPY --from=builder /app/xWallet/target/release/xWallet /app/xWallet

# 환경 설정 파일 복사 (있다면)
COPY .env.example /app/.env

# 소유권 변경
RUN chown -R appuser:appuser /app

# 비루트 사용자로 전환
USER appuser

# 포트 노출
EXPOSE 3030

# 헬스체크 추가
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3030/health || exit 1

# 애플리케이션 실행 (대소문자 주의!)
CMD ["./xWallet"]
