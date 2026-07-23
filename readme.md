# Secure Coding — Tiny Second-hand Shopping Platform

WhiteHat School 시큐어 코딩 과제. 제공된 취약한 Flask 스켈레톤을 기반으로
전체 기능을 구현하고 보안 약점을 제거한 중고거래 플랫폼입니다.

## 구현 기능

- **유저 관리**: 회원가입, 로그인/로그아웃, 사용자 조회, 마이페이지(소개글·비밀번호 변경)
- **상품 관리**: 상품 등록(사진 업로드), 내 상품 수정·삭제, 상품 조회, 상품 상세
- **유저 소통**: 실시간 전체 채팅, 1:1 채팅(DB 저장)
- **악성 유저 필터링**: 상품/사용자 신고, 신고 누적 시 자동 차단·휴면, 관리자 수동 조치
- **거래**: 잔액 충전(모의 결제), 유저 간 송금, 상품 구매(자동 결제·판매완료 처리·구매내역)
- **관리자**: 유저 잔액 지급, 유저 휴면/활성, 상품 차단/삭제, 신고 조회
- **검색**: 상품·사용자 검색
- **관리자**: 전체 유저/상품/신고 관리 페이지

## 환경 설정

miniconda가 없으면 먼저 설치: https://docs.anaconda.com/free/miniconda/

```bash
git clone <your-repo-url>
cd secure-coding
conda env create -f enviroments.yaml
conda activate secure_coding
# 또는 pip install -r requirements.txt
```

## 실행

```bash
python app.py
```

브라우저에서 http://127.0.0.1:5000 접속.

- 관리자 계정: `admin` / 비밀번호는 `ADMIN_PASSWORD` 환경변수(기본 `admin1234!`)
- 포트 변경: `PORT=5001 python app.py` (macOS는 5000번을 AirPlay가 점유할 수 있음)
- 로컬 디버깅: `FLASK_DEBUG=1 python app.py`
- HTTPS 운영 시: `COOKIE_SECURE=1` 로 Secure 쿠키 활성화

### 외부 접속 테스트 (선택)

```bash
sudo snap install ngrok
ngrok http 5000
```

업로드된 이미지는 `uploads/` 폴더에 저장되며, 로그인한 사용자만 조회할 수 있다.

## 보안 조치 요약

| 항목 | 조치 |
|------|------|
| 비밀번호 | werkzeug 해시(+salt) 저장, 평문 미저장 |
| SECRET_KEY | 하드코딩 제거, 환경변수/랜덤 |
| CSRF | Flask-WTF CSRFProtect, 전 폼 토큰 |
| SQL Injection | 파라미터 바인딩(`?`) 전면 사용 |
| XSS | Jinja 자동 이스케이프 + bleach 서버측 sanitize + textContent |
| 입력 검증 | 서버측 길이·형식·범위 검증 |
| 인증/인가 | login_required / admin_required, 상품 소유자 검증 |
| 로그인 방어 | 실패 횟수 기반 계정 잠금 |
| 세션 쿠키 | HttpOnly, SameSite, (운영)Secure |
| 보안 헤더 | CSP, X-Frame-Options, X-Content-Type-Options |
| 에러 처리 | 커스텀 에러 페이지(스택트레이스 은닉), debug=False |
| 채팅 | 소켓 인증·길이 제한·rate limit |
| 신고 | 자기신고·중복신고 방지, 임계치 자동 조치 |
| 구매/결제 | 트랜잭션 원자성, 본인상품·중복구매·잔액부족 차단, 동시구매(race) 방지 |
| 충전 | 1회/누적 한도, 음수·비정수 차단, POST+CSRF, 거래 기록 |
| 파일 업로드 | 확장자 화이트리스트, 매직바이트 검증, 크기 제한, UUID 파일명 재생성 |
