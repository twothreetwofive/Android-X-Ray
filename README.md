# X-ray — 안드로이드 APK 정적/동적/네트워크 분석 자동화

이삼이오_방캅스 팀. APK를 넣으면 정적·동적·네트워크 분석을 한 번에 돌려서
**위험 지표와 보안 판정을 분리해 보여주는** 통합 대시보드.
전체 배경과 8주 로드맵은 `CLAUDE.md` 참고.

> ⚠️ 본 도구의 결과는 분석 과정에서 관찰된 보안 위험 지표를 기반으로 산출된 위험도이며,
> **악성 여부를 단독으로 확정하지 않는다.**

---

## 진행 상황 (2026-08-13 기준)

| 구성 요소 | 상태 |
|---|---|
| 정적 분석 (`src/static_analyzer/`) | ✅ 완료 |
| 동적 분석 (`src/dynamic_analyzer/`, Frida) | ✅ 완료 |
| 네트워크 분석 (`src/network_analyzer/`) | ✅ 완료 |
| 오케스트레이터 (`src/main.py`) | ✅ 완료 |
| 위험도 스코어링 (`src/risk_aggregator.py`) | ✅ 완료 |
| 웹 대시보드 (`app.py` + `views/`) | ✅ 완료 |
| 실샘플 검증 | 🚧 정상 2종 / 악성 1종 완료, 표본 확대 필요 |

- **8주차에 실제 APK로 세 모듈이 모두 성공하는 것을 처음 확인함.** 상세는
  `docs/8주차보고서_B.md`
- 테스트 183개 통과 (`python3 -m pytest -q`)

---

## 빠른 시작

### 1. 의존성

```bash
pip install -r requirements.txt
```

`apktool` / `jadx` / `adb` / `frida-server`는 pip 패키지가 아니라 별도 설치 후
PATH 등록이 필요함. WSL 환경 구축 절차는 **`docs/8주차_로컬테스트_가이드.md`** 에 정리돼 있음.

### 2. 정적 분석만 (에뮬레이터 불필요)

```bash
python3 src/main.py <apk경로> --output output/report_<이름>.json
```

에뮬레이터가 없으면 동적·네트워크는 `분석 실패`로 표시되고 정적 결과만 나옴
(부분 리포트 정책 — 한 모듈이 죽어도 리포트는 항상 생성됨).

### 3. 전체 파이프라인

```bash
source scripts/wsl_env.sh                  # PATH 설정 (매 터미널 1회)
bash scripts/connect_emulator.sh           # 에뮬레이터 연결
bash scripts/prepare_emulator.sh <apk경로> # tcpdump·frida-server 준비 + 앱 설치
python3 src/main.py <apk경로> --output output/report_<이름>.json --observe-sec 15
```

### 4. 대시보드

```bash
streamlit run app.py        # http://localhost:8501
```

업로드하면 **에뮬레이터 설치까지 자동으로 처리**함(`preflight.py`). 준비가 안 된
항목이 있으면 무엇을 실행하면 되는지 화면에 안내함.

기기 없이 화면만 확인하려면:

```bash
streamlit run demo_risk.py     # 판정 카드 + 종합 위험도 (5가지 상태)
streamlit run demo_static.py   # 정적 탭
```

---

## 결과 읽는 법 — 분석 상태 ≠ 보안 판정

8주차에 두 축을 코드 수준에서 분리함. 이전에는 모듈 상태 "정상"이 "이 앱이 안전하다"로
읽히는 문제가 있었음.

**분석 상태(Status)** — 파이프라인이 돌았는가

| 값 | 뜻 |
|---|---|
| 분석 성공 / 부분 성공 | 해당 모듈이 실행에 성공함 (앱의 안전 여부와 무관) |
| 분석 실패 / 시간 초과 | 모듈이 실행되지 못함 |

**보안 판정(Verdict)** — 관찰된 지표로 볼 때 얼마나 위험한가

| 구간 | 판정 |
|---|---|
| 0–29 | 🟢 정상 |
| 30–59 | 🟡 주의 |
| 60–79 | 🟠 의심 |
| 80–100 | 🔴 고위험 |

- **"악성"은 점수만으로 주지 않음.** 종합 80점 이상 **그리고** 강한 지표 3개 이상을
  둘 다 충족할 때만 표시하며, 충족하지 못한 이유를 화면에 그대로 노출함
- **관측된 데이터가 없는 모듈은 0점(=안전)이 아니라 "정보 없음"으로 처리**하고 점수에서
  제외 후 가중치를 재정규화함. "관측 없음"은 "위험 없음"이 아니기 때문

---

## 디렉터리 구조

```
├── app.py                  # Streamlit 진입점 (업로드 → 분석 → 4개 탭)
├── preflight.py            # 분석 전 에뮬레이터 준비 점검 + 앱 자동 설치
├── pipeline_bridge.py      # 대시보드 ↔ 오케스트레이터 연결
├── common.py               # 뷰 공용 상수(상태 라벨, 판정 색/구간, 고지 문구)
├── views/                  # 대시보드 화면
│   ├── verdict_header.py   #   최종 판정 카드 (탭 위, 항상 보임)
│   ├── static_view.py      #   정적 탭
│   ├── dynamic_view.py     #   동적 탭
│   ├── network_view.py     #   네트워크 탭
│   ├── risk_view.py        #   종합 위험도 탭
│   └── static_data.py      #   정적 뷰의 값 가공 (streamlit 없음 → pytest 대상)
├── src/
│   ├── main.py             # 오케스트레이터 (CLI 진입점)
│   ├── risk_aggregator.py  # 세 모듈 결과 → 종합 위험도 + 보안 판정
│   ├── static_analyzer/    # 정적 분석
│   ├── dynamic_analyzer/   # 동적 분석 (Frida)
│   └── network_analyzer/   # 네트워크 분석
├── scripts/                # 실행 환경 준비 도구
├── tests/                  # pytest 183개
└── docs/                   # 주차별 보고서·가이드
```

### scripts/

| 스크립트 | 역할 |
|---|---|
| `wsl_env.sh` | apktool/jadx/adb PATH 설정 |
| `connect_emulator.sh` | WSL ↔ Windows 에뮬레이터 adb 연결 (상태 확인 후 필요한 것만 수행) |
| `prepare_emulator.sh` | adb root → tcpdump 준비 → frida-server 기동 → APK 설치 |
| `snapshot.sh` | 에뮬레이터 스냅샷 save/load/list |
| `check_apk_compat.py` | 받은 APK가 팀 AVD에 설치 가능한지 사전 판별 |

---

## 모듈별 설명

### 정적 분석 (`src/static_analyzer/`)

```
analyzer.py          # analyze_static(apk_path) -> dict, 오케스트레이터는 이것만 import
apk_extractor.py     # 디컴파일 실행 + 메타데이터(해시/패키지명/SDK) 추출
decompiler.py        # apktool d / jadx CLI subprocess wrapper (타임아웃·예외)
manifest_parser.py   # AndroidManifest 파싱 (androguard) — 권한/컴포넌트/exported
cert_analyzer.py     # 서명 인증서 (발급자/유효기간/자가서명)
code_scanner.py      # 의심 API·난독화·리플렉션·네이티브 라이브러리·패킹된 자산 탐지
string_extractor.py  # URL/IP/의심 문자열 추출
sdk_detector.py      # 서드파티 SDK 시그니처 매칭
risk_scorer.py       # 항목별 가중치 합산 → 0.0~1.0
schema.py            # 출력 타입 정의 (TypedDict) — 팀 공유 계약
```

- **decompiler.py vs apk_extractor.py** — 앞은 "도구를 어떻게 실행하고 실패를 어떻게
  처리할지", 뒤는 그 위에서 "apk 하나를 분석 가능한 형태로 준비"하는 조립 담당
- **manifest_parser / cert_analyzer는 디컴파일 결과를 쓰지 않음** — androguard가 apk에서
  바로 읽으므로 apktool 압축 해제가 필요 없음
- 작업 폴더는 `work/<파일명>-<sha256 앞8자>/` 로 **APK마다 분리**됨. 공유하면 이전 APK의
  소스가 남아 다음 분석 결과를 오염시킴(8주차 실측으로 확인)

### 동적 분석 (`src/dynamic_analyzer/`)

```
frida_controller.py  # 세션 관리 (spawn → attach → load → resume → cleanup)
hooks.js / .bundle.js# StringBuilder.append / Base64 / Cipher.doFinal 후킹
message_parser.py    # 후킹 이벤트 수집 → dynamic_report.json
scenario_runner.py   # A+B+C를 엮어 시나리오 실행, 크래시 감지
adb_runner.py        # adb 래퍼 (실행/탭/입력/권한 부여)
scenarios.py         # LAUNCH_ONLY / LOGIN_FLOW / PERMISSION_REQUEST
```

- 평문 후보는 `caller_class` 기준으로 **프레임워크 내부 호출을 제외**함. 제외하지 않으면
  `java.util.Formatter` 같은 런타임 호출이 수백 건 잡혀 정상 앱이 위험하게 보임
- `LOGIN_FLOW` / `PERMISSION_REQUEST`는 좌표가 아직 플레이스홀더라 사용 전 채워야 함

### 네트워크 분석 (`src/network_analyzer/`)

```
capture.py           # 기기에서 tcpdump 실행/종료/pull
scenario_capture.py  # 캡처 시작 → 시나리오 실행 → 종료 → pull 동기화
dns_parser.py        # DNS 질의/응답 파싱
sni_parser.py        # TLS ClientHello SNI 파싱
pcap_fallback.py     # tshark가 없을 때 scapy로 파싱 (형식 동일)
whitelist_checker.py # 화이트리스트 대조 → suspicious.domains
ip_checker.py        # 사설/루프백 제외 후 공인 IP를 하드코딩 접속 후보로 분류
report_builder.py    # 최종 NetworkAnalysisResult 조립
```

- `tcpdump`는 기기의 `/data/local/tmp/tcpdump` 경로를 사용함. 없으면 동적·네트워크가
  함께 실패하므로 `prepare_emulator.sh`가 먼저 준비함
- `tshark`가 없어도 동작함(scapy 폴백). tshark는 관리자 권한이 필요해 PC마다 갈림

---

## 8주차 실측 결과

| 샘플 | 종합 | 판정 | 정적 | 동적 | 네트워크 | 강한 지표 |
|---|---|---|---|---|---|---|
| `com.google.android.deskclock` (정상) | 28 | 🟢 정상 | 37 | 15 | 제외 | — |
| `com.google.android.calendar` (정상) | 46 | 🟡 주의 | 56 | 31 | 제외 | — |
| MalwareBazaar 드로퍼 (악성) | 44 | 🟡 주의 | 69 | 10 | 제외 | ⚠ 패킹된 페이로드 |

- 세 샘플 모두 분석 상태는 세 모듈 전부 "분석 성공"
- **점수만으로는 정상/악성이 아직 분리되지 않음** — 표본 3개 기준이며 상수 재조정은
  팀원 결과를 합쳐 8종이 된 뒤 진행할 예정. 근거와 논의 사항은 `docs/8주차보고서_B.md` 5절
- 결과 원본: `output/report_{deskclock,calendar,dropper}.json`

---

## 샘플 취급 규칙

- **저장소에 커밋 금지.** `.gitignore`에 `*.apk` `*.apk_` `*.dex` `*.zip` `samples/` 등록됨
- 샘플은 `~/samples/` 에만 둘 것
- MalwareBazaar 배포본은 **AES 암호화 zip**이라 Windows 기본 압축 해제로는 안 풀림
  (7-Zip 또는 `pyzipper` 필요, 비밀번호 `infected`)
- **실행 전 스냅샷 저장 필수**: `bash scripts/snapshot.sh save before_run`
  - 드로퍼는 2차 페이로드를 별도 패키지로 설치하므로 `adb uninstall`만으로는 정리되지 않음

---

## 개발 환경

- 에뮬레이터: Pixel 4 / **API 30** / Google APIs / x86_64
  (`abilist = x86_64,x86,arm64-v8a,armeabi-v7a` — ARM 변환 내장이라 샘플 ABI 제약 없음)
- `adb root`가 되어야 함 → Play Store 포함 이미지 대신 **Google APIs** 이미지 사용
- WSL에서 돌리는 경우 **WSL adb와 Windows adb의 버전이 같아야 함**. 다르면 WSL
  클라이언트가 원격 서버를 죽여 기기가 보이지 않음 (`docs/8주차_로컬테스트_가이드.md` 5-3)

```bash
python3 -m pytest -q          # 183개
```

---

## 관련 문서

| 문서 | 내용 |
|---|---|
| `CLAUDE.md` | 프로젝트 개요, 8주 로드맵 |
| `docs/8주차_로컬테스트_가이드.md` | 환경 구축부터 대시보드까지 단계별 명령 + 트러블슈팅 |
| `docs/8주차보고서_B.md` | 8주차 작업 내역, 실측 결과, 미해결 과제 |
| `docs/8주차_계획수정.pdf` | 판정 구조 개편 요구사항 |
| `schemas/README.md` | 세 모듈 JSON 출력 스키마 초안 |
| `src/static_analyzer/HANDOFF_B_to_A_D.md` | 정적 분석 인수인계 메모 |
