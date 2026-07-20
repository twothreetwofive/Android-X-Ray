# X-ray — 안드로이드 악성코드 정적/동적/네트워크 분석 자동화

이삼이오_방캅스 팀. 안드로이드 악성코드(Anubis) 분석 경험을 바탕으로, apk를 넣으면
정적/동적/네트워크 분석 결과를 자동으로 뽑아주는 도구를 만드는 프로젝트.
전체 배경과 8주 로드맵은 `CLAUDE.md` 참고.

## 진행 상황

| 모듈 | 상태 |
|---|---|
| 정적 분석 (`src/static_analyzer/`) | ✅ 완료 |
| 동적 분석 (Frida) | 🚧 진행 중 (`feature/dynamic-agent`, A/B/C/D 4일차까지 완료, 5일차 전원 통합 남음) |
| 네트워크 분석 | 예정 |
| 웹 대시보드 | 예정 |

---

## 1. 정적 분석 모듈 (완료)

역할 분배와 최종 상태:

| 역할 | 내용 | 상태 |
|---|---|---|
| A | 패키지 구조 설계, `analyze_static()` 인터페이스, 출력 스키마(`schema.py`) | 완료 |
| B | `apktool`/`jadx` 호출 wrapper (타임아웃, 예외 처리) | 완료 |
| C | `AndroidManifest.xml` 파싱 (androguard), 위험 권한/컴포넌트 추출 | 완료 |
| D | 위험도 점수 계산, 출력 취합 | 완료 |

추가로 A가 스키마(`schema.py`)에는 정의해뒀지만 역할 배정에는 없었던 인증서 분석 /
코드 스캔 / 문자열 추출 / SDK 탐지 4개 모듈도 구현 완료 — `analyze_static()`이
스키마의 8개 필드(`meta`/`manifest`/`certificate`/`code_analysis`/`strings`/
`third_party_sdks`/`risk_score`/`errors`)를 전부 채워서 반환한다.

### static_analyzer/ 모듈별 역할

```
src/static_analyzer/
├── __init__.py         # 패키지 공개 API
├── analyzer.py          # analyze_static(apk_path) -> dict, 오케스트레이터가 이것만 import
├── apk_extractor.py     # apktool/jadx 실행 + apk 메타데이터(해시, 패키지명, sdk 버전) 추출
├── decompiler.py         # apktool d / jadx CLI를 subprocess로 감싸는 저수준 wrapper
├── manifest_parser.py   # AndroidManifest.xml 파싱 (androguard) — 권한/컴포넌트/exported 체크
├── cert_analyzer.py     # 서명 인증서(발급자/유효기간/자가서명 여부) 추출 (androguard)
├── code_scanner.py      # jadx 소스 트리에서 의심 API 호출·난독화·리플렉션·네이티브 라이브러리 탐지
├── string_extractor.py  # jadx 소스 트리에서 URL/IP/의심 문자열 추출
├── sdk_detector.py      # 알려진 서드파티 SDK 패키지 시그니처 매칭
├── risk_scorer.py       # 권한 가중치 + 코드/문자열 스캔 결과를 합쳐 0.0~1.0 위험도 계산
├── schema.py            # analyze_static() 출력 타입 정의 (TypedDict) — 팀 공유 계약
└── exceptions.py        # StaticAnalysisError 등 커스텀 예외
```

각 파일이 왜 나뉘어 있는지:

- **decompiler.py vs apk_extractor.py** — `decompiler.py`는 "apktool/jadx를 어떻게 실행하고
  실패를 어떻게 처리할지"만 담당. `apk_extractor.py`는 그 위에서 "apk 하나를 분석 가능한
  형태로 준비"하는 조립 담당 — 디컴파일 실행 + 해시/버전 같은 메타데이터 추출을 묶어서
  `analyzer.py`가 쓰기 좋은 dict로 반환한다. 다른 모듈이 필요로 하는 `jadx_dir`/`apk_path`도
  여기서 만들어서 넘겨준다.
- **manifest_parser.py, cert_analyzer.py는 decompiler.py 결과물을 안 씀** — androguard가
  apk 파일 자체에서 바로 Manifest/서명 인증서를 읽기 때문에, apktool로 압축을 풀 필요가
  없음. 반면 `code_scanner`/`string_extractor`/`sdk_detector`는 jadx가 만든 자바 소스 트리
  텍스트를 훑어야 해서 `apk_extractor`가 만든 `jadx_dir`이 필요함.
- **schema.py** — 실제 코드가 아니라 "출력 형식 계약"만 있는 파일. 새 필드를 추가/변경하려면
  여기부터 고치고 팀에 공유해야 함 (임의로 바꾸면 다른 사람 코드가 깨짐).
- **exceptions.py** — `StaticAnalysisError`가 최상위 예외. `decompiler.py`의
  `DecompileError`/`DecompileTimeoutError`는 전부 이 예외의 하위 클래스라서, 오케스트레이터는
  `except StaticAnalysisError`로 apktool/jadx 실패와 미래에 추가될 다른 치명적 실패를 한 번에
  잡을 수 있음.
- **analyzer.py의 부분 실패 처리** — apk 자체가 없거나 apktool/jadx 실행이 실패하는 건
  치명적이라 그대로 예외를 던지지만, 그 이후 6개 하위 모듈(manifest/cert/code/strings/
  sdk/risk) 중 하나가 실패해도 나머지는 계속 진행하고 `errors`에 사유만 남김.

### ⚠️ 정적 분석 — 아직 안 맞춰진 것 / 검증 안 된 것

- **`risk_scorer.py`의 점수 계산식은 1차 추측치임**: 권한 가중치·exported 컴포넌트 개수·
  의심 API 개수 등을 그냥 더해서 100으로 나눈 임의의 공식(`NORMALIZATION_CAP = 100.0`).
  정상 앱 2~3개 vs 공개 악성 샘플 2~3개로 실제 돌려서 점수 차이가 나는지 확인하고
  가중치를 다시 맞춰야 함.
- **실제 apk로 end-to-end 검증 안 됨**: apktool/jadx/실제 apk 샘플이 없는 환경에서
  통합했음. `decompiler.py`/`risk_scorer`는 가짜 도구·가짜 데이터로 로직만 검증했고,
  `code_scanner`/`string_extractor`/`sdk_detector`는 jadx 출력과 비슷하게 흉내낸 가짜
  디렉터리로 검증함. `cert_analyzer`는 API 존재만 확인했고 실제 서명된 apk로는 아직
  안 돌려봄. **팀원 중 apktool/jadx가 깔린 환경에서 실제 apk(anubis.apk 등)로
  `analyze_static()`을 한 번 돌려서 8개 필드가 다 정상적으로 채워지는지 확인 필요.**

---

## 2. 동적 분석 모듈 (2026-07-15(수) 시작)

Frida로 앱을 후킹해서 런타임 행위(문자열 복호화, 암호화 함수 호출 등)를 관찰하는 모듈.
5일 일정, 전원 동일 기간으로 진행.

| 역할 | 담당 | 내용 | 산출물 | 상태 |
|---|---|---|---|---|
| A | 예원 | Frida 제어 스크립트 (세션 생성, attach/spawn) | `frida_controller.py` | 4일차까지 완료 (재시도/배치 실행 포함) |
| B | 소정 | JS 후킹 스크립트 (문자열/Base64/Cipher 등) | `hooks.js` | 4일차까지 완료, `custom_xor`은 실 샘플 부재로 보류 |
| C | 은아 | Python-JS 연동, 메시지 파싱/필터링 | 메시지 파서, `dynamic_report.json` | 4일차까지 완료, 인프라 버그(esbuild interop) 수정 포함 |
| D | 은서 | 실행 시나리오 자동화 (ADB/에뮬레이터) | `scenario_runner.py`, 시나리오 정의서 | 4일차까지 완료(문법 검증만, 실기기 실행 미검증). `login_flow`/`permission_request` 좌표는 실 샘플 부재로 보류 |

5일차(전원 통합, 실제 앱 2개로 A→B→C→D end-to-end 실행)는 아직 진행 전.
자세한 진행 상황은 `docs/동적분석/`의 팀원별 4주차 과제 보고서 참고.

작업 비중: A > C > B > D

### 핵심 원칙 — 3일차는 "인수인계 데드라인"

C는 A(세션)+B(후킹)가 둘 다 있어야 실제 메시지 흐름을 검증할 수 있고, D는 A(제어
스크립트)가 있어야 실제 앱 자동 구동을 검증할 수 있음. 그래서 **A, B는 3일차까지
"완벽하지 않아도 실제로 동작하는 최소 버전"을 반드시 넘겨야** C, D가 4~5일차에
제대로 통합/검증할 시간이 생김.

### 5일 스케줄

**1일차 — 각자 독립 가능한 부분부터**
- A: frida-server 연결 확인, 세션 생성(attach/spawn) 로직 작성 시작
- B: 대상 앱 클래스/함수 구조 분석, 후킹 대상 함수 목록 확정 (`StringBuilder.append`, `Base64`, `Cipher.doFinal` 등)
- C: 메시지 JSON 스키마 설계 (A/B 필요 없음) — 확정되는 대로 A, B에게 공유 ("JS에서 이 필드명으로 `send()` 해줘")
- D: 테스트 시나리오 목록 작성(로그인, 권한 요청 등), `adb shell` 명령으로 앱 수동 실행 자동화 초안

**2일차 — 각자 핵심 로직 완성**
- A: attach/spawn 로직 완성, `resume()` 흐름까지 동작 확인
- B: `Interceptor.attach`로 실제 후킹 코드 작성, frida CLI로 단독 테스트 (`frida -U -f 패키지명 -l hooks.js`)
- C: 확정한 스키마 기준으로 메시지 파서 구조 설계 (아직 실데이터 없이 더미로)
- D: `scenario_runner.py` 뼈대 작성, adb 자동화 로직 보강

**3일차 — ⭐ 인수인계 데드라인 ⭐**
- A: `frida_controller.py` 최소 동작 버전을 D에게 전달 (spawn→resume 되는 상태)
- B: `hooks.js` 최소 동작 버전을 C에게 전달 (문자열/Base64/Cipher 후킹 되는 상태)
- C: A의 세션 + B의 후킹 스크립트를 실제로 연결해서 `script.on('message', ...)`로 첫 실데이터 수신 테스트
- D: A의 제어 스크립트로 실제 시나리오(로그인 등) 자동 실행 테스트 시작

**4일차 — 각자 마무리 + 검증**
- A: 재시도/타임아웃 처리, 배치 실행(여러 앱) 지원 추가
- B: 커스텀 XOR 등 표준 API로 못 잡는 패턴 보강, 후킹 노이즈 필터링 조언(C에게)
- C: 실제 후킹 데이터 기반으로 필터링(중복 제거, 평문 판별) 로직 완성, `dynamic_report.json` 1차 출력
- D: 시나리오 반복 실행 재현성 확인, 엣지 케이스(앱 크래시, 미실행) 대응 로직 추가

**5일차 — 전원 통합**
- 전원이 실제 앱(정상 1개 + 악성 1개)으로 A→B→C→D 전체 파이프라인 end-to-end 실행
- 버그 수정, `dynamic_report.json` 최종 형식 확인
- 발표자료(데모 캡처, 실행 로그) 준비

---

## 3. schemas/ — 각 스키마가 무슨 역할을 하는지

`schemas/` 폴더는 정적/동적/네트워크 세 모듈이 서로 다른 형식으로 결과를 내서 나중에
파이프라인 통합(main.py) 때 파싱 에러가 나는 걸 막기 위한 **출력 형식 초안**이다.

| 파일 | 역할 | 상태 |
|---|---|---|
| `schemas/README.md` | 세 스키마 전체 설명 문서 | - |
| `schemas/static_report.schema.json` | 정적 분석 출력 초안 (`meta`/`permissions`/`components`/`risk_score`) | ⚠️ 1주차 초안, 아래 참고 |
| `schemas/dynamic_report.schema.json` | 동적 분석 출력 — `meta`(패키지명/실행시각/관찰시간), `hooked_calls`(후킹된 함수 호출 기록), `extracted_strings`(정제된 문자열, base64/url/평문 여부 추정) | 4주차에 C가 실제로 채워나갈 대상 |
| `schemas/network_report.schema.json` | 네트워크 분석 출력 — `meta`, `dns_queries`(조회 도메인), `tls_sni`(HTTPS 접속 대상), `suspicious`(C&C 후보 도메인/IP) | 5~6주차에 쓸 예정 |

**`schemas/static_report.schema.json` vs `src/static_analyzer/schema.py`**: 이름이
비슷해서 헷갈리기 쉬운데 서로 다른 파일이다. `schemas/static_report.schema.json`은
1주차에 만든 4필드짜리 초안이고, `src/static_analyzer/schema.py`는 A가 3주차에 실제로
확정한 8필드짜리 최신 버전(팀 코드가 지금 이걸 기준으로 동작함). 정적 분석은 이제
완료됐으니 `schemas/static_report.schema.json`도 `schema.py`에 맞춰 갱신할지 팀 논의
필요 — 다만 정적+동적+네트워크 파이프라인 통합은 5~6주차라 지금 당장 급하지는 않음.

`dynamic_report.schema.json`은 지금 시작하는 동적 분석 모듈의 목표 출력 형식이니,
C가 메시지 파서를 설계할 때(1일차) 이 파일을 기준으로 필드명을 맞추면 된다.

---

## 개발 환경

- 팀 전체가 `docs/androidStudio_match.pdf` 가이드대로 에뮬레이터(`xray_api30`, Pixel 4 /
  API 30 / Google APIs / x86_64)를 통일해서 씀.
- 의존성은 `requirements.txt` 참고 (`pip install -r requirements.txt`). apktool/jadx는 별도
  설치 필요 (pip 패키지 아님) — 설치 후 PATH 등록까지 해야 `decompiler.py`가 찾을 수 있음.

## 관련 문서

- `CLAUDE.md` — 프로젝트 개요, 8주 로드맵
- `schemas/README.md` — 정적/동적/네트워크 세 모듈의 JSON 출력 스키마 초안 설명
- `docs/4주차_계획_자료_수합_후_환경_통일.pdf` — 정적 분석 완료 시점 스냅샷 + 동적 분석 역할 초안
- `docs/2주차_통합_발표자료.md` — 2주차 발표자료
