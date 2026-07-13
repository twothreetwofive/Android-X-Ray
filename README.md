# X-ray — 안드로이드 악성코드 정적/동적/네트워크 분석 자동화

이삼이오_방캅스 팀. 안드로이드 악성코드(Anubis) 분석 경험을 바탕으로, apk를 넣으면
정적/동적/네트워크 분석 결과를 자동으로 뽑아주는 도구를 만드는 프로젝트.
전체 배경과 8주 로드맵은 `CLAUDE.md` 참고.

## 지금 상태

정적 분석 모듈(`src/static_analyzer/`)은 완료. 4주차부터는 동적 분석(Frida) 모듈로 넘어감
(로드맵은 `CLAUDE.md` 참고).

3주차에 4명이 나눠 맡았던 것 + 원래 아무도 안 맡았던 나머지 모듈까지 전부 구현:

| 역할 | 담당 | 내용 | 상태 |
|---|---|---|---|
| A | 백소정 | 패키지 구조 설계, `analyze_static()` 인터페이스, 출력 스키마 | 완료 |
| B | 왕은서 | `apktool`/`jadx` 호출 wrapper (타임아웃, 예외 처리) | 완료 |
| C | 김은아 | `AndroidManifest.xml` 파싱 (androguard), 위험 권한/컴포넌트 추출 | 완료 |
| D | - | 위험도 점수 계산, `static_report.json` 출력 | **왕은서가 대신 작성** |
| (미배정) | - | 인증서/코드 스캔/문자열/SDK 탐지 (A가 설계만 해두고 아무도 안 맡음) | **왕은서가 대신 작성** |

D 역할과, A가 스키마에만 정의해두고 아무도 안 만들었던 4개 모듈
(`cert_analyzer`/`code_scanner`/`string_extractor`/`sdk_detector`)까지 왕은서가 채워서
`analyze_static()`이 스키마의 8개 필드를 전부 다 채워서 반환하도록 완성함.

## static_analyzer/ 모듈별 역할

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
  실패를 어떻게 처리할지"만 담당 (B 역할). `apk_extractor.py`는 그 위에서 "apk 하나를 분석
  가능한 형태로 준비"하는 조립 담당 — 디컴파일 실행 + 해시/버전 같은 메타데이터 추출을
  묶어서 `analyzer.py`가 쓰기 좋은 dict로 반환한다. 다른 모듈(cert_analyzer 제외한 나머지)이
  필요로 하는 `jadx_dir`/`apk_path`도 여기서 만들어서 넘겨준다.
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
  sdk/risk) 중 하나가 실패해도 나머지는 계속 진행하고 `errors`에 사유만 남김 (A의 설계
  원칙).

## ⚠️ 아직 안 맞춰진 것 / 검증 안 된 것 (팀 논의 필요)

- **`schemas/*.json` vs `src/static_analyzer/schema.py`**: `schemas/static_report.schema.json`은
  1주차에 만든 초안이고 필드가 `meta`/`permissions`/`components`/`risk_score` 4개뿐임. 반면
  `schema.py`(A가 3주차에 실제로 확정한 버전)는 `certificate`/`code_analysis`/`strings`/
  `third_party_sdks`/`errors`까지 포함해서 구조가 다름. 지금은 `schema.py`가 최신이니 이걸
  기준으로 삼고 있는데, `schemas/static_report.schema.json`도 여기 맞춰 갱신할지 팀 논의 필요
  (동적/네트워크 모듈과의 파이프라인 통합은 6주차라 아직 급하지 않음).
- **`risk_scorer.py`의 점수 계산식은 1차 추측치임**: 권한 가중치·exported 컴포넌트 개수·
  의심 API 개수 등을 그냥 더해서 100으로 나눈 임의의 공식(`NORMALIZATION_CAP = 100.0`).
  정상 앱 2~3개 vs 공개 악성 샘플 2~3개로 실제 돌려서 점수 차이가 나는지 확인하고
  가중치를 다시 맞춰야 함 (C의 3주차 문서에 원래 있던 검증 계획, 아직 미실행).
- **실제 apk로 end-to-end 검증 안 됨**: 이 저장소는 apktool/jadx/실제 apk 샘플이 없는
  환경에서 통합했음. `decompiler.py`/`calculate_risk`는 가짜 도구·가짜 데이터로 로직만
  검증했고, `code_scanner`/`string_extractor`/`sdk_detector`는 jadx 출력과 비슷하게 흉내낸
  가짜 디렉터리로 검증함. `cert_analyzer`는 API 존재만 확인했고 실제 서명된 apk로는
  아직 안 돌려봄. **팀원 중 apktool/jadx가 깔린 환경에서 실제 apk(anubis.apk 등)로
  `analyze_static()`을 한 번 돌려서 8개 필드가 다 정상적으로 채워지는지 확인 필요.**

## 개발 환경

- 팀 전체가 `docs/androidStudio_match.pdf` 가이드대로 에뮬레이터(`xray_api30`, Pixel 4 /
  API 30 / Google APIs / x86_64)를 통일해서 씀.
- 의존성은 `requirements.txt` 참고 (`pip install -r requirements.txt`). apktool/jadx는 별도
  설치 필요 (pip 패키지 아님) — 설치 후 PATH 등록까지 해야 `decompiler.py`가 찾을 수 있음.

## 관련 문서

- `CLAUDE.md` — 프로젝트 개요, 8주 로드맵
- `schemas/README.md` — 정적/동적/네트워크 세 모듈의 JSON 출력 스키마 초안 설명
- `docs/2주차_통합_발표자료.md` — 2주차 발표자료
