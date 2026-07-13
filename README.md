# X-ray — 안드로이드 악성코드 정적/동적/네트워크 분석 자동화

이삼이오_방캅스 팀. 안드로이드 악성코드(Anubis) 분석 경험을 바탕으로, apk를 넣으면
정적/동적/네트워크 분석 결과를 자동으로 뽑아주는 도구를 만드는 프로젝트.
전체 배경과 8주 로드맵은 `CLAUDE.md` 참고.

## 지금 상태 (3주차 기준)

3주차 목표는 정적 분석 모듈(`src/static_analyzer/`) 구현이고, 역할은 4명이 나눠서 함:

| 역할 | 담당 | 내용 | 상태 |
|---|---|---|---|
| A | 백소정 | 패키지 구조 설계, `analyze_static()` 인터페이스, 출력 스키마 | 완료 |
| B | 왕은서 | `apktool`/`jadx` 호출 wrapper (타임아웃, 예외 처리) | 완료 |
| C | 김은아 | `AndroidManifest.xml` 파싱 (androguard), 위험 권한/컴포넌트 추출 | 완료 |
| D | - | 위험도 점수 계산, `static_report.json` 출력 | 미완료 |

D가 아직 안 끝나서 `certificate`/`code_analysis`/`strings`/`third_party_sdks`/`risk_score`는
`analyzer.py`에서 `None`으로 비워두고 `errors`에 사유를 남기는 식으로 처리해뒀음
(전체를 죽이지 않고 부분 결과만 반환 — A의 설계 원칙을 따름).

## static_analyzer/ 모듈별 역할

```
src/static_analyzer/
├── __init__.py         # 패키지 공개 API
├── analyzer.py          # analyze_static(apk_path) -> dict, 오케스트레이터가 이것만 import
├── apk_extractor.py     # apktool/jadx 실행 + apk 메타데이터(해시, 패키지명, sdk 버전) 추출
├── decompiler.py         # apktool d / jadx CLI를 subprocess로 감싸는 저수준 wrapper
├── manifest_parser.py   # AndroidManifest.xml 파싱 (androguard) — 권한/컴포넌트/exported 체크
├── schema.py            # analyze_static() 출력 타입 정의 (TypedDict) — 팀 공유 계약
└── exceptions.py        # StaticAnalysisError 등 커스텀 예외
```

각 파일이 왜 나뉘어 있는지:

- **decompiler.py vs apk_extractor.py** — `decompiler.py`는 "apktool/jadx를 어떻게 실행하고
  실패를 어떻게 처리할지"만 담당 (B 역할). `apk_extractor.py`는 그 위에서 "apk 하나를 분석
  가능한 형태로 준비"하는 조립 담당 — 디컴파일 실행 + 해시/버전 같은 메타데이터 추출을
  묶어서 `analyzer.py`가 쓰기 좋은 dict로 반환한다.
- **manifest_parser.py는 decompiler.py 결과물을 안 씀** — androguard가 apk 파일 자체에서
  바로 Manifest를 읽기 때문에, apktool로 압축을 풀 필요가 없음. (C가 3주차 과제에서 직접
  확인한 내용)
- **schema.py** — 실제 코드가 아니라 "출력 형식 계약"만 있는 파일. 새 필드를 추가/변경하려면
  여기부터 고치고 팀에 공유해야 함 (임의로 바꾸면 다른 사람 코드가 깨짐).
- **exceptions.py** — `StaticAnalysisError`가 최상위 예외. `decompiler.py`의
  `DecompileError`/`DecompileTimeoutError`는 전부 이 예외의 하위 클래스라서, 오케스트레이터는
  `except StaticAnalysisError`로 apktool/jadx 실패와 미래에 추가될 다른 치명적 실패를 한 번에
  잡을 수 있음.

## ⚠️ 아직 안 맞춰진 것 (팀 논의 필요)

- **`schemas/*.json` vs `src/static_analyzer/schema.py`**: `schemas/static_report.schema.json`은
  1주차에 만든 초안이고 필드가 `meta`/`permissions`/`components`/`risk_score` 4개뿐임. 반면
  `schema.py`(A가 3주차에 실제로 확정한 버전)는 `certificate`/`code_analysis`/`strings`/
  `third_party_sdks`/`errors`까지 포함해서 구조가 다름. 지금은 `schema.py`가 최신이니 이걸
  기준으로 삼고 있는데, `schemas/static_report.schema.json`도 여기 맞춰 갱신할지 팀 논의 필요
  (동적/네트워크 모듈과의 파이프라인 통합은 6주차라 아직 급하지 않음).
- **D의 위험도 점수 스케일**: C가 만든 `PERMISSION_WEIGHTS`는 1~10 스케일인데,
  `schema.py`의 `risk_score`는 0.0~1.0 float임. D가 합류하면 이 변환 방식부터 정해야 함.
- **실제 apk로 end-to-end 검증 안 됨**: 이 저장소는 apktool/jadx가 없는 환경에서 통합했음.
  실제 apk 샘플로 `analyze_static()`을 한 번 돌려서 확인하는 작업이 남아있음.

## 개발 환경

- 팀 전체가 `docs/androidStudio_match.pdf` 가이드대로 에뮬레이터(`xray_api30`, Pixel 4 /
  API 30 / Google APIs / x86_64)를 통일해서 씀.
- 의존성은 `requirements.txt` 참고 (`pip install -r requirements.txt`). apktool/jadx는 별도
  설치 필요 (pip 패키지 아님) — 설치 후 PATH 등록까지 해야 `decompiler.py`가 찾을 수 있음.

## 관련 문서

- `CLAUDE.md` — 프로젝트 개요, 8주 로드맵
- `schemas/README.md` — 정적/동적/네트워크 세 모듈의 JSON 출력 스키마 초안 설명
- `docs/2주차_통합_발표자료.md` — 2주차 발표자료
