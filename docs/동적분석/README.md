# docs/동적분석/ — 동적 분석 모듈 4주차 자료

동적 분석(Frida) 모듈 착수 시점(2026-07-15)에 정한 역할 분배와, 그 역할대로
각자 진행한 4주차 과제 결과물 모음. 실제 코드(`src/dynamic_analyzer/`)는
`feature/dynamic-agent` 브랜치에 있고, 여기 있는 파일들은 그 코드가 나온
과정을 설명하는 보고서다.

## 파일 목록

| 파일 | 담당 | 내용 |
|---|---|---|
| `동적 분석 모듈 개발 역할 분배.txt` | 전체 | A/B/C/D 역할 분배 원안, 5일 스케줄 (README.md `## 2. 동적 분석 모듈`에 정리본 반영됨) |
| `유예원_4주차_과제A.pdf` | A (예원) | `frida_controller.py` — frida-server 연결, spawn/attach/resume, 재시도, 배치 실행 |
| `백소정_4주차_과제B.pdf` | B (소정) | `hooks.js`/`hooks.bundle.js` — string_builder/base64/cipher 후킹, 노이즈 사전 필터, frida-compile 빌드 이슈 |
| `김은아_4주차_과제C.pdf` | C (은아) | `message_parser.py` — 메시지 수신, 중복 제거/평문 판별 필터링, `dynamic_report.json` 1차 출력. Python API에서 Java 브릿지가 안 잡히던 인프라 버그(esbuild interop) 원인 규명 및 해결 과정 포함 |
| `은서_4주차_과제D.md` | D (은서, 본인) | `adb_runner.py`/`scenarios.py`/`scenario_runner.py` — 실행 시나리오 자동화, 재현성/크래시 대응 |

## 각 팀원 산출물이 실제 코드로 어디에 반영됐는지

- A → `src/dynamic_analyzer/frida_controller.py`
- B → `src/dynamic_analyzer/hooks.js`, `hooks.bundle.js`
- C → `src/dynamic_analyzer/message_parser.py`, `schema.py`
- D → `src/dynamic_analyzer/adb_runner.py`, `scenarios.py`, `scenario_runner.py`

전부 `feature/dynamic-agent` 브랜치에 있으며, main에는 아직 병합 전이다
(정적 분석 모듈처럼 검증 끝나면 병합 예정).

## 팀 논의 필요 (B/C가 보고서에 남긴 미결정 사항)

- **caller(호출자) 정보 추가 여부**: 후킹된 API를 호출한 게 앱의 어느
  클래스인지 스택트레이스로 추적해서 `extra`에 넣을지. 호출마다 오버헤드가
  붙어서 성능 트레이드오프 문제 — `schema.py`(C 담당) 계약이 바뀌는 거라
  팀 합의 필요.
- **`custom_xor` 후킹**: 표준 API가 아니라 대상 앱이 자체적으로 짠 로직이라
  실제 악성 샘플(anubis.apk) 디컴파일 결과가 있어야 클래스/메서드를 특정할
  수 있음. 현재 저장소엔 실제 악성 샘플이 없어서 보류 중.
