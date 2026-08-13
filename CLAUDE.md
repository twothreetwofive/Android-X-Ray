# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 개요
- 안드로이드 악성코드(Anubis) 분석 경험을 바탕으로 정적/동적/네트워크 분석을 자동화하는 플랫폼 개발
- 기간: 8주 (2주 단위 격주 발표)
- 진행 기간 : 2026.03 ~ 현재 4명의 팀원과 함께 모바일 보안 및 안드로이드 리버싱에 대한 호기심을 바탕으로, 실제 악성 앱의 동작 원리를 파악하고 그 위험성을 직관적으로 보여주는 도구를 기획하는 프로젝트입니다. 팀원 모두 모바일 분석이 처음이었기에 환경 구축부터 시작하였으며, 현재는 각자 분석한 내용을 공유하며 함께 학습하고 있습니다. 자동화 앱 개발 이전에, 안드로이드 악성앱에 대해 학습하기 위해 교육용 악성앱인 syssecapp.apk, 뱅킹 트로이목마 악성앱인 anubis.apk를 3월부터 6월까지 분석하며 공부하였고, jadx를 이용한 정적 분석과 AndroidStudio 에뮬레이터에서의 동적 분석 기초를 익히고 있으며, 분석 과정에서 파악한 권한 오남용 사례 등을 바탕으로 일반 사용자도 앱의 위험 활동을 쉽게 확인할 수 있도록 돕는 'X-ray' 앱 제작을 최종 목표로 삼고 있습니다. 단순히 개별 분석에 그치는 것이 아니라 팀원들과 분석 결과를 대조해보며 안드로이드 내부에서 앱의 권한과 데이터가 어떻게 관리되고 작동하는지 그 기본 원리를 기초부터 공부해보는 중입니다.
학기 8주동안 사전 공부를 진행하였으므로, 현재 방학 8주동안 X-ray 앱 개발 완성을 목표로 하고 있으며, 그 계획은 ecops_2325/docs/2주차_통합_발표자료.md 파일에 적혀있음.
팀 저장소는 https://github.com/twothreetwofive/Android-X-Ray 이며 연결 완료됨. feature 브랜치 -> PR -> main 병합 순서로 작업함.
- 팀원 4명 모두 사이버보안학과 재학생이며, 공부가 부족하여 전공 관련 수준은 훌륭하지 않음. 따라서 친절한 설명이 필요하고 과정을 정확히 알려줘야함. 다만 지나친 비유적 표현은 삼가할 것.

## 현재 상태 (2026-08-13 기준)

**8주 로드맵의 구현은 사실상 완료됐고, 지금은 실샘플로 검증·보정하는 단계입니다.**

| 구성 요소 | 상태 |
|---|---|
| 정적 분석 `src/static_analyzer/` | 완료 |
| 동적 분석 `src/dynamic_analyzer/` (Frida) | 완료 |
| 네트워크 분석 `src/network_analyzer/` | 완료 |
| 오케스트레이터 `src/main.py` | 완료 |
| 위험도 스코어링 `src/risk_aggregator.py` | 완료 |
| 웹 대시보드 `app.py` + `views/` | 완료 |
| 실샘플 검증 | 진행 중 (정상 2종 / 악성 1종 완료, 표본 확대 필요) |

- **테스트**: `python3 -m pytest -q` — 183개 통과. 새 코드를 넣으면 여기에 테스트도 추가할 것
- **의존성**: `requirements.txt`에 8개 명시(androguard, frida, streamlit, scapy, pytest 등).
  `apktool`/`jadx`/`adb`/`frida-server`는 pip 패키지가 아니라 별도 설치 + PATH 등록 필요
- **git**: GitHub 팀 저장소 운영 중 (`twothreetwofive/Android-X-Ray`, 기본 브랜치 `main`).
  작업은 feature 브랜치 → PR → main 병합 순서
- **실행 환경**: WSL에서 코드를 돌리고 Windows에서 에뮬레이터를 띄우는 구성.
  절차와 함정은 `docs/8주차_로컬테스트_가이드.md`에 전부 정리돼 있음

### 새 코드를 쓸 때 지킬 것

기존 컨벤션이 이미 자리잡았으므로 그것을 따를 것:

1. **"값이 없음"을 0으로 채우지 않는다.** 위험도 0은 "안전"으로 읽히기 때문.
   점수를 못 내면 `None`, 관측이 없으면 점수에서 제외 후 가중치 재정규화
   (`risk_aggregator`, `views/static_data.py`, `views/risk_view.py` 모두 이 원칙을 따름)
2. **분석 상태(Status)와 보안 판정(Verdict)을 섞지 않는다.** 전자는 "파이프라인이
   돌았는가", 후자는 "얼마나 위험한가". 라벨도 겹치지 않게 씀
3. **부분 리포트 허용.** 한 모듈이 실패해도 예외를 위로 던지지 말고 리포트는 항상 생성
4. **판단 로직은 streamlit 없는 파일에 둔다.** 화면 코드에 판단을 넣으면 테스트가 안 됨
   (`views/static_data.py`가 그 예)
5. 주석에는 "무엇을"이 아니라 **"왜 그렇게 했는지"**와 근거가 된 실측을 남길 것

## 개발 계획 및 일정 (로드맵)
- 1~2주차: 아키텍처 설계 및 정적 분석 자동화 스크립트(JADX CLI 연동) 구현 — 완료
- 3~4주차: 동적 분석 모듈(Frida) 개발 및 Python 연동 — 완료
- 5~6주차: 네트워크 패킷 파싱 로직 및 전체 파이프라인 통합 — 완료
- 7~8주차: Streamlit 기반 웹 대시보드 UI 구현 및 검증 — 완료
  (8주차에 실제 APK로 세 모듈이 모두 성공하는 것을 처음 확인. `docs/8주차보고서_B.md`)

로드맵에 있던 구성 요소(정적 분석 래퍼, Frida 동적 계측, 네트워크 패킷 파싱, 통합 파이프라인, Streamlit UI)는 모두 구현되어 `src/`와 저장소 루트에 있습니다. 남은 일은 새 기능 추가보다 **실샘플로 점수 기준을 검증하고 보정하는 것**입니다 — 현재 미해결 과제는 `docs/8주차보고서_B.md` 5절 참고.

## 디렉터리 구조

```
app.py                  # Streamlit 진입점
preflight.py            # 분석 전 에뮬레이터 준비 점검 + 앱 자동 설치
pipeline_bridge.py      # 대시보드 <-> 오케스트레이터 연결
common.py               # 뷰 공용 상수 (상태 라벨, 판정 색/구간, 고지 문구)
views/                  # 대시보드 화면 (verdict_header / static / dynamic / network / risk)
src/
  main.py               # 오케스트레이터 (CLI 진입점)
  risk_aggregator.py    # 세 모듈 결과 -> 종합 위험도 + 보안 판정
  static_analyzer/      # 정적 분석
  dynamic_analyzer/     # 동적 분석 (Frida)
  network_analyzer/     # 네트워크 분석
scripts/                # 실행 환경 준비 (wsl_env / connect_emulator / prepare_emulator / snapshot / check_apk_compat)
tests/                  # pytest 183개
docs/                   # 주차별 보고서·가이드
output/                 # 분석 결과 (report_*.json만 추적, pcap 등 실행 산출물은 제외)
work/                   # 디컴파일 작업 폴더 (APK별 하위 폴더, 버전관리 제외)
```

**분석 샘플(APK)은 저장소에 절대 두지 않습니다.** `.gitignore`에 `*.apk` `*.apk_`
`*.dex` `*.zip` `samples/`가 등록돼 있고, 샘플은 `~/samples/`에만 둡니다.
악성 샘플 실행 전에는 반드시 에뮬레이터 스냅샷을 저장합니다
(`bash scripts/snapshot.sh save before_run`).

## 관련 문서

- `README.md` — 실행 방법, 결과 읽는 법
- `docs/8주차_로컬테스트_가이드.md` — 환경 구축부터 대시보드까지 단계별 명령 + 트러블슈팅
- `docs/8주차보고서_B.md` — 8주차 작업 내역, 실측 결과, 미해결 과제
