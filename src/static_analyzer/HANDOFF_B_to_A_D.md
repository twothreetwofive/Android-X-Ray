# 인수인계 — B(왕은서) → A(유예원), D(백소정)

**날짜**: 2026-08-02 작성 / **2026-08-03 갱신 (Day 4)**
**브랜치**: `feature/static-adapter`
**상세 근거**: `docs/정적분석/6주차_B_필드매핑.md`

정적 분석 출력을 통합 스키마에 맞추는 어댑터를 만들었습니다. 그 과정에서 **혼자 결정하면
안 되는 항목**이 A에 4건, D에 4건 나왔습니다. 아래가 그 목록입니다.

---

# [2026-08-03 갱신] A/D 답변 반영 결과

A의 6주차 스펙과 D의 `fix/static-permission-weights`를 받아서 **8건 중 7건이
해소**됐습니다. 아래는 그 결과와 **새로 생긴 확인 요청**입니다.

## 해소된 항목

| 대상 | 항목 | 결과 |
|---|---|---|
| A (1) | `errors` 통합 스펙 반영 | `main.py`가 `result.get("errors")`로 `module_status` 판정 — 반영됨 |
| A (2) | `manifest` 실패 정책 | 원본 정책(`None` + `errors` 기록) 존중으로 확정 |
| A (3) | `min_sdk`/`target_sdk`의 `0` | 원본 값 그대로 통과, 구분 표시는 7~8주차 대시보드 몫 |
| A (4) | 스키마에 자리 없는 4필드 | 8필드 원본을 그대로 통과시켜 버려지는 필드 없음 |
| D (1) | `PERMISSION_WEIGHTS` 5개뿐 | 20개로 확장 + 8점 미만 권한이 합산에서 빠지던 버그 수정 |
| D (2) | 점수 계산 근거 반환 | `calculate_risk_with_breakdown()` 신설 — **B가 배선 완료(아래 참고)** |
| D (3) | 종합 점수에 쓸 필드 | `is_self_signed` 반영(가중치 10), `third_party_sdks`는 미사용 확정 |
| D (4) | 정적↔네트워크 교차 검증 | D가 `src/cross_reference.py`에 구현 |

## B가 이번에 한 일 — breakdown 배선

D가 `calculate_risk_with_breakdown()`을 **"어댑터에서 이 함수로 갈아타면 됨"**으로
만들었는데, A가 어댑터를 안 쓰기로 하면서 **이 함수를 부르는 코드가 아무 데도 없는
상태**였습니다 (`analyzer.py`는 여전히 `calculate_risk()`만 호출, `main.py`의 최상위
`risk_score.breakdown`도 `None`). 그대로 두면 D가 만든 근거가 리포트에 안 실립니다.

그래서 **`analyzer.py`가 직접 부르도록 배선**했습니다. 어댑터를 거치지 않는 A의
8필드 원본 경로에서도 근거가 나옵니다.

```python
result = analyze_static(apk_path, work_dir)
result["risk_score"]      # 0.0~1.0 float — 기존 계약 그대로
result["risk_breakdown"]  # {"total": .., "raw": .., "breakdown": [{factor, weight}, ..]}
```

## 새로 확인 부탁드릴 것 (3건)

### (A-5) 8필드 → 9필드가 됐습니다

`risk_breakdown`을 **형제 필드로 추가**했습니다. `risk_score`의 타입을 객체로 바꾸면
`schema.py`의 팀 계약과 `main.py`의 통과 정책이 깨지므로 float을 유지하고 근거만
따로 뺐습니다. `main.py`는 `data=result`로 통째로 넘기니 코드 수정 없이 그대로
흘러갑니다만, **"8필드 그대로"라고 쓰신 스펙과는 달라져서 확인이 필요합니다.**

계산 실패 시 `risk_score`와 `risk_breakdown`이 **둘 다 `None`**이 됩니다. "점수는
있는데 근거가 없는" 어긋난 상태는 생기지 않습니다.

### (A/D-6) breakdown 항목의 키 이름이 스키마와 다릅니다

`static_report.schema.json`은 항목을 `{permission, weight}`로 적어뒀지만, D의
breakdown에는 권한이 아닌 항목(`"exported_components×2 (3개)"`,
`"obfuscation_detected"`, `"certificate.is_self_signed"`)도 섞여 있어서 `permission`
이라는 이름이 맞지 않습니다. **D가 쓰는 `{factor, weight}`를 그대로 내보냅니다.**
스키마의 `items`에는 `required`도 `additionalProperties` 제한도 없어서 검증은
통과합니다. 스키마 문구 자체를 고칠지는 정해 주세요.

### (D-7) `cuckoo.apk`로는 권한 확장을 검증할 수 없습니다

"B가 `cuckoo.apk`로 다시 돌려봐 달라"고 하신 것 중 **절반만 됐습니다.**

| 확인 요청 | 결과 |
|---|---|
| `is_self_signed` 가산점이 실제 점수에 영향 주는지 | **확인됨** — self-signed `True`, total `0.060` → `0.160` (+0.10) |
| breakdown 합계가 raw와 일치하는지 | **확인됨** — 합계 16 == raw 16 |
| `CAMERA` 등이 medium/high로 잡히는지 | **검증 불가** |

`cuckoo.apk`의 권한이 `INTERNET`과 자체 정의 권한 **2개뿐**이라 확장된 표를 실제
APK로 확인할 방법이 없습니다. 합성 데이터로는 정상 동작을 확인했고
(`CAMERA` 7점 medium / `READ_SMS` 9점 high / 8점 미만 권한도 합산에 잡힘)
회귀 테스트로 고정해 뒀습니다(`tests/test_static_adapter.py`,
`tests/test_analyzer.py`). **권한이 많은 실제 샘플이 있어야 진짜 검증이 됩니다** —
D가 지적하신 `NORMALIZATION_CAP` 재조정도 같은 샘플이 있어야 가능합니다.

이 PC에서 찾을 수 있는 APK는 `cuckoo.apk`와 에뮬레이터 스킨 오버레이 APK뿐입니다.

---

> **아래는 2026-08-02 원본입니다.** 위 갱신 표에 해소 여부가 정리돼 있으니, 질의
> 8건의 현재 상태는 위쪽을 보세요. 아래 본문은 각 항목을 왜 물었는지에 대한 근거로
> 남겨둡니다.

## 1. A(유예원, 오케스트레이터)가 쓸 수 있는 것

`main.py`에서 정적 분석 결과를 통합 포맷으로 바꾸려면 이 함수 하나만 부르면 됩니다.

```python
from static_analyzer import analyze_static, to_static_report

result = analyze_static(apk_path, work_dir)   # 기존 8개 필드 dict
report = to_static_report(result)             # static_report.json 형태
```

- `to_static_report()`는 **순수 dict 변환 함수**입니다. 파일도 안 읽고 외부 도구도 안 씁니다.
  그래서 실패하거나 느려질 일이 없고, 타임아웃 처리도 필요 없습니다.
- 출력은 `schemas/static_report.schema.json`을 만족합니다 (`jsonschema`로 테스트에서 검증 중).
- 옵션: `to_static_report(result, include_extra=False)` — 통합 스키마에 없는 필드
  (`certificate` / `code_analysis` / `strings` / `third_party_sdks`)를 빼고 순수 스키마
  필드만 받고 싶을 때 씁니다.

---

## 2. A에게 드리는 질의 (4건)

### (1) [최우선] `errors`를 통합 스펙에 반드시 넣어 주세요

**`analyze_static()`은 하위 단계가 실패해도 예외를 던지지 않습니다.** 6개 단계 중 무엇이
실패하든 해당 값을 `None`으로 둔 채 **정상 반환**하고, 실패 사실은 `result["errors"]`
리스트에만 문자열로 남깁니다 (`analyzer.py`의 `_run_stage`).

즉 **`try/except`로는 정적 분석의 부분 실패를 감지할 수 없습니다.** `errors`가 비어 있는지
확인하는 것이 유일한 방법입니다. 이걸 모르면 코드 스캔이 전부 실패한 결과도
"정적 분석 성공"으로 처리됩니다.

어댑터 출력의 `errors`는 **원본 `errors` + 어댑터가 발견한 문제**입니다. 어댑터가 값을
임의로 채워 넣은 자리(빈 `apk_name`, 대체한 `analyzed_at`, `total=0.0` 등)에는 반드시
흔적이 남습니다.

> 특히 **`risk_score` 계산이 실패하면 `total`이 `0.0`이 됩니다.** 스키마에서 `total`이
> required + number라 `null`을 넣을 수 없어서 어쩔 수 없습니다. 그대로 두면 "위험도 0 =
> 안전한 앱"으로 읽히므로, 대시보드에 표시하기 전에 `errors`를 꼭 확인해 주세요.

### (2) `manifest` 파싱 실패 시 정책 확인

현재 어댑터는 **빈 배열로 채우고 계속 진행**합니다 (`permissions: []`, `components: []`).
정적 분석 모듈 전체가 "부분 실패해도 계속 진행" 정책이라 어댑터만 예외를 던지면
일관성이 깨진다고 판단했습니다. 통합 스펙에서 다른 정책(예: 즉시 중단)을 정하시면
바꾸겠습니다. 코드에 바꿀 지점을 주석으로 표시해 뒀습니다.

### (3) `min_sdk` / `target_sdk`의 `0` 처리

`apk_extractor._safe_int()`가 파싱 실패 시 `0`을 넣습니다. **`0`은 "SDK 0"이 아니라
"파싱 실패"라는 뜻**이라 대시보드에 그대로 보여주면 오해를 줍니다. 구분해서 표시할지
결정해 주세요. (참고: 값이 아예 없으면 어댑터가 키를 뺍니다 — 스키마가 `null`을
허용하지 않기 때문입니다.)

### (4) 통합 스키마에 없는 4개 필드의 자리

`certificate`, `code_analysis`, `strings`, `third_party_sdks`는 1주차 스키마 작성 시점에
고려되지 않아 `static_report.schema.json`에 자리가 없습니다. 버리기엔 아까운 정보라
**어댑터가 최상위에 그대로 실어 보냅니다**(JSON Schema draft-07은 추가 필드를 막지 않아
검증은 통과합니다). 통합 리포트에서 이 필드들을 어떻게 다룰지 정해 주세요.

### (참고) androguard 로그

`androguard`가 loguru로 DEBUG 로그를 대량 출력합니다. 파이프라인 통합 시 다른 로그가
전부 묻히므로 로그 레벨 조정을 고려해 주세요.

---

## 3. D(백소정, 종합 위험도 점수)에게 드리는 질의 (4건)

### (1) [중요] `PERMISSION_WEIGHTS`에 권한이 5개뿐입니다

`manifest_parser.PERMISSION_WEIGHTS`에 등록된 권한이 5개라, `CAMERA`, `RECORD_AUDIO`,
`READ_CONTACTS`, `ACCESS_FINE_LOCATION` 같은 실제 위험 권한이 전부 가중치 0으로
떨어져 `risk_level`이 `low`로 나옵니다. 단순 `INTERNET`과 같은 등급입니다.

**이 표는 `calculate_risk()`가 그대로 합산에 쓰기 때문에, 제가 임의로 늘리면 D의 점수가
통째로 바뀝니다.** 그래서 손대지 않았습니다. 6주차 종합 점수 설계와 함께 정해 주세요.

> 실제로 `cuckoo.apk`로 확인해 보니 권한이 2개(`INTERNET` 등)뿐이고
> `dangerous_permissions`는 **비어 있었습니다.**

참고로 **설명 텍스트는 제가 따로 만들어 뒀습니다** — `manifest_parser.ABUSE_EXAMPLES`에
권한 16개의 악용 예시가 있습니다. 이건 점수 계산에 안 쓰이므로 자유롭게 추가하셔도
D의 점수에 영향이 없습니다. 반대로 `PERMISSION_WEIGHTS`는 그렇지 않습니다.

| | `PERMISSION_WEIGHTS` | `ABUSE_EXAMPLES` |
|---|---|---|
| 쓰임 | 점수 **계산에 직접 들어감** | 사용자에게 보여줄 **설명** |
| 항목 추가 시 | 점수가 바뀜 | 점수 영향 없음 |
| 담당 | **D** | B |

### (2) `calculate_risk()`가 점수 계산 근거를 반환해 주세요

통합 스키마의 `risk_score.breakdown`(권한명 - 가중치 목록)을 채우려면 근거가 필요한데,
현재 `calculate_risk()`는 합산만 하고 근거를 남기지 않습니다.

어댑터에서 권한 항목만 재현할 수는 있지만, 실제 raw 점수에는 `exported_components × 2`,
`suspicious_api_calls × 3`, 난독화 +15, 리플렉션 +10, 동적 로딩 +15,
`suspicious_strings × 2`가 함께 들어갑니다. **권한만 재현하면 breakdown 합계가 total과
맞지 않아** 오히려 혼란스럽습니다. 그래서 지금은 `breakdown`을 생략했습니다.
근거를 반환해 주시면 바로 연결하겠습니다.

### (3) 종합 점수에 정적 분석의 어떤 필드를 쓰실 건가요?

아래 필드들을 쓰실 계획이면 어댑터에서 버리지 않고 계속 통과시키겠습니다
(현재는 전부 통과시키는 중):

- `code_analysis` — 난독화 / 리플렉션 / 동적 코드 로딩 / 의심 API 호출
- `certificate.is_self_signed`
- `strings.suspicious_strings`
- `third_party_sdks`

### (4) 정적 ↔ 네트워크 교차 검증 제안

`strings.urls` / `strings.ip_addresses`(코드에 하드코딩된 주소)를 네트워크 모듈의
`suspicious.domains` / `suspicious.ips`(실제 통신한 주소)와 **대조**해 보면 어떨까요.

"코드에 박혀 있던 주소로 실제 통신까지 했다"는 건 단일 모듈로는 못 내는 강한 근거이고,
발표 자료에서도 정적·네트워크를 잇는 볼거리가 될 것 같습니다. D가 두 모듈을 다 보시니
가장 적합할 것 같아 제안드립니다.

---

## 4. C(김은아, 동적 분석 출력 정리)에게

동적 모듈도 **`src/dynamic_analyzer/schema.py`와 `schemas/dynamic_report.schema.json`을
먼저 대조**해 보시길 권합니다. 정적 쪽은 8개 필드 중 **4개가 통합 스키마에 자리가 없었고,
`intent_filters`처럼 파싱 단계에서 아예 버려진 데이터도 있었습니다.** 어댑터를 다 짜고
나서 발견하면 원천 코드를 다시 고쳐야 합니다.

`jsonschema`를 `requirements.txt`에 추가해 뒀으니 `Draft7Validator`로 검증하실 수 있습니다.
테스트 세팅(`pytest.ini`)도 이미 있어서 `tests/`에 파일만 추가하면 바로 돌아갑니다.

---

## 5. 제가 바꾼 파일 (충돌 방지용)

**기존 필드는 하나도 바꾸거나 지우지 않았습니다. 전부 추가만 했습니다.**

| 파일 | 변경 |
|---|---|
| `static_adapter.py` | 신규 |
| `manifest_parser.py` | `_get_intent_filters()` 추가, `components` 필드 추가, `ABUSE_EXAMPLES` 추가 |
| `apk_extractor.py` | `meta.apk_name` 추가 |
| `analyzer.py` | `meta.analyzed_at` 추가 |
| `schema.py` | `Component` TypedDict 신설, `Meta`/`ManifestInfo`에 필드 추가 |
| `__init__.py` | `to_static_report`, `permission_risk_level` export |
| `pytest.ini`, `tests/` | 신규 (저장소에 테스트 인프라가 없어 함께 세팅) |
| `requirements.txt` | `pytest`, `jsonschema`, `lxml` 추가 |

**D 주의**: `risk_scorer.py`는 **건드리지 않았습니다.** `calculate_risk()`가 쓰는
`dangerous_permissions`와 `exported_components`의 내용·순서가 이전과 동일하다는 것을
회귀 테스트로 고정해 뒀습니다 (`tests/test_manifest_parser.py`). 점수가 바뀔 일은 없습니다.

---

## 6. [2026-08-03 추가] 병합 이후 바뀐 파일

`fix/static-permission-weights`를 `feature/static-adapter`에 병합했습니다.

**충돌 1건** — `manifest_parser.py`에서 `ABUSE_EXAMPLES`(B)와
`DANGEROUS_PERMISSION_THRESHOLD`(D)가 `PERMISSION_WEIGHTS` 바로 뒤 같은 위치에
추가돼 겹쳤습니다. 내용이 안 겹쳐서 **둘 다 살렸습니다.** D가 미리 예고해 주신
그대로였습니다.

| 파일 | 변경 |
|---|---|
| `analyzer.py` | `calculate_risk()` → `calculate_risk_with_breakdown()`, `risk_breakdown` 필드 추가 |
| `schema.py` | `RiskBreakdown` / `BreakdownItem` TypedDict 추가, `risk_breakdown` 필드 |
| `static_adapter.py` | `_build_breakdown()` 추가 — 근거를 직접 계산하지 않고 옮기기만 함 |
| `tests/test_analyzer.py` | **신규 8개** |
| `tests/test_static_adapter.py` | breakdown 케이스 + `risk_level` 회귀 6건 추가 |
| `risk_scorer.py`, `manifest_parser.py`(가중치 부분) | **D 작업물 그대로** — B는 안 건드림 |

`pytest` **44개 → 67개 전부 통과**. 통과만 보면 의미가 없어서 코드를 일부러 되돌려
테스트가 실제로 잡는지 확인했습니다 (4건 전부 잡힘):

| 되돌린 것 | 잡은 테스트 |
|---|---|
| 어댑터의 breakdown 연결 제거 | 4개 |
| breakdown 항목 1개 누락시킴 | 4개 |
| `analyzer`가 `risk_breakdown`을 안 채우게 함 | 5개 (`test_analyzer.py`) |
| 8점 미만 권한 미합산 버그 재현 | 1개 (`test_analyzer.py`) |

세 번째 항목이 `tests/test_analyzer.py`를 새로 만든 이유입니다. 어댑터 테스트는 전부
fixture dict 기반이라 **원천(`analyze_static`)에서 필드가 빠지는 걸 못 잡습니다.**
6주차 Day 1에 `intent_filters`가 파싱 단계에서 버려지고 있던 걸 뒤늦게 발견한 것과
같은 유형의 구멍이라, 하위 단계를 monkeypatch해서 jadx/apktool 없이 조립 로직만
검증하도록 했습니다.
