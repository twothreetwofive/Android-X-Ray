"""종합 위험도 스코어링. (원래 D 담당, D 미착수라 대신 작성)

1차 버전 — 권한 가중치 합산 + 코드/문자열/인증서 스캔 결과를 더해서 0.0~1.0으로
정규화. 정상 앱 2~3개 vs 공개 악성 샘플 2~3개로 실제 돌려보고 점수 차이가 나는지
검증한 뒤 NORMALIZATION_CAP과 각 항목 가중치를 다시 맞춰야 하는 휴리스틱이다.

B의 static_report.schema.json risk_score.breakdown 요청 관련:
- third_party_sdks는 점수에 안 쓴다. 광고/분석 SDK를 쓰는 것 자체는 대부분의 정상
  앱에도 흔해서 그 존재만으로는 위험 신호가 아니다 - 어댑터에서 지금처럼 그대로
  통과(passthrough)시키면 된다.
- certificate.is_self_signed는 점수에 새로 반영한다 (아래 SELF_SIGNED_CERT_WEIGHT).
  정식 CA 서명 없이 자가서명된 앱은 Play Store 배포 앱 대비 드물고, 팀이 분석 중인
  Anubis 계열 샘플도 자가서명이 흔한 패턴이라 약한 신호로라도 넣을 가치가 있다.
"""

from __future__ import annotations

from typing import Any

from .manifest_parser import PERMISSION_WEIGHTS

# raw 점수를 이 값으로 나눠서 0.0~1.0으로 clamp한다. 임의로 잡은 초기값.
NORMALIZATION_CAP = 100.0

# ── 8주차 재조정 ── (실샘플 검증에서 드러난 오탐 교정)
#
# 계기: 에뮬레이터 내장 시계 앱(com.google.android.deskclock)이 87점 "고위험"으로
# 나왔다. 구글 서명 정품 앱이므로 명백한 오탐이고, 원인은 네 가지였다.
#
# 1) suspicious_api_calls를 **건수 × 3**으로만 셌다. code_scanner는 각 항목에
#    risk("high"/"medium"/"low")를 이미 매겨 두는데 그걸 무시해서, Gson 매퍼의
#    Base64.decode(low)가 AccessibilityService(high)와 같은 3점이었다.
#    게다가 같은 API가 여러 파일에서 발견되면 그만큼 배로 늘어났다.
#    -> risk별 가중치 + **서로 다른 API 종류**만 세고 상한을 둔다.
# 2) 매칭이 **번들된 라이브러리**까지 훑는다. 시계 앱의 AccessibilityService는
#    android/support/design/snackbar/… 즉 지원 라이브러리의 접근성 처리였다.
#    소스 경로 기반 완전 제외는 오탐/미탐이 갈리는 판단이라 여기서 하지 않고,
#    위 1)의 종류 기준 + 상한으로 영향만 줄인다.
# 3) certificate.is_self_signed에 10점을 줬다. 그러나 **안드로이드 앱은 거의 전부
#    자체 서명**이다(구글 플레이 배포본도 개발자 키로 서명). 변별력이 거의 없는데
#    10점은 과했다 -> 2점으로 낮춘다. 자체 서명 자체보다 "디버그 키로 서명"이
#    의미 있는 신호인데, 그 판별은 cert_analyzer가 아직 제공하지 않는다(TODO).
# 4) 하드코딩 IP 문자열 오탐은 string_extractor.IP_RE를 옥텟 검증으로 고쳤다.
API_RISK_WEIGHTS = {"high": 6, "medium": 2, "low": 0.5}
API_RISK_DEFAULT = 1
SUSPICIOUS_API_CAP = 30            # 의심 API 항목 전체가 줄 수 있는 최대 점수

EXPORTED_COMPONENT_WEIGHT = 2
EXPORTED_COMPONENT_CAP = 12        # 컴포넌트가 많은 정상 앱(시계 11개)이 22점을 받던 것 방지

SUSPICIOUS_STRING_WEIGHT = 2
SUSPICIOUS_STRING_CAP = 10

SELF_SIGNED_CERT_WEIGHT = 2

# 패킹된 페이로드 — APK의 대부분이 정체 불명의 암호화 덩어리라면 코드 분석으로는
# 볼 수 있는 게 없다는 뜻이다. 그 자체가 강한 신호라 단일 항목 중 가장 큰 가중치를 준다.
PACKED_ASSET_WEIGHT = 25


def _score_breakdown(
    manifest_data: dict[str, Any] | None,
    code_data: dict[str, Any] | None,
    strings_data: dict[str, Any] | None,
    cert_data: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """항목별 raw 기여도 목록. 이 weight들의 합이 곧 raw 총점이다.

    calculate_risk()와 calculate_risk_with_breakdown()이 이 함수 하나를 공유해서
    "점수 계산에 실제로 쓰인 것"과 "breakdown에 보여주는 것"이 항상 일치하게 한다
    (B가 어댑터에서 권한만 재현했을 때 breakdown 합계가 total과 안 맞던 문제 해결).
    각 항목은 {"factor": str, "weight": number} 형태 - 권한 항목은 factor에 권한
    전체 이름(예: "android.permission.CAMERA")을 그대로 넣어서, 필요하면 어댑터가
    PERMISSION_WEIGHTS/ABUSE_EXAMPLES와 다시 대조할 수 있게 했다.
    """
    breakdown: list[dict[str, Any]] = []

    if manifest_data:
        for p in manifest_data.get("permissions", []):
            weight = PERMISSION_WEIGHTS.get(p, 0)
            if weight:
                breakdown.append({"factor": p, "weight": weight})

        exported_count = len(manifest_data.get("exported_components", []))
        if exported_count:
            weight = min(exported_count * EXPORTED_COMPONENT_WEIGHT, EXPORTED_COMPONENT_CAP)
            capped = " 상한적용" if exported_count * EXPORTED_COMPONENT_WEIGHT > EXPORTED_COMPONENT_CAP else ""
            breakdown.append(
                {"factor": f"exported_components ({exported_count}개{capped})", "weight": weight}
            )

    if code_data:
        api_calls = code_data.get("suspicious_api_calls", []) or []
        if api_calls:
            # 같은 API가 여러 파일에서 발견돼도 한 종류로 센다. "몇 번 나왔나"보다
            # "어떤 종류가 나왔나"가 신호이고, 번들 라이브러리 때문에 건수가 쉽게 부푼다.
            by_api: dict[str, str] = {}
            for call in api_calls:
                if not isinstance(call, dict):
                    continue
                api = call.get("api", "unknown")
                risk = (call.get("risk") or "").lower()
                # 같은 API가 여러 risk로 오면 가장 높은 것을 남긴다.
                prev = by_api.get(api)
                if prev is None or API_RISK_WEIGHTS.get(risk, API_RISK_DEFAULT) > API_RISK_WEIGHTS.get(prev, API_RISK_DEFAULT):
                    by_api[api] = risk

            raw_api = sum(API_RISK_WEIGHTS.get(r, API_RISK_DEFAULT) for r in by_api.values())
            weight = min(raw_api, SUSPICIOUS_API_CAP)
            if weight:
                n_high = sum(1 for r in by_api.values() if r == "high")
                label = f"suspicious_api_calls ({len(by_api)}종"
                if n_high:
                    label += f", 고위험 {n_high}종"
                label += f" / 발견 {len(api_calls)}건)"
                breakdown.append({"factor": label, "weight": weight})
        if code_data.get("obfuscation_detected"):
            breakdown.append({"factor": "obfuscation_detected", "weight": 15})
        if code_data.get("reflection_usage"):
            breakdown.append({"factor": "reflection_usage", "weight": 10})
        if code_data.get("dynamic_code_loading"):
            breakdown.append({"factor": "dynamic_code_loading", "weight": 15})

        packed = code_data.get("packed_assets") or []
        if packed:
            biggest = max(packed, key=lambda a: a.get("apk_ratio") or 0)
            ratio = biggest.get("apk_ratio") or 0
            breakdown.append({
                "factor": f"packed_assets ({len(packed)}개, 최대 APK의 {ratio*100:.0f}%)",
                "weight": PACKED_ASSET_WEIGHT,
            })

    if strings_data:
        suspicious_count = len(strings_data.get("suspicious_strings", []))
        if suspicious_count:
            weight = min(suspicious_count * SUSPICIOUS_STRING_WEIGHT, SUSPICIOUS_STRING_CAP)
            breakdown.append(
                {"factor": f"suspicious_strings ({suspicious_count}개)", "weight": weight}
            )

    if cert_data and cert_data.get("is_self_signed"):
        breakdown.append({"factor": "certificate.is_self_signed", "weight": SELF_SIGNED_CERT_WEIGHT})

    return breakdown


def calculate_risk(
    manifest_data: dict | None,
    code_data: dict | None,
    strings_data: dict | None,
    cert_data: dict | None = None,
) -> float:
    """analyzer.py가 호출하는 기존 시그니처 - schema.py의 risk_score: float 계약 유지.

    cert_data는 기본값 None으로 둬서, 기존 호출부(cert_data 안 넘기던 코드)도 그대로
    동작한다. 근거(breakdown)까지 필요하면 calculate_risk_with_breakdown()을 쓴다.
    """
    raw = sum(item["weight"] for item in _score_breakdown(manifest_data, code_data, strings_data, cert_data))
    return min(raw / NORMALIZATION_CAP, 1.0)


def calculate_risk_with_breakdown(
    manifest_data: dict | None,
    code_data: dict | None,
    strings_data: dict | None,
    cert_data: dict | None = None,
) -> dict:
    """B의 static_adapter.py용 - risk_score.breakdown까지 채운 형태로 반환.

    {"total": 0.0~1.0 (calculate_risk()와 동일값), "raw": 정규화 전 합산 점수,
     "breakdown": [{"factor": str, "weight": number}, ...]}

    breakdown의 weight 합이 raw와 정확히 일치한다.
    """
    breakdown = _score_breakdown(manifest_data, code_data, strings_data, cert_data)
    raw = sum(item["weight"] for item in breakdown)
    return {"total": min(raw / NORMALIZATION_CAP, 1.0), "raw": raw, "breakdown": breakdown}
