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

SELF_SIGNED_CERT_WEIGHT = 10


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
            breakdown.append(
                {"factor": f"exported_components×2 ({exported_count}개)", "weight": exported_count * 2}
            )

    if code_data:
        api_count = len(code_data.get("suspicious_api_calls", []))
        if api_count:
            breakdown.append({"factor": f"suspicious_api_calls×3 ({api_count}개)", "weight": api_count * 3})
        if code_data.get("obfuscation_detected"):
            breakdown.append({"factor": "obfuscation_detected", "weight": 15})
        if code_data.get("reflection_usage"):
            breakdown.append({"factor": "reflection_usage", "weight": 10})
        if code_data.get("dynamic_code_loading"):
            breakdown.append({"factor": "dynamic_code_loading", "weight": 15})

    if strings_data:
        suspicious_count = len(strings_data.get("suspicious_strings", []))
        if suspicious_count:
            breakdown.append(
                {"factor": f"suspicious_strings×2 ({suspicious_count}개)", "weight": suspicious_count * 2}
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
