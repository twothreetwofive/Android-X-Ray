"""종합 위험도 스코어링. (원래 D 담당, D 미착수라 대신 작성)

1차 버전 — 권한 가중치 합산 + 코드/문자열 스캔 결과를 더해서 0.0~1.0으로 정규화.
정상 앱 2~3개 vs 공개 악성 샘플 2~3개로 실제 돌려보고 점수 차이가 나는지
검증한 뒤 NORMALIZATION_CAP과 각 항목 가중치를 다시 맞춰야 하는 휴리스틱이다.
"""

from __future__ import annotations

from .manifest_parser import PERMISSION_WEIGHTS

# raw 점수를 이 값으로 나눠서 0.0~1.0으로 clamp한다. 임의로 잡은 초기값.
NORMALIZATION_CAP = 100.0


def calculate_risk(manifest_data: dict | None, code_data: dict | None, strings_data: dict | None) -> float:
    raw = 0.0

    if manifest_data:
        raw += sum(
            PERMISSION_WEIGHTS.get(p, 0) for p in manifest_data.get("dangerous_permissions", [])
        )
        raw += len(manifest_data.get("exported_components", [])) * 2

    if code_data:
        raw += len(code_data.get("suspicious_api_calls", [])) * 3
        raw += 15 if code_data.get("obfuscation_detected") else 0
        raw += 10 if code_data.get("reflection_usage") else 0
        raw += 15 if code_data.get("dynamic_code_loading") else 0

    if strings_data:
        raw += len(strings_data.get("suspicious_strings", [])) * 2

    return min(raw / NORMALIZATION_CAP, 1.0)
