"""동적 분석(후킹 이벤트) 기반 위험도 스코어링.

static_analyzer/risk_scorer.py와 같은 방식(가중치 합산 후 0.0~1.0으로 정규화)을
동적 분석 산출물(DynamicAnalysisResult)에 적용한 버전이다.

1차 버전 — 아래 세 가지 신호를 더한다:
  1. hook_type별 가중치 (custom_xor/cipher가 string_builder/base64보다 위험) +
     호출자(caller_class)가 안드로이드/자바 프레임워크가 아니라 앱 자체 코드일 때 가중치 배수 적용
     (앱이 직접 암복호화/난독화 로직을 실행했다는 뜻이라 프레임워크 내부 동작보다 훨씬 의미있음)
  2. plaintext_candidates 안에서 URL/IP/민감 키워드(password, sms 등) 패턴 탐지
  3. total_events_filtered / total_events_captured 비율이 너무 낮으면(대부분 노이즈) 약한 가산점

static_analyzer와 마찬가지로 이 가중치들은 전부 1차 추측치다. 정상 앱 2~3개 vs
공개 악성 샘플 2~3개로 실제 돌려서 점수 차이가 나는지 확인하고 다시 맞춰야 한다.
"""

from __future__ import annotations

import re
from typing import List

from .schema import DynamicAnalysisResult, HookEvent

# raw 점수를 이 값으로 나눠서 0.0~1.0으로 clamp한다. 임의로 잡은 초기값.
NORMALIZATION_CAP = 100.0

# hook_type별 기본 가중치.
HOOK_TYPE_WEIGHTS = {
    "custom_xor": 10,
    "cipher": 6,
    "base64": 1,
    "string_builder": 0.5,
}

# 호출자가 앱 자체 코드일 때(프레임워크가 아닐 때) 위 가중치에 곱하는 배수.
NON_FRAMEWORK_MULTIPLIER = 3

# 호출자가 프레임워크일 때 위 가중치에 곱하는 할인율. 프레임워크발 string_builder/base64는
# 세션 시간이 길수록(타임존 목록, SQL DDL 등) 수백 건씩 쌓이는 순수 노이즈라, 할인 없이 개수만
# 누적하면 정상 앱도 이벤트 수만으로 점수가 커진다(deskclock 실측 시 0.63까지 올라감을 확인).
# "누가 호출했는가"가 "몇 번 호출됐는가"보다 중요하다는 원칙을 지키기 위해 갯수의 영향력을 죽인다.
FRAMEWORK_DISCOUNT = 0.05

# 안드로이드/자바 표준 프레임워크 패키지 접두사. 여기서 후킹된 호출은 폰트 로딩,
# DB 쿼리 포맷팅 등 OS/런타임 내부 동작일 확률이 높아 정상 앱에서도 흔하게 잡힌다.
_FRAMEWORK_PREFIXES = (
    "android.", "androidx.", "java.", "javax.", "dalvik.",
    "com.google.android.", "com.android.", "org.chromium.", "org.apache.",
)

# 평문 후보 문자열에서 위험 신호로 보는 패턴 (C2 URL, 하드코딩 IP, 민감 키워드 등).
_SUSPICIOUS_STRING_PATTERNS = [
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),  # IPv4
    re.compile(r"(password|token|secret|apikey|api_key)", re.IGNORECASE),
    re.compile(r"(sms|contacts|accounts|clipboard)", re.IGNORECASE),
]

# 가중치 1개당 점수. NORMALIZATION_CAP과 마찬가지로 임의 초기값.
SUSPICIOUS_STRING_WEIGHT = 5

# 필터링 후 남은 이벤트 비율이 이 값보다 낮으면(대부분 중복/노이즈였다는 뜻) 약한 가산점.
# 그 자체로는 악성 여부를 말해주지 않지만, 반복 조립/반복 호출 패턴(예: 디코딩 루프)에서
# 흔히 관찰되는 부수 신호라 작은 가중치만 준다.
NOISE_RATIO_THRESHOLD = 0.3
NOISE_RATIO_PENALTY = 3


def _is_framework_caller(caller_class: str) -> bool:
    return caller_class == "unknown" or caller_class.startswith(_FRAMEWORK_PREFIXES)


def _event_score(event: HookEvent) -> float:
    weight = HOOK_TYPE_WEIGHTS.get(event["hook_type"], 0)
    caller_class = event.get("extra", {}).get("caller_class", "unknown")
    if _is_framework_caller(caller_class):
        weight *= FRAMEWORK_DISCOUNT
    else:
        weight *= NON_FRAMEWORK_MULTIPLIER
    return weight


def _suspicious_string_count(strings: List[str]) -> int:
    return sum(
        1 for s in strings
        if any(pattern.search(s) for pattern in _SUSPICIOUS_STRING_PATTERNS)
    )


def calculate_dynamic_risk(report: DynamicAnalysisResult) -> float:
    events = report.get("events", [])
    raw = sum(_event_score(e) for e in events)

    raw += _suspicious_string_count(report.get("plaintext_candidates", [])) * SUSPICIOUS_STRING_WEIGHT

    captured = report.get("total_events_captured", 0)
    filtered = report.get("total_events_filtered", 0)
    if captured > 0 and (filtered / captured) < NOISE_RATIO_THRESHOLD:
        raw += NOISE_RATIO_PENALTY

    return min(raw / NORMALIZATION_CAP, 1.0)
