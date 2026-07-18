"""
[C] Python-JS 연동 및 데이터 처리 모듈

역할:
- script.on('message', ...)로 들어오는 frida 메시지를 받아 HookEvent로 변환
- 중복 제거 / 평문 판별 필터링
- dynamic_report.json 스키마에 맞춰 최종 결과 dict 생성 + 파일 출력

이 파일은 src/dynamic_analyzer/message_parser.py 에 그대로 넣으면 됨.
"""

from __future__ import annotations

import json
import string
from datetime import datetime
from typing import List

from .schema import HookEvent, DynamicAnalysisResult


# ────────────────────────────────────────────────────────────
# 1. frida 메시지 수신 콜백 (script.on("message", on_message)에 그대로 등록)
# ────────────────────────────────────────────────────────────

# 수신된 이벤트를 세션 동안 계속 누적해두는 버퍼.
# run_test.py / scenario_runner.py에서 세션 끝난 뒤 이 리스트를 build_report()에 넘기면 됨.
_captured_events: List[HookEvent] = []


def on_message(message: dict, data=None) -> None:
    """script.on('message', on_message) 에 그대로 등록할 콜백"""
    print("[디버그] 전체 메시지:", message)  # 이 줄 추가
    if message["type"] == "send":
        payload: HookEvent = message["payload"]
        _captured_events.append(payload)
        print(f"[{payload['hook_type']}] {payload['method_name']} → {payload['raw_value'][:60]}")
    elif message["type"] == "error":
        print(f"[hooks.js 런타임 에러] {message.get('description')}")


def get_captured_events() -> List[HookEvent]:
    """지금까지 누적된 원본 이벤트 리스트를 반환 (필터링 전)"""
    return _captured_events


def reset_captured_events() -> None:
    """다음 앱 분석 전에 버퍼 비우기 (배치 실행 시 반드시 호출)"""
    _captured_events.clear()


# ────────────────────────────────────────────────────────────
# 2. 필터링 로직 — 중복 제거
# ────────────────────────────────────────────────────────────

def dedupe_events(events: List[HookEvent]) -> List[HookEvent]:
    """
    세션 전체 범위에서 (hook_type, method_name, raw_value) 조합이 겹치는 이벤트 제거.
    B가 hooks.js에서 이미 "직전 호출과 연속 동일값"은 걸렀으므로,
    여기서는 "세션 전체에서 안 겹치는지"를 본다 (B 필터와 역할 안 겹침).
    """
    seen = set()
    result = []
    for e in events:
        key = (e["hook_type"], e["method_name"], e["raw_value"])
        if key not in seen:
            seen.add(key)
            result.append(e)
    return result


# ────────────────────────────────────────────────────────────
# 3. 필터링 로직 — 평문 판별
# ────────────────────────────────────────────────────────────

_PRINTABLE = set(string.printable)


def is_plaintext(value: str, min_len: int = 4) -> bool:
    """
    사람이 읽을 수 있는 문자열인지 판별.
    - 너무 짧으면(내부 해시/포인터 값일 확률 높음) 제외
    - 출력 가능한 문자 비율이 낮으면(바이너리/암호문일 확률 높음) 제외
    """
    if not value or len(value) < min_len:
        return False
    printable_ratio = sum(c in _PRINTABLE for c in value) / len(value)
    return printable_ratio > 0.9


def extract_plaintext_candidates(events: List[HookEvent]) -> List[str]:
    return [e["raw_value"] for e in events if is_plaintext(e["raw_value"])]


# ────────────────────────────────────────────────────────────
# 4. dynamic_report.json 조립 + 저장
# ────────────────────────────────────────────────────────────

def build_report(
    package_name: str,
    session_start: datetime,
    raw_events: List[HookEvent],
    output_path: str = "dynamic_report.json",
) -> DynamicAnalysisResult:
    filtered = dedupe_events(raw_events)
    plaintext = extract_plaintext_candidates(filtered)

    report: DynamicAnalysisResult = {
        "package_name": package_name,
        "session_duration_sec": int((datetime.now() - session_start).total_seconds()),
        "total_events_captured": len(raw_events),
        "total_events_filtered": len(filtered),
        "events": filtered,
        "plaintext_candidates": plaintext,
        "errors": [],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    return report


# ────────────────────────────────────────────────────────────
# 5. 실제 크롬 후킹 로그로 검증 (오늘 CLI에서 얻은 실데이터 일부)
#    Python API 연동이 막혀있어도, 이 데이터로 필터링/출력 로직은 지금 검증 가능
# ────────────────────────────────────────────────────────────

REAL_CAPTURED_EVENTS: List[HookEvent] = [
    {"hook_type": "string_builder", "timestamp": "2026-07-18T07:21:56.227Z",
     "class_name": "java.lang.StringBuilder", "method_name": "append",
     "raw_value": "18765ebe", "extra": {}, "thread_id": 8930},
    {"hook_type": "string_builder", "timestamp": "2026-07-18T07:21:56.236Z",
     "class_name": "java.lang.StringBuilder", "method_name": "append",
     "raw_value": "190e6c42a70", "extra": {}, "thread_id": 8930},
    {"hook_type": "string_builder", "timestamp": "2026-07-18T07:21:56.952Z",
     "class_name": "java.lang.StringBuilder", "method_name": "append",
     "raw_value": "Using linker: ", "extra": {}, "thread_id": 8994},
    {"hook_type": "string_builder", "timestamp": "2026-07-18T07:21:56.954Z",
     "class_name": "java.lang.StringBuilder", "method_name": "append",
     "raw_value": "org.chromium.base.library_loader.ModernLinker", "extra": {}, "thread_id": 8994},
    {"hook_type": "string_builder", "timestamp": "2026-07-18T07:21:57.541Z",
     "class_name": "java.lang.StringBuilder", "method_name": "append",
     "raw_value": "Loaded native library version number \"", "extra": {}, "thread_id": 8994},
    {"hook_type": "string_builder", "timestamp": "2026-07-18T07:21:57.544Z",
     "class_name": "java.lang.StringBuilder", "method_name": "append",
     "raw_value": "83.0.4103.106", "extra": {}, "thread_id": 8994},
    {"hook_type": "base64", "timestamp": "2026-07-18T07:21:57.909Z",
     "class_name": "android.util.Base64", "method_name": "encodeToString",
     "raw_value": "MIIEqDCCA5CgAwIBAgIJANWFuGx90071MA0GCSqGSIb3DQEBBAUAMIGU...",
     "extra": {"direction": "encode"}, "thread_id": 8930},
    {"hook_type": "base64", "timestamp": "2026-07-18T07:21:57.910Z",
     "class_name": "android.util.Base64", "method_name": "decode",
     "raw_value": "MIIEqDCCA5CgAwIBAgIJANWFuGx90071MA0GCSqGSIb3DQEBBAUAMIGU...",
     "extra": {"direction": "decode"}, "thread_id": 8930},
    # 중복 제거 로직 검증용: 위 base64 decode와 완전히 동일한 값 한 번 더 (다른 시각)
    {"hook_type": "base64", "timestamp": "2026-07-18T07:21:58.114Z",
     "class_name": "android.util.Base64", "method_name": "decode",
     "raw_value": "MIIEqDCCA5CgAwIBAgIJANWFuGx90071MA0GCSqGSIb3DQEBBAUAMIGU...",
     "extra": {"direction": "decode"}, "thread_id": 8930},
    {"hook_type": "string_builder", "timestamp": "2026-07-18T07:21:58.418Z",
     "class_name": "java.lang.StringBuilder", "method_name": "append",
     "raw_value": "Error while loading asset ", "extra": {}, "thread_id": 8930},
    {"hook_type": "string_builder", "timestamp": "2026-07-18T07:21:58.420Z",
     "class_name": "java.lang.StringBuilder", "method_name": "append",
     "raw_value": "assets/stored-locales/en-US.pak", "extra": {}, "thread_id": 8930},
]


if __name__ == "__main__":
    # 실데이터로 필터링 + JSON 출력 검증
    report = build_report(
        package_name="com.android.chrome",
        session_start=datetime.now(),
        raw_events=REAL_CAPTURED_EVENTS,
        output_path="dynamic_report.json",
    )
    print("\n=== dynamic_report.json 1차 출력 결과 ===")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\n원본 {report['total_events_captured']}개 → 필터링 후 {report['total_events_filtered']}개")
    print(f"평문 후보 {len(report['plaintext_candidates'])}개 발견")