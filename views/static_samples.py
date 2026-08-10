"""
views/static_samples.py — 정적 뷰 확인용 가짜 데이터 (역할 B, 왕은서 담당, 7주차)

7주차 계획의 규칙 ②("미완성 부분은 됐다고 치고 화면부터 구현")에 따라, 실제
APK나 apktool/jadx/기기 없이도 정적 화면을 띄워볼 수 있게 만든 데이터다.
6주차에 "남의 작업을 기다리다 아무것도 못 하는" 상황이 실제로 있었기 때문에,
이 파일만 있으면 분석 도구가 하나도 없는 PC에서도 화면 작업이 진행된다.

**전부 손으로 만든 값이다. 실제 분석 결과가 아니다.**
발표 자료 캡처에는 반드시 실제 APK로 돌린 결과를 쓸 것.

세 가지를 준비해 뒀고, 셋 다 화면이 죽지 않아야 한다:
    SAMPLE_OK      — 정상적으로 분석된 악성 앱 (위험 권한 다수)
    SAMPLE_PARTIAL — 일부 하위 단계 실패 (errors가 채워지고 점수가 None)
    SAMPLE_FAILED  — 모듈 자체가 실패 (data가 None)

demo_static.py와 tests/test_static_view.py가 이 데이터를 함께 쓴다.
"""
from __future__ import annotations

import copy
from typing import Any

_OK_DATA: dict[str, Any] = {
    "meta": {
        "apk_name": "sample_banker.apk",
        "analyzed_at": "2026-08-09T04:12:33+00:00",
        "package_name": "com.example.sample.banker",
        "version_name": "1.4.2",
        "version_code": 142,
        "min_sdk": 21,
        "target_sdk": 30,
        "file_hash": {
            "md5": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        },
        "file_size": 4_812_390,
    },
    "manifest": {
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_CONTACTS",
            "android.permission.CAMERA",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.READ_PHONE_STATE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ],
        "dangerous_permissions": [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "activities": ["com.example.sample.banker.MainActivity"],
        "services": ["com.example.sample.banker.AccessibilitySvc"],
        "receivers": ["com.example.sample.banker.SmsReceiver"],
        "providers": [],
        "exported_components": [
            "com.example.sample.banker.MainActivity",
            "com.example.sample.banker.SmsReceiver",
            "com.example.sample.banker.AccessibilitySvc",
        ],
        "components": [
            {
                "type": "activity",
                "name": "com.example.sample.banker.MainActivity",
                "exported": True,
                "intent_filters": [
                    "android.intent.action.MAIN",
                    "android.intent.category.LAUNCHER",
                ],
            },
            {
                "type": "receiver",
                "name": "com.example.sample.banker.SmsReceiver",
                "exported": True,
                "intent_filters": ["android.provider.Telephony.SMS_RECEIVED"],
            },
            {
                "type": "service",
                "name": "com.example.sample.banker.AccessibilitySvc",
                "exported": True,
                "intent_filters": ["android.accessibilityservice.AccessibilityService"],
            },
        ],
    },
    "certificate": {
        "issuer": "CN=Android Debug, O=Android, C=US",
        "subject": "CN=Android Debug, O=Android, C=US",
        "valid_from": "2025-11-02T00:00:00Z",
        "valid_to": "2055-10-26T00:00:00Z",
        "is_self_signed": True,
    },
    "code_analysis": {
        "suspicious_api_calls": [
            {
                "api": "SmsManager.sendTextMessage",
                "location": "Lcom/example/sample/banker/SmsReceiver;",
                "risk": "high",
            },
            {
                "api": "DexClassLoader.<init>",
                "location": "Lcom/example/sample/banker/Loader;",
                "risk": "high",
            },
            {
                "api": "Class.forName",
                "location": "Lcom/example/sample/banker/Loader;",
                "risk": "medium",
            },
        ],
        "obfuscation_detected": True,
        "native_libraries": ["lib/arm64-v8a/libcore.so"],
        "reflection_usage": True,
        "dynamic_code_loading": True,
    },
    "strings": {
        "urls": [
            "http://update.example-cdn.top/payload.dex",
            "https://api.example.com/v1/ping",
        ],
        "ip_addresses": ["203.0.113.77"],
        "suspicious_strings": ["/system/bin/su", "base64:aHR0cDovL2MyLmV4YW1wbGU="],
    },
    "third_party_sdks": ["com.google.firebase"],
    # 아래 점수는 손으로 적은 값이 아니라 D의 calculate_risk_with_breakdown()에
    # 위 데이터를 그대로 넣어서 나온 실제 출력이다. 처음에는 raw를 82로 적었다가
    # breakdown 합계 검증(breakdown_matches_raw)에 걸려서 바로잡았다.
    #
    # 여기서 확인된 것: NORMALIZATION_CAP이 100인데 이 정도 앱의 raw가 이미
    # 140이라 total이 1.0에서 잘린다. 즉 지금 기준으로는 "꽤 위험"과 "매우 위험"이
    # 똑같이 100점으로 보인다. D가 지적한 NORMALIZATION_CAP 재조정이 필요하다는
    # 근거 — 8주차 과제로 넘긴다.
    "risk_score": 1.0,
    "risk_breakdown": {
        "total": 1.0,
        "raw": 140.0,
        # 순서는 risk_scorer가 내보내는 그대로다(권한은 manifest 등장 순서).
        # 가중치 순으로 정렬돼 있지 않다는 점이 중요하다 — 화면에서 위험한 것을
        # 위로 올리는 정렬은 static_data.build_breakdown_rows()가 담당한다.
        "breakdown": [
            {"factor": "android.permission.READ_SMS", "weight": 9},
            {"factor": "android.permission.RECEIVE_SMS", "weight": 9},
            {"factor": "android.permission.SEND_SMS", "weight": 8},
            {"factor": "android.permission.BIND_ACCESSIBILITY_SERVICE", "weight": 10},
            {"factor": "android.permission.SYSTEM_ALERT_WINDOW", "weight": 10},
            {"factor": "android.permission.READ_CONTACTS", "weight": 6},
            {"factor": "android.permission.CAMERA", "weight": 7},
            {"factor": "android.permission.QUERY_ALL_PACKAGES", "weight": 5},
            {"factor": "android.permission.READ_PHONE_STATE", "weight": 4},
            {"factor": "android.permission.WRITE_EXTERNAL_STORAGE", "weight": 3},
            {"factor": "exported_components×2 (3개)", "weight": 6},
            {"factor": "suspicious_api_calls×3 (3개)", "weight": 9},
            {"factor": "obfuscation_detected", "weight": 15},
            {"factor": "reflection_usage", "weight": 10},
            {"factor": "dynamic_code_loading", "weight": 15},
            {"factor": "suspicious_strings×2 (2개)", "weight": 4},
            {"factor": "certificate.is_self_signed", "weight": 10},
        ],
    },
    "errors": [],
}

SAMPLE_OK: dict[str, Any] = {"status": "ok", "data": _OK_DATA, "error": None}


def _make_partial() -> dict[str, Any]:
    """일부 하위 단계가 실패한 결과.

    analyze_static()이 실제로 만드는 형태를 흉내낸 것 — 실패한 단계의 값은
    None이 되고 errors에만 문자열이 남는다. 점수 계산도 함께 실패해서
    risk_score와 risk_breakdown이 둘 다 None인 경우를 일부러 포함시켰다.
    화면이 0점이 아니라 "계산 실패"로 표시하는지 확인하는 용도다.
    target_sdk를 0으로 둔 것도 같은 이유(파싱 실패 표기 확인).
    """
    data = copy.deepcopy(_OK_DATA)
    data["code_analysis"] = None
    data["strings"] = None
    data["certificate"] = None
    data["risk_score"] = None
    data["risk_breakdown"] = None
    data["meta"]["target_sdk"] = 0
    data["errors"] = [
        "code_scanner: jadx 디컴파일 결과 없음 (건너뜀)",
        "string_extractor: 대상 소스 디렉터리 없음",
        "cert_analyzer: META-INF 서명 블록을 찾지 못함",
        "risk_scorer: code_analysis가 None이라 점수 계산 불가",
    ]
    return {"status": "partial", "data": data, "error": None}


SAMPLE_PARTIAL: dict[str, Any] = _make_partial()

SAMPLE_FAILED: dict[str, Any] = {
    "status": "failed",
    "data": None,
    "error": "StaticAnalysisError: apktool을 찾을 수 없습니다 (PATH 확인 필요)",
}

# 대조용 정상 앱. 악성 샘플만 보면 "모든 앱이 빨갛게 나오는 화면"인지 아닌지
# 알 수 없어서, 낮은 점수일 때 화면이 어떻게 보이는지 확인하려고 같이 둔다.
# 점수는 위와 마찬가지로 calculate_risk_with_breakdown()의 실제 출력이다.
_NORMAL_DATA: dict[str, Any] = {
    "meta": {
        "apk_name": "sample_normal.apk",
        "analyzed_at": "2026-08-09T04:20:10+00:00",
        "package_name": "com.example.sample.notes",
        "version_name": "2.0.1",
        "version_code": 201,
        "min_sdk": 24,
        "target_sdk": 34,
        "file_hash": {
            "md5": "5d41402abc4b2a76b9719d911017c592",
            "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
            "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        },
        "file_size": 1_204_733,
    },
    "manifest": {
        "permissions": [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.CAMERA",
            "android.permission.READ_EXTERNAL_STORAGE",
        ],
        "dangerous_permissions": [],
        "activities": ["com.example.sample.notes.MainActivity"],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": ["com.example.sample.notes.MainActivity"],
        "components": [
            {
                "type": "activity",
                "name": "com.example.sample.notes.MainActivity",
                "exported": True,
                "intent_filters": [
                    "android.intent.action.MAIN",
                    "android.intent.category.LAUNCHER",
                ],
            }
        ],
    },
    "certificate": {
        "issuer": "CN=Example Publisher, O=Example Inc, C=KR",
        "subject": "CN=Example Publisher, O=Example Inc, C=KR",
        "valid_from": "2024-03-01T00:00:00Z",
        "valid_to": "2049-02-23T00:00:00Z",
        "is_self_signed": False,
    },
    "code_analysis": {
        "suspicious_api_calls": [],
        "obfuscation_detected": False,
        "native_libraries": [],
        "reflection_usage": False,
        "dynamic_code_loading": False,
    },
    "strings": {
        "urls": ["https://api.example.com/notes"],
        "ip_addresses": [],
        "suspicious_strings": [],
    },
    "third_party_sdks": ["com.google.firebase"],
    "risk_score": 0.12,
    "risk_breakdown": {
        "total": 0.12,
        "raw": 12.0,
        "breakdown": [
            {"factor": "android.permission.CAMERA", "weight": 7},
            {"factor": "android.permission.READ_EXTERNAL_STORAGE", "weight": 3},
            {"factor": "exported_components×2 (1개)", "weight": 2},
        ],
    },
    "errors": [],
}

SAMPLE_NORMAL: dict[str, Any] = {"status": "ok", "data": _NORMAL_DATA, "error": None}

SAMPLES: dict[str, dict[str, Any]] = {
    "악성 앱 예시 (정상 분석)": SAMPLE_OK,
    "정상 앱 예시 (대조용)": SAMPLE_NORMAL,
    "일부 단계 실패": SAMPLE_PARTIAL,
    "모듈 전체 실패": SAMPLE_FAILED,
}


def as_report(static_module: dict[str, Any]) -> dict[str, Any]:
    """static 모듈 dict를 main.py의 통합 report 형태로 감싼다.

    render(report)가 report 전체를 받으므로, 정적 부분만 넣고 나머지 모듈은
    실패 상태로 채운 최소 리포트를 만든다.
    """
    return {
        "apk_name": "sample_banker.apk",
        "package_name": "com.example.sample.banker",
        "analyzed_at": "2026-08-09T04:12:33+00:00",
        "modules": {
            "static": static_module,
            "dynamic": {"status": "failed", "data": None, "error": "샘플 데이터 (미실행)"},
            "network": {"status": "failed", "data": None, "error": "샘플 데이터 (미실행)"},
        },
        "risk_score": {"total": None, "level": None, "breakdown": None},
    }
