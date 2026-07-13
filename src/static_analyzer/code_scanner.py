"""디컴파일 코드에서 API 호출·난독화·리플렉션·네이티브 라이브러리 탐지.

jadx가 만든 자바 소스 트리를 텍스트로 훑는 정규식 기반 1차 스캔이다.
바이트코드를 직접 분석하는 게 아니라서 오탐/누락이 있을 수 있음 —
실제 정상/악성 샘플로 재검증 필요 (아직 안 함).
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

# API 이름(부분 문자열 매칭) -> 위험도
SUSPICIOUS_APIS = {
    "HttpURLConnection": "medium",
    "OkHttpClient": "medium",
    "Runtime.exec": "high",
    "ProcessBuilder": "high",
    "DexClassLoader": "high",
    "PathClassLoader": "high",
    "Cipher.getInstance": "medium",
    "SmsManager": "high",
    "AccessibilityService": "high",
    "TelephonyManager": "medium",
    "Base64.decode": "low",
}

# 클래스 파일 이름이 a, b, A0 처럼 1~2글자면 난독화된 이름으로 취급
_OBFUSCATED_NAME_RE = re.compile(r"^[a-zA-Z][0-9A-Za-z]?$")
_OBFUSCATION_RATIO_THRESHOLD = 0.3


def _detect_native_libraries(apk_path: Path) -> list[str]:
    libs = set()
    with zipfile.ZipFile(apk_path) as z:
        for name in z.namelist():
            if name.startswith("lib/") and name.endswith(".so"):
                libs.add(Path(name).name)
    return sorted(libs)


def scan_code(extracted: dict) -> dict:
    jadx_dir = Path(extracted["jadx_dir"])
    apk_path = Path(extracted["apk_path"])

    suspicious_api_calls = []
    reflection_usage = False
    dynamic_code_loading = False
    obfuscated_class_count = 0
    total_class_count = 0

    for java_file in jadx_dir.rglob("*.java"):
        total_class_count += 1
        if _OBFUSCATED_NAME_RE.match(java_file.stem):
            obfuscated_class_count += 1

        text = java_file.read_text(encoding="utf-8", errors="ignore")
        rel_path = str(java_file.relative_to(jadx_dir))

        for api, risk in SUSPICIOUS_APIS.items():
            if api in text:
                suspicious_api_calls.append({"api": api, "location": rel_path, "risk": risk})

        if "java.lang.reflect" in text or "Class.forName(" in text:
            reflection_usage = True
        if "DexClassLoader" in text or "System.loadLibrary" in text:
            dynamic_code_loading = True

    obfuscation_detected = (
        total_class_count > 0
        and (obfuscated_class_count / total_class_count) > _OBFUSCATION_RATIO_THRESHOLD
    )

    return {
        "suspicious_api_calls": suspicious_api_calls,
        "obfuscation_detected": obfuscation_detected,
        "native_libraries": _detect_native_libraries(apk_path),
        "reflection_usage": reflection_usage,
        "dynamic_code_loading": dynamic_code_loading,
    }
