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
        "packed_assets": _detect_packed_assets(extracted, apk_path),
    }


# ── 패킹된 페이로드 탐지 (8주차 추가) ──────────────────────────
#
# 계기: MalwareBazaar 드로퍼 샘플(SHA256 44f9d5c6…)이 21점 "정상"으로 나왔다.
# 정적 분석이 jadx 소스만 훑기 때문인데, 이 앱의 실체는 코드가 아니라
# assets/f80at32d.zip 이었다:
#   - 크기 8,331,772 bytes = APK 전체의 **94.9%**
#   - 매직바이트 "SVLT" (알려진 포맷 아님), 엔트로피 7.906/8.0 = 암호화된 데이터
#   - UpgradeActivity(WebView)가 JS 브리지로 설치를 유도하고
#     REQUEST_INSTALL_PACKAGES로 2차 APK를 설치하는 구조
# 즉 페이로드를 통째로 품고 있어서 C2 통신조차 필요 없었다(네트워크 캡처가
# 정당하게 비어 있던 이유). 코드만 보는 분석으로는 원리상 놓칠 수밖에 없다.
#
# 판별 기준: 큰 파일 + 높은 엔트로피 + 알려진 포맷 아님. 셋을 모두 만족할 때만
# 잡는다. 정상 앱도 큰 리소스(폰트/이미지/모델)를 assets에 넣지만, 그것들은
# 매직바이트로 식별되거나 엔트로피가 이만큼 높지 않다.
PACKED_ASSET_MIN_BYTES = 512 * 1024      # 이보다 작으면 페이로드로 보기 어렵다
PACKED_ASSET_MIN_ENTROPY = 7.5           # 8.0에 가까울수록 암호화/압축
PACKED_ASSET_MIN_APK_RATIO = 0.20        # APK에서 차지하는 비율

# 매직바이트로 식별되는 정상 포맷(압축/미디어)은 제외한다. 이것들도 엔트로피는
# 높지만 "정체를 알 수 없는 덩어리"가 아니다.
_KNOWN_MAGIC = {
    b"PK\x03\x04": "zip/jar/apk",
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"\xfd7zXZ": "xz",
    b"7z\xbc\xaf": "7zip",
    b"\x89PNG": "png",
    b"\xff\xd8\xff": "jpeg",
    b"RIFF": "webp/wav",
    b"OggS": "ogg",
    b"\x00\x00\x00\x18ftyp": "mp4",
    b"\x00\x00\x00\x20ftyp": "mp4",
    b"dex\n": "dex",
    b"\x02\x00\x0c\x00": "arsc",
    b"OTTO": "otf",
    b"\x00\x01\x00\x00": "ttf",
    b"wOF": "woff",
}


def _shannon_entropy(data: bytes) -> float:
    """바이트 분포의 섀넌 엔트로피(0~8). 8에 가까우면 암호화/압축된 데이터다."""
    import math
    from collections import Counter

    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _looks_known_format(head: bytes) -> str | None:
    for magic, name in _KNOWN_MAGIC.items():
        if head.startswith(magic):
            return name
    return None


def _detect_packed_assets(extracted: dict, apk_path: Path) -> list[dict]:
    """apktool 결과의 assets/ res/raw/ 에서 "정체 불명의 큰 암호화 덩어리"를 찾는다.

    apktool 결과가 없거나 읽을 수 없으면 조용히 빈 리스트를 반환한다 —
    이 하위 검사 하나 때문에 정적 분석 전체가 실패하면 안 된다.
    """
    apktool_dir = extracted.get("apktool_dir")
    if not apktool_dir:
        return []

    try:
        apk_size = apk_path.stat().st_size
    except OSError:
        return []

    found: list[dict] = []
    for sub in ("assets", "res/raw"):
        base = Path(apktool_dir) / sub
        if not base.is_dir():
            continue
        for f in base.rglob("*"):
            if not f.is_file():
                continue
            try:
                size = f.stat().st_size
                if size < PACKED_ASSET_MIN_BYTES:
                    continue
                if apk_size and (size / apk_size) < PACKED_ASSET_MIN_APK_RATIO:
                    continue
                with f.open("rb") as fh:
                    head = fh.read(16)
                    fh.seek(0)
                    sample = fh.read(1_000_000)   # 앞 1MB만 봐도 충분하다
            except OSError:
                continue

            if _looks_known_format(head):
                continue

            entropy = _shannon_entropy(sample)
            if entropy < PACKED_ASSET_MIN_ENTROPY:
                continue

            found.append({
                "path": str(f.relative_to(apktool_dir)),
                "size": size,
                "apk_ratio": round(size / apk_size, 4) if apk_size else None,
                "entropy": round(entropy, 3),
                "magic": head[:8].hex(),
            })

    return found
