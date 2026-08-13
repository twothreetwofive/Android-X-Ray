"""apktool/jadx로 APK를 디컴파일하고, 분석 전반에 쓰이는 기본 메타데이터를 뽑는다.

디컴파일 자체(apktool/jadx 호출, 타임아웃/예외 처리)는 decompiler.py(B 작성)를 그대로 쓴다.
이 모듈은 그 위에서 analyzer.py가 기대하는 형태(dict)로 결과를 감싸는 역할만 한다.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from androguard.core.apk import APK

from .decompiler import DEFAULT_TIMEOUT, run_apktool, run_jadx


def _hash_file(apk_path: Path) -> dict:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with apk_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def extract_apk(apk_path: str | Path, work_dir: str | Path, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """APK를 디컴파일하고 meta 정보를 뽑는다.

    Returns:
        {
            "meta": schema.Meta 형태의 dict,
            "apk_path": 원본 apk 경로 (Path) — cert_analyzer 등 다른 모듈이 재사용,
            "apktool_dir": apktool 디컴파일 결과 폴더 (Path),
            "jadx_dir": jadx 디컴파일 결과 폴더 (Path),
        }
    """
    apk_path = Path(apk_path)
    work_dir = Path(work_dir)

    apk = APK(str(apk_path))
    meta = {
        # apk_name은 analyze_static()의 반환값만 봐서는 "어떤 파일을 분석했는지" 알 수
        # 없어서 추가했다 (통합 스키마의 required 필드). 호출부마다 경로를 따로 들고
        # 다니게 하는 것보다 meta에 넣어두는 쪽이 대시보드 단계에서도 재사용하기 좋다.
        "apk_name": apk_path.name,
        "package_name": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": _safe_int(apk.get_androidversion_code()),
        "min_sdk": _safe_int(apk.get_min_sdk_version()),
        "target_sdk": _safe_int(apk.get_target_sdk_version()),
        "file_hash": _hash_file(apk_path),
        "file_size": apk_path.stat().st_size,
    }

    # APK마다 별도 하위 폴더에 푼다.
    #
    # 이전에는 모든 APK를 work/apktool, work/jadx에 그대로 덮어썼다. apktool -f나
    # jadx -d는 자기가 새로 쓰는 파일만 덮어쓸 뿐 **이전 APK의 잔재를 지우지 않기**
    # 때문에, 두 번째 APK를 분석하면 앞 APK의 소스가 그대로 남아 code_scanner /
    # string_extractor가 그것까지 훑었다.
    #
    # 실측(8주차): 시계 앱을 분석한 뒤 캘린더를 분석하니 캘린더 결과에
    # sources/com/android/deskclock/... 의 AccessibilityService와 Spotify SDK의
    # Base64.decode가 "캘린더의 의심 API"로 잡혀 정적 점수가 부풀었다.
    #
    # 폴더 이름에 sha256 앞 8자를 붙여 같은 파일명 다른 내용도 섞이지 않게 한다.
    apk_id = f"{apk_path.stem}-{meta['file_hash']['sha256'][:8]}"
    target_dir = work_dir / apk_id

    # 같은 APK를 다시 돌릴 때 이전 결과가 남아 있으면 그것도 오염원이 되므로
    # (예: 재패키징으로 클래스가 빠진 경우) 우리가 만든 이 폴더만 지우고 새로 푼다.
    if target_dir.exists():
        shutil.rmtree(target_dir)

    apktool_dir = run_apktool(apk_path, target_dir / "apktool", timeout=timeout)
    jadx_dir = run_jadx(apk_path, target_dir / "jadx", timeout=timeout)

    return {
        "meta": meta,
        "apk_path": apk_path,
        "apktool_dir": apktool_dir,
        "jadx_dir": jadx_dir,
    }
