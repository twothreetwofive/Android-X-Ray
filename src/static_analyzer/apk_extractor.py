"""apktool/jadx로 APK를 디컴파일하고, 분석 전반에 쓰이는 기본 메타데이터를 뽑는다.

디컴파일 자체(apktool/jadx 호출, 타임아웃/예외 처리)는 decompiler.py(B 작성)를 그대로 쓴다.
이 모듈은 그 위에서 analyzer.py가 기대하는 형태(dict)로 결과를 감싸는 역할만 한다.
"""

from __future__ import annotations

import hashlib
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
            "apktool_dir": apktool 디컴파일 결과 폴더 (Path),
            "jadx_dir": jadx 디컴파일 결과 폴더 (Path),
        }
    """
    apk_path = Path(apk_path)
    work_dir = Path(work_dir)

    apk = APK(str(apk_path))
    meta = {
        "package_name": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": _safe_int(apk.get_androidversion_code()),
        "min_sdk": _safe_int(apk.get_min_sdk_version()),
        "target_sdk": _safe_int(apk.get_target_sdk_version()),
        "file_hash": _hash_file(apk_path),
        "file_size": apk_path.stat().st_size,
    }

    apktool_dir = run_apktool(apk_path, work_dir / "apktool", timeout=timeout)
    jadx_dir = run_jadx(apk_path, work_dir / "jadx", timeout=timeout)

    return {"meta": meta, "apktool_dir": apktool_dir, "jadx_dir": jadx_dir}
