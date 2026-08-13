"""jadx로 APK를 디컴파일하고, 분석 전반에 쓰이는 기본 메타데이터를 뽑는다.

디컴파일 자체(jadx 호출, 타임아웃/예외 처리)는 decompiler.py(B 작성)를 그대로 쓴다.
이 모듈은 그 위에서 analyzer.py가 기대하는 형태(dict)로 결과를 감싸는 역할만 한다.

apktool은 더 이상 실행하지 않는다 — 결과물(apktool_dir)을 소비하는 하위 단계가
하나도 없었고(모든 코드/문자열/SDK 스캔이 jadx 트리를, manifest/cert/meta는
androguard를 씀), 느린 apktool이 타임아웃 나면 정적 분석 전체가 죽던 문제만 있었다.
apktool CLI 래퍼(decompiler.run_apktool)는 나중에 실제로 쓸 데가 생기면
재사용할 수 있게 남겨 뒀다.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from androguard.core.apk import APK

from .decompiler import DEFAULT_TIMEOUT, run_jadx
from .exceptions import StaticAnalysisError


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
            "jadx_dir": jadx 디컴파일 결과 폴더 (Path) 또는 실패 시 None,
            "decompile_warnings": 디컴파일 실패 사유 목록 (없으면 빈 리스트),
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
    # 이전에는 모든 APK를 work/jadx에 그대로 덮어썼다. jadx -d는 자기가 새로 쓰는
    # 파일만 덮어쓸 뿐 **이전 APK의 잔재를 지우지 않기** 때문에, 두 번째 APK를
    # 분석하면 앞 APK의 소스가 그대로 남아 code_scanner / string_extractor가
    # 그것까지 훑었다.
    #
    # 실측(8주차): 시계 앱을 분석한 뒤 캘린더를 분석하니 캘린더 결과에
    # sources/com/android/deskclock/... 의 AccessibilityService와 Spotify SDK의
    # Base64.decode가 "캘린더의 의심 API"로 잡혀 정적 점수가 부풀었다.
    #
    # 폴더 이름에 sha256 앞 8자를 붙여 같은 파일명 다른 내용도 섞이지 않게 한다.
    apk_id = f"{apk_path.stem}-{meta['file_hash']['sha256'][:8]}"
    target_dir = work_dir / apk_id
    if target_dir.exists():
        shutil.rmtree(target_dir)

    # jadx 디컴파일은 실패해도 meta/package_name을 잃지 않도록 방어한다 — 여기서
    # 예외가 위로 전파되면 analyze_static()이 치명적 실패로 처리해 동적/네트워크
    # 단계까지 package_name을 못 구해 전부 안 돌던 문제가 있었다. 실패 시 jadx_dir은
    # None이 되고 사유를 decompile_warnings에 남겨 상위 errors로 노출한다.
    warnings: list[str] = []
    try:
        jadx_dir = run_jadx(apk_path, target_dir / "jadx", timeout=timeout)
    except StaticAnalysisError as e:
        warnings.append(f"jadx 디컴파일 실패(무시하고 계속 진행): {e}")
        jadx_dir = None

    return {
        "meta": meta,
        "apk_path": apk_path,
        "jadx_dir": jadx_dir,
        "decompile_warnings": warnings,
    }
