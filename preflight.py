"""
preflight.py — 분석 시작 전 에뮬레이터 준비 상태 점검 + 자동 설치 (8주차)

왜 필요한가
-----------
대시보드에 APK를 업로드하면 정적 분석은 파일만 있으면 되지만, **동적/네트워크
분석은 그 앱이 에뮬레이터에 설치돼 있어야** 한다(frida가 패키지명으로 앱을
띄우는 구조라서). 그런데 업로드는 파일을 서버 임시 폴더에 저장할 뿐 설치를
하지 않는다. 그래서 새로 받은 샘플을 UI로 올리면 **어떤 샘플이든** 정적만
성공하고 동적·네트워크는 "앱이 설치되어 있지 않음"으로 실패했다.

CLI에서는 scripts/prepare_emulator.sh가 그 일을 대신 해줬기 때문에 문제가
드러나지 않았고, "샘플이 잘못됐나"로 오해하기 쉬웠다.

이 모듈은 분석 직전에 다음을 점검하고, 고칠 수 있는 것은 고친다:
    1. adb 실행 가능 여부          (PATH 문제)
    2. 기기 연결                    (에뮬레이터/중계)
    3. 대상 앱 설치 — 없으면 설치   ← 이게 핵심
    4. frida-server 구동
    5. tcpdump 준비
고칠 수 없는 것은 사람이 읽을 수 있는 안내로 돌려준다.

streamlit에 의존하지 않는다(테스트/CLI에서도 그대로 쓸 수 있게).
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

TCPDUMP_DEVICE_PATH = "/data/local/tmp/tcpdump"


@dataclass
class PreflightResult:
    ok: bool                                  # 동적/네트워크를 시도할 만한 상태인가
    steps: list[tuple[str, str, str]] = field(default_factory=list)  # (레벨, 제목, 설명)

    def add(self, level: str, title: str, detail: str = "") -> None:
        self.steps.append((level, title, detail))


def _adb(args: list[str], timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(["adb"] + args, capture_output=True, text=True, timeout=timeout)


def _package_name_of(apk_path: str) -> Optional[str]:
    """androguard로 패키지명만 빠르게 읽는다(디컴파일 없이 매니페스트만 파싱).

    androguard는 loguru로 AXML 파싱 과정을 수천 줄 찍는다. CLI(main.py)는 이미
    끄고 있지만 대시보드 경로는 이 함수를 통해 androguard를 처음 부르므로
    여기서도 꺼 준다 — 안 그러면 streamlit을 띄운 터미널이 로그로 덮인다.
    """
    try:
        try:
            from loguru import logger

            logger.remove()
        except ImportError:
            pass
        from androguard.core.apk import APK

        return APK(apk_path).get_package()
    except Exception:  # noqa: BLE001 — 여기서 실패해도 정적 분석은 계속돼야 한다
        return None


def check_and_prepare(apk_path: str, auto_install: bool = True) -> PreflightResult:
    """분석 전 점검. 동적/네트워크 준비가 안 됐어도 예외를 던지지 않는다 —
    정적 분석만이라도 진행하는 것이 이 프로젝트의 부분 리포트 정책이다."""
    result = PreflightResult(ok=True)

    # 1. adb
    if shutil.which("adb") is None:
        result.ok = False
        result.add("error", "adb를 찾을 수 없습니다",
                   "터미널에서 `source scripts/wsl_env.sh` 실행 후 대시보드를 다시 띄우세요. "
                   "정적 분석은 그대로 진행됩니다.")
        return result
    result.add("ok", "adb 확인됨")

    # 2. 기기 연결
    try:
        devices = _adb(["devices"]).stdout
    except (OSError, subprocess.SubprocessError) as e:
        result.ok = False
        result.add("error", "adb 실행 실패", str(e))
        return result

    if not any(line.strip().endswith("\tdevice") for line in devices.splitlines()[1:]):
        result.ok = False
        result.add("error", "연결된 기기가 없습니다",
                   "Windows에서 에뮬레이터를 켜고 `bash scripts/connect_emulator.sh`를 실행하세요.")
        return result
    result.add("ok", "에뮬레이터 연결됨")

    # 3. 대상 앱 설치 여부 — 이 모듈이 만들어진 이유
    package = _package_name_of(apk_path)
    if package is None:
        result.add("warn", "패키지명을 읽지 못했습니다", "설치 여부를 확인하지 못했습니다.")
    else:
        installed = any(
            line.strip() == f"package:{package}"
            for line in _adb(["shell", "pm", "list", "packages", package]).stdout.splitlines()
        )
        if installed:
            result.add("ok", f"앱 설치 확인됨 ({package})")
        elif not auto_install:
            result.ok = False
            result.add("error", f"앱이 설치되어 있지 않습니다 ({package})",
                       "동적·네트워크 분석은 설치된 앱을 실행해야 가능합니다.")
        else:
            # -g: 런타임 권한을 미리 부여해 권한 팝업에서 시나리오가 멈추지 않게 한다.
            out = _adb(["install", "-r", "-g", apk_path], timeout=300).stdout
            if "Success" in out:
                result.add("ok", f"앱 설치 완료 ({package})")
            elif "NO_MATCHING_ABIS" in out:
                result.ok = False
                result.add("error", "설치 실패 — APK의 네이티브 라이브러리가 기기 ABI와 맞지 않습니다",
                           "`python3 scripts/check_apk_compat.py <apk>`로 확인하세요. "
                           "이 샘플은 정적 분석 전용으로 쓸 수 있습니다.")
            else:
                result.ok = False
                result.add("error", "앱 설치 실패", out.strip()[:300])

    # 4. frida-server
    if _adb(["shell", "pidof", "frida-server"]).stdout.strip():
        result.add("ok", "frida-server 구동 중")
    else:
        result.ok = False
        result.add("error", "frida-server가 실행 중이 아닙니다",
                   "`bash scripts/prepare_emulator.sh`를 실행하세요.")

    # 5. tcpdump
    check = _adb(["shell", f"[ -f {TCPDUMP_DEVICE_PATH} ] && echo EXISTS"]).stdout
    if "EXISTS" in check:
        result.add("ok", "tcpdump 준비됨")
    else:
        result.ok = False
        result.add("error", "기기에 tcpdump가 없습니다",
                   "`bash scripts/prepare_emulator.sh`를 실행하세요. 없으면 네트워크 분석이 실패합니다.")

    return result
