"""
[D] ADB 자동화 모듈

역할:
- 에뮬레이터에 설치된 앱을 adb로 직접 조작해서(런처 실행, 화면 탭, 텍스트 입력,
  권한 부여 등) 시나리오(로그인, 권한 요청 등)를 자동으로 재현한다.
- A의 frida_controller.py는 "프로세스를 spawn하고 후킹을 붙이는 것"까지만 하고,
  그 뒤 실제 화면 조작(로그인 버튼 누르기 등)은 Frida가 아니라 여기서 adb로 한다.
- scenario_runner.py가 이 모듈 + frida_controller.py + message_parser.py를 엮는다.
"""

from __future__ import annotations

import re
import subprocess
import time
from typing import List, Optional


class AdbError(RuntimeError):
    """adb 명령 실행 자체가 실패했을 때 (adb 미설치, 디바이스 미연결 등)"""


# Android 표준 keyevent 코드 (adb shell input keyevent에 그대로 사용)
KEYCODE_BACK = "KEYCODE_BACK"
KEYCODE_HOME = "KEYCODE_HOME"
KEYCODE_ENTER = "KEYCODE_ENTER"
KEYCODE_TAB = "KEYCODE_TAB"
KEYCODE_DPAD_RIGHT = "KEYCODE_DPAD_RIGHT"


class AdbRunner:
    def __init__(self, serial: Optional[str] = None, timeout: float = 15.0):
        """serial=None이면 연결된 디바이스가 하나뿐이라고 가정 (에뮬레이터 1대 기준)."""
        self.serial = serial
        self.timeout = timeout

    def _base_cmd(self) -> List[str]:
        cmd = ["adb"]
        if self.serial:
            cmd += ["-s", self.serial]
        return cmd

    def _run(self, args: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
        cmd = self._base_cmd() + args
        try:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
            )
        except FileNotFoundError as e:
            raise AdbError("adb 실행 파일을 찾을 수 없음 (PATH 확인 필요)") from e
        except subprocess.TimeoutExpired as e:
            raise AdbError(f"adb 명령 타임아웃: {' '.join(args)}") from e

    def _shell(self, args: List[str], timeout: Optional[float] = None) -> str:
        result = self._run(["shell"] + args, timeout=timeout)
        return result.stdout

    # ── 디바이스/앱 상태 확인 ──────────────────────────────────

    def check_device(self) -> bool:
        """에뮬레이터가 연결되어 device 상태인지 확인. (Step 1, B의 가이드와 동일)"""
        result = self._run(["devices"])
        for line in result.stdout.splitlines()[1:]:
            line = line.strip()
            if line and line.endswith("\tdevice"):
                return True
        return False

    def is_installed(self, package_name: str) -> bool:
        """앱이 에뮬레이터에 설치되어 있는지 확인. 없으면 spawn 전에 걸러서 낭비 방지."""
        output = self._shell(["pm", "list", "packages", package_name])
        return any(line.strip() == f"package:{package_name}" for line in output.splitlines())

    def is_running(self, package_name: str) -> bool:
        """앱 프로세스가 살아있는지 확인 (크래시/강제종료 감지용).

        `pidof`가 없는 기기도 있어서 `ps -A`를 fallback으로 쓴다.
        """
        pidof_output = self._shell(["pidof", package_name]).strip()
        if pidof_output:
            return True
        ps_output = self._shell(["ps", "-A"])
        return any(line.strip().endswith(package_name) for line in ps_output.splitlines())

    # ── 앱 실행/종료 ──────────────────────────────────────────

    def launch(self, package_name: str) -> bool:
        """앱을 런처 인텐트로 실행한다.

        메인 액티비티 이름을 몰라도 되도록 `monkey`로 LAUNCHER 카테고리 인텐트를
        날린다 (`am start -n`은 액티비티 이름이 필요해서 대상 앱마다 조사해야 함).
        frida_controller.spawn_and_attach()로 이미 프로세스를 띄운 뒤라면
        이 메서드는 보통 필요 없고, adb만으로 수동 프로토타입을 만들 때(1일차) 쓴다.
        """
        result = self._run(
            ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            timeout=10.0,
        )
        return "Events injected: 1" in result.stdout

    def force_stop(self, package_name: str) -> None:
        """다음 시나리오 실행 전 잔여 프로세스 정리."""
        self._run(["shell", "am", "force-stop", package_name])

    def wait_for_process(self, package_name: str, timeout: float = 10.0, interval: float = 0.5) -> bool:
        """프로세스가 뜰 때까지 폴링. spawn 직후 실제로 살아있는지 확인할 때 사용."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_running(package_name):
                return True
            time.sleep(interval)
        return False

    # ── UI 조작 (로그인 입력, 권한 다이얼로그 등) ──────────────────

    def tap(self, x: int, y: int) -> None:
        self._run(["shell", "input", "tap", str(x), str(y)])

    def swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int = 300) -> None:
        self._run(["shell", "input", "swipe", str(x1), str(y1), str(x2), str(y2), str(duration_ms)])

    def input_text(self, text: str) -> None:
        """adb input text는 공백을 못 받아서 %s로 치환."""
        escaped = re.sub(r"\s", "%s", text)
        self._run(["shell", "input", "text", escaped])

    def press_key(self, keycode: str) -> None:
        self._run(["shell", "input", "keyevent", keycode])

    def grant_permission(self, package_name: str, permission: str) -> bool:
        """권한 다이얼로그 좌표를 몰라도 되는 결정적인 방법.

        실기기 대상 자동화에서 좌표 탭보다 이 방법이 안정적이라 권한 요청
        시나리오의 기본 경로로 쓴다. 다이얼로그를 실제로 띄워서 탭으로
        허용/거부하는 경로가 필요하면 `tap_permission_dialog()`를 쓴다
        (좌표는 API 레벨/기기마다 달라질 수 있어 실제 타겟 앱으로 검증 필요).
        """
        result = self._run(["shell", "pm", "grant", package_name, permission])
        return result.returncode == 0 and not result.stderr.strip()

    def tap_permission_dialog(self, allow: bool, screen_width: int, screen_height: int) -> None:
        """런타임 권한 다이얼로그를 화면 비율 좌표로 탭한다.

        표준 Android 권한 다이얼로그는 화면 하단에 버튼이 있고, "허용"이 보통
        오른쪽에 위치한다. 정확한 좌표는 Android 버전/기기 해상도마다 달라서
        여기서는 화면 크기 비율로 근사한다 — 팀 에뮬레이터(xray_api30, Pixel 4 /
        API 30)로 실제 검증 필요 (5일차 통합 때 좌표 보정 예정).
        """
        y = int(screen_height * 0.82)
        x = int(screen_width * (0.75 if allow else 0.25))
        self.tap(x, y)
