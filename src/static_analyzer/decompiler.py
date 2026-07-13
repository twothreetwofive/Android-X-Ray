"""apktool / jadx CLI를 감싸는 디컴파일 wrapper 함수 모음.

정적 분석 파이프라인의 첫 단계로, APK를 apktool과 jadx로 각각 디컴파일해서
이후 단계(Manifest 파싱 등)가 사용할 소스 트리를 만들어 둔다.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from .exceptions import StaticAnalysisError

DEFAULT_TIMEOUT = 120  # 초. 큰 APK는 더 걸릴 수 있으므로 호출부에서 조정 가능


class DecompileError(StaticAnalysisError):
    """디컴파일 도구 실행이 실패했을 때 발생."""


class DecompileTimeoutError(DecompileError):
    """지정한 시간 안에 디컴파일이 끝나지 않았을 때 발생."""


def _run_tool(cmd: list[str], tool_name: str, timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise DecompileTimeoutError(
            f"{tool_name}이(가) {timeout}초 내에 끝나지 않아 중단함: {' '.join(cmd)}"
        ) from e
    except FileNotFoundError as e:
        raise DecompileError(
            f"'{cmd[0]}' 실행 파일을 찾을 수 없음. PATH에 {tool_name} 경로가 등록되어 있는지 확인하세요."
        ) from e


def run_apktool(apk_path: str | Path, output_dir: str | Path, timeout: int = DEFAULT_TIMEOUT) -> Path:
    """apktool d 로 APK를 디컴파일해서 output_dir에 리소스/스말리 코드를 풀어낸다."""
    apk_path = Path(apk_path)
    output_dir = Path(output_dir)
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK 파일을 찾을 수 없음: {apk_path}")

    cmd = ["apktool", "d", "-f", "-o", str(output_dir), str(apk_path)]
    result = _run_tool(cmd, "apktool", timeout)

    if result.returncode != 0:
        raise DecompileError(
            f"apktool 디컴파일 실패 (exit code {result.returncode}): {result.stderr.strip()}"
        )
    return output_dir


def run_jadx(apk_path: str | Path, output_dir: str | Path, timeout: int = DEFAULT_TIMEOUT) -> Path:
    """jadx로 APK를 디컴파일해서 output_dir에 자바 소스코드를 복원한다."""
    apk_path = Path(apk_path)
    output_dir = Path(output_dir)
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK 파일을 찾을 수 없음: {apk_path}")

    cmd = ["jadx", "-d", str(output_dir), str(apk_path)]
    result = _run_tool(cmd, "jadx", timeout)

    if result.returncode != 0:
        raise DecompileError(
            f"jadx 디컴파일 실패 (exit code {result.returncode}): {result.stderr.strip()}"
        )
    return output_dir
