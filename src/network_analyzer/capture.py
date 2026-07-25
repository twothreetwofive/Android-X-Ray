"""network_analyzer/capture.py
Android X-Ray - Role A (동적 분석: 네트워크 캡처 제어)

목표: adb shell 위에서 tcpdump 프로세스를 시작/종료하고,
      결과 pcap을 호스트로 pull 해오는 컨트롤러.

전제:
- Android Studio AVD (xray_api30), root 가능 (adb root 성공)
- tcpdump 바이너리가 기기에 없을 수 있으므로 static binary를 push하는 옵션 포함
- 캡처 파일은 기기 /data/local/tmp/capture.pcap 에 저장 후 pull

예외는 exceptions.py의 NetworkAnalysisError를 상속한 TcpdumpCaptureError를 사용한다.
(D의 exceptions.py 계약을 그대로 따름 - 다른 모듈과 동일하게 상위에서 한 번에 캐치 가능)
"""

import subprocess
import time
from pathlib import Path

from .exceptions import TcpdumpCaptureError

__all__ = ["TcpdumpCaptureController", "TcpdumpCaptureError"]


class TcpdumpCaptureController:
    DEVICE_TCPDUMP_PATH = "/data/local/tmp/tcpdump"
    DEVICE_PCAP_PATH = "/data/local/tmp/capture.pcap"

    def __init__(self, adb_serial: str | None = None, interface: str = "any", verbose: bool = True):
        """
        adb_serial: 여러 기기/에뮬레이터 연결 시 -s 옵션으로 지정할 시리얼.
                    None이면 단일 기기 가정.
        interface: tcpdump -i 옵션. 보통 any 로 전체 인터페이스 캡처.
        """
        self.adb_serial = adb_serial
        self.interface = interface
        self.verbose = verbose
        self._capture_proc: subprocess.Popen | None = None
        self._remote_pid: str | None = None

    # ---------- 내부 유틸 ----------

    def _adb_base_cmd(self) -> list[str]:
        cmd = ["adb"]
        if self.adb_serial:
            cmd += ["-s", self.adb_serial]
        return cmd

    def _log(self, msg: str):
        if self.verbose:
            print(f"[tcpdump_capture] {msg}")

    def _run(self, args: list[str], check: bool = True, timeout: int = 15) -> subprocess.CompletedProcess:
        full_cmd = self._adb_base_cmd() + args
        self._log(f"$ {' '.join(full_cmd)}")
        result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
        if check and result.returncode != 0:
            raise TcpdumpCaptureError(
                f"명령 실패: {' '.join(full_cmd)}\nstdout={result.stdout}\nstderr={result.stderr}"
            )
        return result

    # ---------- 준비 단계 ----------

    def check_device_connected(self) -> bool:
        result = self._run(["get-state"], check=False)
        ok = result.returncode == 0 and "device" in result.stdout
        if not ok:
            self._log(f"기기 연결 확인 실패: {result.stdout} {result.stderr}")
        return ok

    def wait_for_boot_complete(self, timeout: int = 90, poll_interval: float = 2.0) -> bool:
        """헤드리스(-no-window)로 방금 띄운 직후엔 adb에는 잡혀도 아직 부팅 중일 수 있음."""
        elapsed = 0.0
        while elapsed < timeout:
            result = self._run(["shell", "getprop", "sys.boot_completed"], check=False)
            if result.stdout.strip() == "1":
                self._log(f"부팅 완료 확인 ({elapsed:.0f}s 경과)")
                return True
            time.sleep(poll_interval)
            elapsed += poll_interval
        self._log(f"부팅 완료 대기 타임아웃 ({timeout}s)")
        return False

    def check_tcpdump_exists(self) -> bool:
        result = self._run(
            ["shell", f"[ -f {self.DEVICE_TCPDUMP_PATH} ] && echo EXISTS || echo MISSING"],
            check=False,
        )
        return "EXISTS" in result.stdout

    def push_tcpdump_binary(self, local_binary_path: str):
        """static-compiled tcpdump 바이너리를 기기에 push."""
        local = Path(local_binary_path)
        if not local.exists():
            raise TcpdumpCaptureError(f"로컬 tcpdump 바이너리를 찾을 수 없음: {local_binary_path}")

        self._run(["push", str(local), self.DEVICE_TCPDUMP_PATH])
        self._run(["shell", f"chmod 755 {self.DEVICE_TCPDUMP_PATH}"])
        self._log("tcpdump 바이너리 push 및 실행 권한 부여 완료")

    def ensure_ready(self, local_tcpdump_binary: str | None = None):
        """캡처 시작 전 필요한 사전 점검을 한 번에 처리."""
        if not self.check_device_connected():
            raise TcpdumpCaptureError("기기가 연결되어 있지 않습니다 (adb devices 확인)")

        if not self.wait_for_boot_complete():
            raise TcpdumpCaptureError("에뮬레이터 부팅이 완료되지 않았습니다 (헤드리스 기동 직후라면 잠시 후 재시도)")

        if not self.check_tcpdump_exists():
            if not local_tcpdump_binary:
                raise TcpdumpCaptureError(
                    "기기에 tcpdump가 없고 로컬 바이너리 경로도 지정되지 않았습니다. "
                    "local_tcpdump_binary 인자로 static binary 경로를 넘겨주세요."
                )
            self.push_tcpdump_binary(local_tcpdump_binary)

    # ---------- 캡처 시작/종료 ----------

    def start(self):
        """백그라운드로 tcpdump 실행. 로컬 subprocess로 붙잡아 종료 시점을 확실히 통제."""
        if self._capture_proc is not None:
            raise TcpdumpCaptureError("이미 캡처가 진행 중입니다")

        cmd = self._adb_base_cmd() + [
            "shell",
            f"{self.DEVICE_TCPDUMP_PATH} -i {self.interface} -w {self.DEVICE_PCAP_PATH}",
        ]
        self._log(f"캡처 시작: {' '.join(cmd)}")
        self._capture_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        time.sleep(1.0)
        check = self._run(["shell", "pidof tcpdump"], check=False)
        if not check.stdout.strip():
            self._capture_proc.terminate()
            self._capture_proc = None
            raise TcpdumpCaptureError(
                "tcpdump가 기기에서 시작되지 않았습니다. 권한(root) 또는 인터페이스명을 확인하세요."
            )
        self._remote_pid = check.stdout.strip().split()[0]
        self._log(f"캡처 시작 확인됨 (remote pid={self._remote_pid})")

    def stop(self, wait: float = 1.0):
        """원격 tcpdump에 SIGTERM을 보내 정상 종료(=pcap 파일 flush)."""
        if self._remote_pid:
            self._run(["shell", f"kill -TERM {self._remote_pid}"], check=False)
            self._log(f"원격 tcpdump(pid={self._remote_pid})에 SIGTERM 전송")

        if self._capture_proc:
            try:
                self._capture_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._capture_proc.terminate()
            self._capture_proc = None

        time.sleep(wait)
        self._remote_pid = None
        self._log("캡처 종료 완료")

    def pull(self, local_path: str) -> str:
        """캡처된 pcap을 호스트로 pull. 반환값은 로컬 저장 경로."""
        local = Path(local_path)
        local.parent.mkdir(parents=True, exist_ok=True)
        self._run(["pull", self.DEVICE_PCAP_PATH, str(local)])
        size = local.stat().st_size
        self._log(f"pcap pull 완료: {local} ({size} bytes)")
        if size == 0:
            raise TcpdumpCaptureError("pull된 pcap 파일 크기가 0바이트입니다 - 캡처 실패 가능성")
        return str(local)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False