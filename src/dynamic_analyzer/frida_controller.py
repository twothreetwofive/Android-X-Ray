""" [A] Frida 세션 관리 모듈 """

from __future__ import annotations

import time
import frida


class FridaController:
    def __init__(self, max_retries: int = 3, retry_delay: float = 2.0):
        self.device: frida.core.Device | None = None
        self.session: frida.core.Session | None = None
        self.pid: int | None = None
        self.script: frida.core.Script | None = None
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def connect(self) -> None:
        """frida-server에 연결한다. 실패하면 재시도."""
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                self.device = frida.get_usb_device(timeout=5)
                return
            except (frida.TimedOutError, frida.ServerNotRunningError) as e:
                last_error = e
                print(f"[재시도 {attempt}/{self.max_retries}] 연결 실패: {e}")
                time.sleep(self.retry_delay)
        raise RuntimeError(f"frida-server 연결 {self.max_retries}회 실패: {last_error}")
    
    def spawn_and_attach(self, package_name: str) -> int:
        """앱을 정지 상태로 띄우고 그 프로세스에 붙는다. 실패하면 재시도."""
        if self.device is None:
            raise RuntimeError("connect()를 먼저 호출해야 합니다.")
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                self.pid = self.device.spawn([package_name])
                self.session = self.device.attach(self.pid)
                return self.pid
            except Exception as e:
                last_error = e
                print(f"[재시도 {attempt}/{self.max_retries}] spawn 실패 ({package_name}): {e}")
                time.sleep(self.retry_delay)
        raise RuntimeError(f"{package_name} spawn {self.max_retries}회 실패: {last_error}")

    def load_script(self, js_path: str) -> None:
        """후킹 스크립트를 세션에 로드한다. (resume 전에 호출해야 함)"""
        if self.session is None:
            raise RuntimeError("attach 또는 spawn_and_attach()를 먼저 호출해야 합니다.")
        with open(js_path, "r", encoding="utf-8") as f:
            source = f.read()
        self.script = self.session.create_script(source)
        self.script.on("message", self._on_message)
        self.script.load()

    def _on_message(self, message: dict, data) -> None:
        """스크립트에서 온 메시지(console.log, send() 등)를 출력한다."""
        print("[스크립트 메시지]", message)

    def resume(self) -> None:
        """정지된 프로세스를 실행 재개한다. 반드시 load_script() 다음에 호출."""
        if self.device is None or self.pid is None:
            raise RuntimeError("spawn_and_attach()를 먼저 호출해야 합니다.")
        self.device.resume(self.pid)

    def _cleanup_current_session(self) -> None:
        """현재 세션/프로세스를 정리한다. 다음 앱 분석 전에 반드시 호출."""
        try:
            if self.script is not None:
                self.script.unload()
        except Exception:
            pass
        try:
            if self.session is not None:
                self.session.detach()
        except Exception:
            pass
        try:
            if self.pid is not None and self.device is not None:
                self.device.kill(self.pid)
        except Exception:
            pass
        self.session = None
        self.pid = None
        self.script = None

    def analyze_app(self, package_name: str, js_path: str, observe_sec: float = 5.0) -> dict:
        """앱 하나를 spawn -> 후킹 -> resume -> 관찰 -> 정리까지 한 번에 처리한다."""
        result = {"package": package_name, "success": False, "error": None, "pid": None}
        try:
            pid = self.spawn_and_attach(package_name)
            self.load_script(js_path)
            self.resume()
            time.sleep(observe_sec)
            result["success"] = True
            result["pid"] = pid
        except Exception as e:
            result["error"] = str(e)
        finally:
            self._cleanup_current_session()
        return result

    def run_batch(self, package_names: list[str], js_path: str, observe_sec: float = 5.0) -> list[dict]:
        """여러 앱을 순차적으로 분석한다."""
        results = []
        for package_name in package_names:
            print(f"=== {package_name} 분석 시작 ===")
            result = self.analyze_app(package_name, js_path, observe_sec)
            status = "성공" if result["success"] else f"실패 - {result['error']}"
            print(f"=== {package_name} 완료: {status} ===")
            results.append(result)
        return results
      
if __name__ == "__main__":
    controller = FridaController()
    controller.connect()
    print("연결된 디바이스:", controller.device.name)

    targets = ["com.google.android.calendar", "com.google.android.deskclock"]  # 실제 설치된 패키지로 교체
    results = controller.run_batch(targets, "hooks.bundle.js", observe_sec=3.0)
    for r in results:
        print(r)