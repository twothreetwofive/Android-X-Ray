"""network_analyzer/scenario_capture.py
Android X-Ray - Role A (scenario_runner.py 동기화 + CaptureMeta 생성)

D의 scenario_runner.py(ScenarioRunner.run_scenario)를 확인해서 맞췄다.
- ScenarioRunner는 이미 FridaController/AdbRunner를 물고 구성된 상태로 넘어온다
  (network_analyzer가 dynamic_analyzer 내부를 직접 임포트/구성할 필요 없음)
- run_scenario()는 package_name 문자열이 아니라 Scenario 객체를 받고
  ScenarioResult(success, crashed, error, report)를 반환한다

그래서 이 모듈은 "인자 없는 콜러블(run_scenario_fn)"만 받는다.
호출하는 쪽(D 또는 통합 스크립트)이 이미 구성된 runner와 scenario를
람다/클로저로 감싸서 넘겨주면 됨:
    run_scenario_fn=lambda: runner.run_scenario(scenario)
-> network_analyzer는 dynamic_analyzer의 클래스/시그니처가 바뀌어도 영향받지 않는다.

이 모듈이 하는 일 (schema.py 계약 준수):
- 캡처 시작 -> run_scenario_fn() 실행 -> 캡처 종료 -> pull
- schema.CaptureMeta 4개 필드(package_name, capture_started_at,
  capture_duration_sec, pcap_file)를 채워서 반환한다.
- 동시에 run_scenario_fn()의 반환값(ScenarioResult 등)도 그대로 같이 반환해서
  호출 쪽이 크래시/성공 여부를 알 수 있게 한다.

동기화 원칙:
1. tcpdump가 "완전히 시작된 것"을 확인(pidof)한 다음에 시나리오 실행
2. 시나리오 종료 후 flush 대기 시간(margin)을 두고 캡처 종료
   (run_scenario 내부에서 이미 observe_after_sec만큼 대기하지만,
    네트워크 패킷은 그보다 더 늦게 도착할 수 있어 margin을 별도로 둔다)
3. 예외 발생 시에도 반드시 캡처가 종료되고 pcap이 pull되도록 try/finally 보장
"""

from __future__ import annotations

import time
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Tuple

from .capture import TcpdumpCaptureController
from .schema import CaptureMeta


def _default_scenario_fn() -> None:
    """run_scenario_fn을 안 넘겼을 때 쓰는 더미 (단독 테스트용)."""
    print("[scenario_capture] run_scenario_fn이 지정되지 않아 8초 대기로 대체합니다")
    time.sleep(8)


def capture_during_scenario(
    package_name: str,
    output_pcap_path: str,
    run_scenario_fn: Callable[[], Any] = _default_scenario_fn,
    adb_serial: Optional[str] = None,
    post_scenario_margin: float = 3.0,
) -> Tuple[CaptureMeta, Any]:
    """
    캡처 시작 -> run_scenario_fn() 실행 -> 캡처 종료 -> pull.

    사용 예 (D의 ScenarioRunner와 연결):
        controller = FridaController(); controller.connect()
        adb = AdbRunner()
        runner = ScenarioRunner(controller, adb, hooks_js_path="src/dynamic_analyzer/hooks.bundle.js")

        meta, scenario_result = capture_during_scenario(
            package_name=LAUNCH_ONLY.package_name,
            output_pcap_path="./output/capture.pcap",
            run_scenario_fn=lambda: runner.run_scenario(LAUNCH_ONLY),
        )

    반환값:
        (CaptureMeta, run_scenario_fn()의 반환값)
        - meta는 schema.CaptureMeta 형태 그대로 -> D가 meta 필드에 바로 사용
        - 두 번째 값은 run_scenario_fn이 ScenarioResult를 반환했다면 그대로 담겨서 나옴
          (여기서 dynamic_analyzer.ScenarioResult를 직접 import하지 않으므로 타입은 Any)
    """
    controller = TcpdumpCaptureController(adb_serial=adb_serial, verbose=True)

    started_at = datetime.now(timezone.utc)
    start_ts = time.monotonic()
    pcap_path: Optional[str] = None
    scenario_result: Any = None

    try:
        controller.ensure_ready(local_tcpdump_binary=None)  # 최초 1회 push는 별도로 완료했다고 가정
        controller.start()

        try:
            scenario_result = run_scenario_fn()
        except Exception:
            print("[scenario_capture] 시나리오 실행 중 예외 발생, 캡처는 계속 종료 처리합니다:")
            traceback.print_exc()

        print(f"[scenario_capture] flush 대기 {post_scenario_margin}s...")
        time.sleep(post_scenario_margin)

    finally:
        controller.stop()

    duration_sec = int(time.monotonic() - start_ts)

    try:
        pcap_path = controller.pull(output_pcap_path)
    except Exception:
        print("[scenario_capture] pcap pull 실패 - meta.pcap_file은 None으로 기록됩니다:")
        traceback.print_exc()
        pcap_path = None

    meta: CaptureMeta = {
        "package_name": package_name,
        "capture_started_at": started_at.isoformat(timespec="seconds"),
        "capture_duration_sec": duration_sec,
        "pcap_file": pcap_path,
    }
    return meta, scenario_result


if __name__ == "__main__":
    # 실제 통합 시 이렇게 D의 scenario_runner와 연결한다
    from src.dynamic_analyzer.frida_controller import FridaController
    from src.dynamic_analyzer.adb_runner import AdbRunner
    from src.dynamic_analyzer.scenario_runner import ScenarioRunner
    from src.dynamic_analyzer.scenarios import LAUNCH_ONLY

    controller = FridaController()
    controller.connect()
    adb = AdbRunner()
    runner = ScenarioRunner(controller, adb, hooks_js_path="src/dynamic_analyzer/hooks.bundle.js")

    result_meta, scenario_result = capture_during_scenario(
        package_name=LAUNCH_ONLY.package_name,
        output_pcap_path="./output/capture.pcap",
        run_scenario_fn=lambda: runner.run_scenario(LAUNCH_ONLY),
    )

    print("CaptureMeta:", result_meta)
    print("Scenario success:", getattr(scenario_result, "success", None))
    print("Scenario crashed:", getattr(scenario_result, "crashed", None))
    print("Scenario error:", getattr(scenario_result, "error", None))
    print("B/C에게 전달 준비 완료 -> dns_parser.py / sni_parser.py 입력으로 사용 가능")
    
    
    