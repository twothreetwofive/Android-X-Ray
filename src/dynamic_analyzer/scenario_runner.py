"""
[D] 실행 시나리오 자동화 모듈 (scenario_runner.py)

A(frida_controller.py) + B(hooks.bundle.js) + C(message_parser.py)를 실제로
엮어서, scenarios.py에 정의된 시나리오(로그인, 권한 요청 등)를 adb로 재현하며
관찰하고 dynamic_report.json을 뽑는다.

역할 분배 원안 기준 진행 상황:
- 1일차: 테스트 시나리오 목록 작성 → scenarios.py
- 2일차: scenario_runner.py 뼈대, adb 자동화 보강 → adb_runner.py
- 3일차: A의 frida_controller.py로 실제 시나리오 자동 실행 테스트 → run_scenario()
- 4일차: 재현성 확인 + 크래시/미실행 대응 → run_scenario_repeated(), _precheck()
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from .adb_runner import AdbRunner
from .frida_controller import FridaController
from .scenarios import Scenario, ScenarioStep
from . import message_parser
from .schema import DynamicAnalysisResult


@dataclass
class ScenarioResult:
    scenario_name: str
    package_name: str
    success: bool
    crashed: bool
    error: Optional[str]
    report: Optional[DynamicAnalysisResult]


class ScenarioRunner:
    def __init__(self, controller: FridaController, adb: AdbRunner, hooks_js_path: str = "hooks.bundle.js"):
        self.controller = controller
        self.adb = adb
        self.hooks_js_path = hooks_js_path

    # ── 엣지 케이스 대응 (4일차) ────────────────────────────────

    def _precheck(self, package_name: str) -> Optional[str]:
        """시나리오 실행 전에 걸러낼 수 있는 실패를 미리 확인.

        None을 반환하면 통과, 문자열을 반환하면 그게 실패 사유.
        """
        if not self.adb.check_device():
            return "디바이스 연결 안 됨 (adb devices에 device 상태 없음)"
        if not self.adb.is_installed(package_name):
            return f"앱 미설치: {package_name}"
        return None

    def _execute_step(self, step: ScenarioStep) -> None:
        if step.action == "wait":
            time.sleep(step.params.get("seconds", 1))
        elif step.action == "tap":
            self.adb.tap(step.params["x"], step.params["y"])
        elif step.action == "swipe":
            self.adb.swipe(step.params["x1"], step.params["y1"], step.params["x2"], step.params["y2"],
                            step.params.get("duration_ms", 300))
        elif step.action == "input_text":
            self.adb.input_text(step.params["text"])
        elif step.action == "press_key":
            self.adb.press_key(step.params["keycode"])
        elif step.action == "grant_permission":
            self.adb.grant_permission(step.params.get("package_name") or "", step.params["permission"])
        else:
            raise ValueError(f"알 수 없는 시나리오 액션: {step.action}")

    def _run_steps_with_crash_check(self, scenario: Scenario) -> bool:
        """스텝 사이사이에 프로세스 생존을 확인한다. 크래시하면 즉시 중단.

        반환값: 크래시 없이 전체 스텝을 다 돌았으면 True.
        """
        for step in scenario.steps:
            # grant_permission은 package_name을 시나리오에서 채워야 하므로 여기서 주입
            if step.action == "grant_permission" and "package_name" not in step.params:
                step.params["package_name"] = scenario.package_name
            self._execute_step(step)
            if not self.adb.is_running(scenario.package_name):
                return False
        return True

    # ── 시나리오 1회 실행 (3일차) ────────────────────────────────

    def run_scenario(self, scenario: Scenario, observe_after_sec: float = 5.0,
                      report_dir: str = ".") -> ScenarioResult:
        precheck_error = self._precheck(scenario.package_name)
        if precheck_error is not None:
            return ScenarioResult(scenario.name, scenario.package_name, False, False, precheck_error, None)

        message_parser.reset_captured_events()
        session_start = datetime.now()
        crashed = False
        error: Optional[str] = None

        try:
            self.controller.spawn_and_attach(scenario.package_name)
            self.controller.load_script(self.hooks_js_path)
            # frida_controller._on_message는 콘솔 출력만 함. C의 message_parser로
            # 실제로 이벤트를 모으려면 별도 리스너를 추가로 건다 (A의 코드는 안 건드림).
            self.controller.script.on("message", message_parser.on_message)
            self.controller.resume()

            if not self.adb.wait_for_process(scenario.package_name, timeout=10.0):
                crashed = True
            else:
                completed = self._run_steps_with_crash_check(scenario)
                if not completed:
                    crashed = True
                else:
                    time.sleep(observe_after_sec)
        except Exception as e:
            error = str(e)
        finally:
            self.controller._cleanup_current_session()

        events = message_parser.get_captured_events()
        report = None
        if events or not crashed:
            output_path = f"{report_dir}/dynamic_report_{scenario.name}_{session_start:%Y%m%dT%H%M%S}.json"
            report = message_parser.build_report(
                package_name=scenario.package_name,
                session_start=session_start,
                raw_events=events,
                output_path=output_path,
            )
        message_parser.reset_captured_events()

        success = error is None and not crashed
        return ScenarioResult(scenario.name, scenario.package_name, success, crashed, error, report)

    # ── 반복 실행으로 재현성 확인 (4일차) ─────────────────────────

    def run_scenario_repeated(self, scenario: Scenario, repeat: int = 3,
                               observe_after_sec: float = 5.0, report_dir: str = ".") -> dict:
        """같은 시나리오를 여러 번 돌려서 매번 비슷한 수의 이벤트가 잡히는지 확인.

        후킹된 값이 실행마다 크게 들쭉날쭉하면(예: 앱 초기화 타이밍 문제,
        스크립트 주입 레이스 컨디션 등) 자동화 신뢰도가 낮다는 신호라서
        재현성 체크가 필요함 — C의 4주차 과제에서 나온 waitForJava 레이스
        컨디션 이슈가 대표적 사례.
        """
        results: List[ScenarioResult] = []
        for i in range(repeat):
            self.adb.force_stop(scenario.package_name)
            result = self.run_scenario(scenario, observe_after_sec=observe_after_sec, report_dir=report_dir)
            results.append(result)

        event_counts = [r.report["total_events_filtered"] for r in results if r.report is not None]
        summary = {
            "scenario_name": scenario.name,
            "runs": repeat,
            "success_count": sum(1 for r in results if r.success),
            "crash_count": sum(1 for r in results if r.crashed),
            "event_counts": event_counts,
            "min_events": min(event_counts) if event_counts else None,
            "max_events": max(event_counts) if event_counts else None,
        }
        return {"summary": summary, "results": results}

    # ── 여러 시나리오 순차 실행 ────────────────────────────────

    def run_batch(self, scenarios: List[Scenario], observe_after_sec: float = 5.0,
                  report_dir: str = ".") -> List[ScenarioResult]:
        results = []
        for scenario in scenarios:
            print(f"=== 시나리오 시작: {scenario.name} ({scenario.package_name}) ===")
            result = self.run_scenario(scenario, observe_after_sec=observe_after_sec, report_dir=report_dir)
            status = "성공" if result.success else ("크래시" if result.crashed else f"실패 - {result.error}")
            print(f"=== 시나리오 종료: {scenario.name} → {status} ===")
            results.append(result)
        return results


if __name__ == "__main__":
    from .scenarios import LAUNCH_ONLY

    controller = FridaController()
    controller.connect()
    print("연결된 디바이스:", controller.device.name)

    adb = AdbRunner()
    runner = ScenarioRunner(controller, adb, hooks_js_path="dynamic_analyzer/hooks.bundle.js")

    # 팀이 지금까지 검증에 써온 calendar 기준 베이스라인 시나리오 재현성 확인
    outcome = runner.run_scenario_repeated(LAUNCH_ONLY, repeat=2, observe_after_sec=3.0)
    print(outcome["summary"])
