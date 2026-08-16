"""
main.py — Android X-Ray 오케스트레이터 (6주차 Day2 골격, 역할1 유예원 담당)

의존성 주의: network_analyzer의 capture.py/scenario_capture.py/dns_parser.py/
sni_parser.py/ip_checker.py/report_builder.py는 아직 `feature/network-analyzer`
브랜치에만 있고 main에는 merge 전이다(6주차_Day1_통합인터페이스_스펙.md 참고).
이 파일을 실행하려면 그 브랜치가 먼저 main에 merge돼 있어야 함 — 역할4의 Day1 작업.

진행상황 콜백(on_progress): 7~8주차 Streamlit 대시보드(pipeline_bridge.py)에서
단계별 진행 표시를 하려고 run_pipeline(..., on_progress=콜백)을 추가했다.
콜백은 (stage: str, status: str) 두 인자를 받는 함수면 된다. stage는
"static"/"dynamic"/"network" 중 하나, status는 "running"이거나 module_status
값(ok/partial/failed/timeout)이다. 안 넘기면(기본값 None) 기존과 동일하게 동작.

실행 순서:
    1. 정적 분석(analyze_static) — 독립적이라 가장 먼저 실행
    2. 동적 분석 + 네트워크 캡처 — 동시 실행. 네트워크 캡처가 Frida 세션과
       동기화돼야 해서(순서가 어긋나면 트래픽을 놓침) 순차 실행하지 않고,
       network_analyzer.scenario_capture.capture_during_scenario()가
       "캡처 시작 -> run_scenario_fn 실행 -> 캡처 종료 -> pull"을 한 번에
       보장하는 구조를 그대로 사용한다.
    3. 위험도 스코어링 — risk_aggregator.aggregate_risk()가 세 모듈의 하위 점수를
       가중평균해 종합 total/level/breakdown을 채운다(실패 모듈은 빼고 재정규화).
    4. 최종 report.json 조립 + 저장

에러/타임아웃 정책 (스펙 문서 3번 항목 그대로 구현):
    - 모듈별 fatal exception(StaticAnalysisError, NetworkAnalysisError)은 개별로
      잡아서 module_status="failed"로 기록하고, 파이프라인 자체는 계속 진행한다.
      한 모듈이 죽어도 report.json은 항상 나온다(부분 리포트 허용).
    - 모듈 내부 타임아웃(decompiler.DEFAULT_TIMEOUT, AdbRunner.timeout 등)은 각
      모듈이 이미 갖고 있으므로 건드리지 않고, 여기서는 stage 단위 outer timeout만
      추가한다 — "코드가 실패한 것"과 "그냥 오래 걸리는 것"을 구분하기 위해
      module_status에 "timeout"을 별도로 둠.
    - outer timeout이 트립됐을 때 내부 adb/frida subprocess가 좀비로 남을 수 있는
      문제 (8주차, 잔버그 f로 수정): 원인은 두 가지였다. (1) `_with_outer_timeout`이
      `with ThreadPoolExecutor() as executor:`를 쓰고 있어서, 타임아웃을 감지해도
      `__exit__`이 `shutdown(wait=True)`를 호출해 실제로는 그 stage가 끝날 때까지
      계속 기다리고 있었다(이름만 "timeout"이었지 진행 시간은 전혀 안 줄었음) —
      `threading.Thread(daemon=True)` + `join(timeout=...)`으로 교체해 진짜로 그
      시점에 포기하고 리턴하게 함. (2) 그렇게 스레드를 포기해도 그 스레드가 잡고
      있던 adb/frida 프로세스 자체는 안 죽으므로, `_run_dynamic_and_network_stage`가
      만든 컨트롤러를 `resource_sink`로 빼내 `_force_cleanup_after_timeout()`이
      타임아웃 시점에 강제로 정리(frida cleanup + adb force-stop/pkill tcpdump)한다.
      스레드 자체를 강제 종료하는 건 여전히 불가능하므로(파이썬의 근본 한계) 완전한
      해결은 아니고, daemon=True라 최소한 메인 프로세스가 그것 때문에 안 끝나는
      일은 없다. stage를 별도 프로세스로 분리하는 근본 해결은 이월 과제로 남김
      (`docs/8주차보고서_B.md` 5-3).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

# app.py/pipeline_bridge.py(대시보드)에서 진행상황 표시에 쓰는 콜백 타입.
# (stage, status) -> None. 예외를 던지면 안 됨 — 아래 _notify()가 방어함.
ProgressCallback = Callable[[str, str], None]

from static_analyzer.analyzer import analyze_static
from static_analyzer.exceptions import StaticAnalysisError

# frida는 동적 분석에만 필요한데 top-level import라서 frida 미설치 PC에서는
# main.py를 import하는 것 자체가 실패했다(B가 PR #2에서 발견 — 정적 분석만
# 돌려보려 해도 막힘). try/except로 감싸서 import 자체는 항상 성공하게 하고,
# 실제로 동적 stage를 실행할 때(_run_dynamic_and_network_stage)만 None 체크로
# 명확한 에러를 낸다. FridaController 등을 여기 모듈 레벨 이름으로 유지하는
# 이유는 테스트 코드가 main.FridaController = FakeController 식으로 몽키패치
# 하기 때문 — 함수 안에서 지연 import하면 그 패치가 안 먹는다.
try:
    from dynamic_analyzer.frida_controller import FridaController
    from dynamic_analyzer.adb_runner import AdbRunner
    from dynamic_analyzer.scenario_runner import ScenarioRunner
except ImportError as _e:  # noqa: N818
    FridaController = None
    AdbRunner = None
    ScenarioRunner = None
    _DYNAMIC_IMPORT_ERROR: Optional[Exception] = _e
else:
    _DYNAMIC_IMPORT_ERROR = None

from dynamic_analyzer.scenarios import Scenario, LAUNCH_ONLY

from network_analyzer.scenario_capture import capture_during_scenario
from network_analyzer.dns_parser import parse_dns
from network_analyzer.sni_parser import parse_sni
from network_analyzer.report_builder import build_network_report
from network_analyzer.exceptions import NetworkAnalysisError

from risk_aggregator import aggregate_risk


# ── 모듈별 outer timeout (초) ──
STATIC_STAGE_TIMEOUT_SEC = 300              # apktool/jadx 디컴파일 포함 여유있게
DYNAMIC_NETWORK_STAGE_TIMEOUT_SEC = 240     # observe_after_sec + margin 여유


@dataclass
class ModuleResult:
    status: str                              # "ok" | "partial" | "failed" | "timeout"
    data: Optional[dict] = None
    error: Optional[str] = None
    extra: dict = field(default_factory=dict)  # crashed 여부 등 모듈별 부가 정보

    def to_dict(self) -> dict:
        d = {"status": self.status, "data": self.data, "error": self.error}
        d.update(self.extra)
        return d


def _with_outer_timeout(fn, timeout_sec: float, *args, **kwargs):
    """stage 전체에 outer timeout을 건다. 반환값이 문자열 "TIMEOUT"이면 트립된 것.

    수정 이력 (8주차, 잔버그 f — 좀비 프로세스의 실제 원인): 원래 이 함수는
    `with ThreadPoolExecutor() as executor:`로 되어 있었다. `future.result(timeout=...)`가
    타임아웃을 던지는 것까지는 맞는데, `with` 블록을 빠져나갈 때
    `ThreadPoolExecutor.__exit__`이 내부적으로 `shutdown(wait=True)`를 호출한다 —
    즉 이 함수가 실제로 "TIMEOUT"을 리턴하기 전에 **그 작업이 실제로 끝날 때까지
    그대로 기다리고 있었다.** 라벨만 나중에 "timeout"으로 다르게 찍힐 뿐 파이프라인
    진행 시간은 전혀 줄지 않는 이름뿐인 타임아웃이었던 것 — adb 명령 하나가 응답
    없이 계속 걸려있으면 run_pipeline() 자체가, 그리고 CLI로 돌렸다면 python
    프로세스 자체가 그 명령이 끝날 때까지(응답이 없으면 영원히) 안 끝났다.

    파이썬 스레드는 강제 종료가 안 되므로 여기서 할 수 있는 건 "기다리는 것을
    멈추는 것"뿐이다. `threading.Thread(daemon=True)`로 띄우면 그 스레드가 끝내
    안 끝나도(예: adb 명령이 정말 응답을 안 주면) 최소한 프로세스 종료 시 그
    스레드 때문에 block되지는 않는다. 다만 이 함수 자체는 스레드 안에서 실제로
    붙잡고 있던 adb/frida 리소스를 모르므로 그건 못 죽인다 — 그건 호출부
    (run_pipeline)가 `_force_cleanup_after_timeout()`으로 "알려진" 리소스만 따로
    정리한다.
    """
    result_box: list = []

    def _target():
        try:
            result_box.append(("ok", fn(*args, **kwargs)))
        except Exception as e:  # noqa: BLE001 — 백그라운드 스레드 예외는 그대로 못 던지니 담아뒀다가 다시 던진다
            result_box.append(("error", e))

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout=timeout_sec)
    if thread.is_alive():
        return "TIMEOUT"

    kind, payload = result_box[0]
    if kind == "error":
        raise payload
    return payload


def _force_cleanup_after_timeout(
    package_name: Optional[str], controller: Optional["FridaController"]
) -> None:
    """dynamic+network stage가 outer timeout으로 트립된 뒤, 그 안에서 실행되던
    백그라운드 스레드가 잡고 있었을 adb/frida 리소스를 최선을 다해 정리한다.

    스레드 자체를 죽이는 게 아니라 걔가 쓰던 "이름이 알려진" 핸들만 다른 스레드에서
    가로채 끊는 것이다 — FridaController.cleanup()의 각 단계는 이미 개별
    try/except로 감싸져 있어 원래 스레드와 여기가 동시에 같은 컨트롤러를 건드려도
    최악의 경우 조용히 실패할 뿐 예외가 위로 새지 않는다. adb 레벨 강제 종료는
    frida cleanup이 이미 처리했어도 중복 호출이 안전하다(이미 없는 프로세스에
    force-stop/pkill은 그냥 아무 일도 안 하고 끝난다).

    완전한 해결은 아니다 — 스레드 자체가 진짜로 응답 없는 adb 호출 하나에 영원히
    막혀 있으면 그 스레드는 프로세스가 끝날 때까지 살아있는다(daemon=True라
    최소한 메인 프로세스 종료는 막지 않는다). 근본적으로 stage를 별도 프로세스로
    분리해서 강제 종료 가능하게 만드는 건 Day2 골격 이상의 리팩터라 이월 과제로
    남긴다(`docs/8주차보고서_B.md` 5-3).
    """
    if controller is not None:
        try:
            controller.cleanup()
        except Exception:  # noqa: BLE001 — 정리 실패가 파이프라인을 죽이면 안 됨
            pass

    if package_name:
        try:
            subprocess.run(
                ["adb", "shell", "am", "force-stop", package_name],
                capture_output=True, timeout=10,
            )
        except Exception:  # noqa: BLE001 — adb 미설치/기기 없음 등, 정리는 최선만 다한다
            pass

    try:
        subprocess.run(
            ["adb", "shell", "pkill", "-f", "tcpdump"],
            capture_output=True, timeout=10,
        )
    except Exception:  # noqa: BLE001
        pass


def _notify(on_progress: Optional[ProgressCallback], stage: str, status: str) -> None:
    """on_progress 콜백을 안전하게 호출한다. 콜백이 없거나(None) 콜백 자체에서
    예외가 나도 파이프라인 실행에는 영향 없게 방어한다 — 대시보드 쪽 버그가
    분석 파이프라인을 죽이면 안 되기 때문."""
    if on_progress is None:
        return
    try:
        on_progress(stage, status)
    except Exception:  # noqa: BLE001 — 진행상황 표시 실패는 무시하고 계속 진행
        pass


# ────────────────────────────────────────────────────────────
# 1. 정적 분석 stage
# ────────────────────────────────────────────────────────────

def _run_static_stage(apk_path: str, work_dir: str) -> ModuleResult:
    """analyze_static()의 기존 규약을 그대로 존중한다: apk 자체가 없거나 apktool/jadx가
    실패하면 StaticAnalysisError(치명적)를 던지고, 그 외 6개 하위 분석 중 일부 실패는
    예외 없이 result["errors"]에 쌓인 채 정상 반환된다.

    주의: B(왕은서)가 feature/static-adapter 브랜치에 만든 to_static_report()(1주차
    레거시 schemas/static_report.schema.json 4필드로 변환하는 어댑터)는 여기서 의도적으로
    쓰지 않는다. 이 오케스트레이터는 analyze_static() 원본을 필드 개수와 무관하게
    변환 없이 그대로 통과시키는 정책이라(원래 8필드였다가 D의 risk_breakdown이
    추가되며 9필드가 된 것처럼 필드가 늘어나도 main.py는 코드 수정이 필요 없다),
    certificate/code_analysis/strings/third_party_sdks도 자동으로 살아남고, risk_score
    실패 시에도 0.0으로 강제하지 않고 None + module_status="partial"로 그대로 드러난다.
    다만 B가 원천 코드(manifest_parser.py의 intent_filters 수집, meta.apk_name/
    analyzed_at)에 넣은 개선사항은 그대로 이 원본 안에 포함되어 이득을 본다."""
    try:
        result = analyze_static(apk_path, work_dir)
    except StaticAnalysisError as e:
        return ModuleResult(status="failed", error=f"StaticAnalysisError: {e}")
    except FileNotFoundError as e:
        # analyze_static()의 docstring에 명시된 예상된 케이스(apk_path가 없음).
        # StaticAnalysisError가 아니라서 원래는 아래 except Exception의 "예상치
        # 못한 에러"로 뭉뚱그려졌었다(B가 PR #2에서 지적) — 로그 읽을 때
        # 구분되게 따로 잡는다.
        return ModuleResult(status="failed", error=f"apk 파일을 찾을 수 없음: {e}")
    except Exception as e:  # noqa: BLE001 — 예상 못한 에러도 파이프라인을 죽이지 않음
        return ModuleResult(status="failed", error=f"예상치 못한 에러: {e}")

    status = "ok" if not result.get("errors") else "partial"
    return ModuleResult(status=status, data=result)


# ────────────────────────────────────────────────────────────
# 2. 동적 분석 + 네트워크 캡처 stage (동시 실행)
# ────────────────────────────────────────────────────────────

def _build_scenario(package_name: str, template: Scenario = LAUNCH_ONLY) -> Scenario:
    """LAUNCH_ONLY 등 시나리오 템플릿의 package_name을 실제 분석 대상 apk의
    package_name으로 교체한다. scenarios.py의 LOGIN_FLOW/PERMISSION_REQUEST는
    좌표가 아직 플레이스홀더(__TARGET_PACKAGE__)라 정상 앱 1개 e2e 목표에는
    좌표 불필요한 LAUNCH_ONLY를 기본값으로 쓴다."""
    return replace(template, package_name=package_name)


def _run_dynamic_and_network_stage(
    package_name: str,
    scenario: Scenario,
    hooks_js_path: str,
    output_pcap_path: str,
    observe_after_sec: float,
    resource_sink: Optional[dict] = None,
) -> tuple[ModuleResult, ModuleResult]:
    """capture_during_scenario()가 캡처 시작 -> 시나리오 실행 -> 캡처 종료 순서를
    이미 보장하므로, 오케스트레이터가 따로 스레드를 나눠 병렬 실행할 필요 없이
    이 함수 하나만 부르면 동기화가 된다.

    resource_sink (8주차, 잔버그 f): outer timeout이 트립됐을 때 run_pipeline이
    이 함수가 만든 `controller`를 강제로 정리(cleanup)할 수 있도록, 만들어지는
    즉시(연결까지 끝난 뒤) 넘겨받은 dict에 채워 넣는다. 이 함수는 자기 스레드
    안에서만 실행되므로 다른 스레드가 이 dict를 읽어도 안전하다(그냥 참조 하나
    꺼내가는 것). None이면(main() CLI 등 기존 호출부) 그냥 아무 일도 안 한다 —
    하위 호환 유지."""
    if FridaController is None:
        err = f"동적 분석 모듈 import 실패 (frida 미설치 환경으로 보임): {_DYNAMIC_IMPORT_ERROR}"
        return ModuleResult(status="failed", error=err), ModuleResult(status="failed", error=err)

    try:
        controller = FridaController()
        adb = AdbRunner()
        runner = ScenarioRunner(controller, adb, hooks_js_path=hooks_js_path)
        controller.connect()
    except Exception as e:
        err = f"Frida 연결 실패: {e}"
        return ModuleResult(status="failed", error=err), ModuleResult(status="failed", error=err)

    if resource_sink is not None:
        resource_sink["controller"] = controller

    try:
        capture_meta, scenario_result = capture_during_scenario(
            package_name=package_name,
            output_pcap_path=output_pcap_path,
            # report_dir="output" — C(김은아)가 6주차에 dynamic_report.json 저장 위치를
            # output/ 폴더로 통일했다고 공유함(2026-08-02). network 쪽 output_pcap_path
            # 기본값과도 맞춘다.
            run_scenario_fn=lambda: runner.run_scenario(
                scenario, observe_after_sec=observe_after_sec, report_dir="output"
            ),
        )
    except NetworkAnalysisError as e:
        err = f"NetworkAnalysisError(캡처 단계): {e}"
        return ModuleResult(status="failed", error=err), ModuleResult(status="failed", error=err)
    except Exception as e:
        err = f"예상치 못한 에러(캡처+시나리오 단계): {e}"
        return ModuleResult(status="failed", error=err), ModuleResult(status="failed", error=err)

    dynamic_result = _build_dynamic_result(scenario_result)
    network_result = _build_network_result(capture_meta)
    return dynamic_result, network_result


def _build_dynamic_result(scenario_result: Any) -> ModuleResult:
    """ScenarioResult(success/crashed/error/report)를 ModuleResult로 변환.
    report가 None이면(크래시 등으로 못 만든 경우) failed, report는 있는데
    report["errors"]가 비어있지 않으면 partial, 그 외엔 ok."""
    if scenario_result is None:
        return ModuleResult(status="failed", error="시나리오 실행 결과 없음")

    crashed = getattr(scenario_result, "crashed", False)
    error = getattr(scenario_result, "error", None)
    report = getattr(scenario_result, "report", None)

    if report is None:
        status = "failed"
    elif report.get("errors"):
        status = "partial"
    else:
        status = "ok"

    return ModuleResult(status=status, data=report, error=error, extra={"crashed": crashed})


def _build_network_result(capture_meta: dict) -> ModuleResult:
    """pcap 경로를 받아서 dns_parser/sni_parser로 파싱하고 report_builder로 최종
    NetworkAnalysisResult를 조립한다. pcap pull 자체가 실패했으면(capture_meta.pcap_file
    이 None) 파싱을 시도하지 않고 바로 failed 처리."""
    pcap_file = capture_meta.get("pcap_file")
    if not pcap_file:
        return ModuleResult(
            status="failed",
            error="pcap pull 실패 (capture_meta.pcap_file이 None)",
            data={"meta": capture_meta},
        )

    try:
        dns_queries = parse_dns(pcap_file)
        tls_sni = parse_sni(pcap_file)
        network_report = build_network_report(capture_meta, dns_queries, tls_sni)
        return ModuleResult(status="ok", data=network_report)
    except Exception as e:
        return ModuleResult(
            status="failed",
            error=f"DNS/SNI 파싱 또는 조립 실패: {e}",
            data={"meta": capture_meta},
        )


# ────────────────────────────────────────────────────────────
# 3. 전체 파이프라인
# ────────────────────────────────────────────────────────────

def run_pipeline(
    apk_path: str,
    work_dir: str = "work",
    hooks_js_path: str = "src/dynamic_analyzer/hooks.bundle.js",
    output_pcap_path: str = "output/capture.pcap",
    observe_after_sec: float = 8.0,
    scenario_template: Scenario = LAUNCH_ONLY,
    on_progress: Optional[ProgressCallback] = None,
) -> dict:
    """전체 파이프라인 실행. 항상 dict(통합 report.json 형태)를 반환하고, 일부
    모듈이 실패해도 예외를 던지지 않는다 — 부분 리포트를 허용하는 게 정책이다.

    on_progress: (stage, status) -> None 형태의 선택적 콜백. stage는
    "static"/"dynamic"/"network", status는 "running" 또는 module_status값
    (ok/partial/failed/timeout). 대시보드(pipeline_bridge.py)에서 진행상황
    표시용으로 씀 — CLI 실행(main())에서는 안 넘기므로 동작 그대로다.

    timings (8주차 계획수정 PDF, 역할1 유예원 담당): B가 설계하는 "수동 대비 시간
    단축" 정량화 프로토콜에 자동 측정치를 공급하기 위해 stage별 소요시간을 잰다.
    사람이 손으로 재던 것을 대체하는 게 목적이라 수동 측정과 같은 기준(벽시계 시간,
    outer timeout 대기까지 포함)으로 재야 해서 time.perf_counter()를 stage 진입
    직전~직후에 바로 감싼다(모듈 내부에 계측을 넣지 않음 — 세 모듈 각자 건드리지
    않고 오케스트레이터 한 곳에서만 재는 게 유지보수에 유리하다).

    동적+네트워크 단계가 건너뛰어진 경우(정적 분석 실패로 package_name이 없음)
    dynamic_network_sec은 0이 아니라 None이다 — 이 저장소의 원칙("관측 없음은
    위험 없음이 아니다")과 같은 이유로, "0초 걸림"과 "애초에 안 돌았음"을
    구분해야 B의 배수 계산이 왜곡되지 않는다."""

    pipeline_start = time.perf_counter()
    analyzed_at = datetime.now(timezone.utc).isoformat()

    # 1. 정적 분석 (독립적, 먼저 실행)
    _notify(on_progress, "static", "running")
    static_start = time.perf_counter()
    static_out = _with_outer_timeout(_run_static_stage, STATIC_STAGE_TIMEOUT_SEC, apk_path, work_dir)
    static_sec = time.perf_counter() - static_start
    static_result = (
        ModuleResult(status="timeout", error=f"{STATIC_STAGE_TIMEOUT_SEC}s 초과")
        if static_out == "TIMEOUT" else static_out
    )
    _notify(on_progress, "static", static_result.status)

    # package_name은 정적 분석 meta에서 가져온다 — 동적/네트워크가 분석해야 할
    # 대상과 정적 분석 대상이 같은 apk/패키지라는 전제.
    package_name = None
    if static_result.data:
        package_name = static_result.data.get("meta", {}).get("package_name")

    dynamic_network_sec: Optional[float] = None
    if package_name is None:
        msg = "package_name을 구할 수 없어 동적/네트워크 단계 실행 안 함 (정적 분석 실패)"
        dynamic_result = ModuleResult(status="failed", error=msg)
        network_result = ModuleResult(status="failed", error=msg)
        _notify(on_progress, "dynamic", "failed")
        _notify(on_progress, "network", "failed")
    else:
        _notify(on_progress, "dynamic", "running")
        _notify(on_progress, "network", "running")
        scenario = _build_scenario(package_name, scenario_template)
        resource_sink: dict = {}
        dynamic_network_start = time.perf_counter()
        stage_out = _with_outer_timeout(
            _run_dynamic_and_network_stage,
            DYNAMIC_NETWORK_STAGE_TIMEOUT_SEC,
            package_name, scenario, hooks_js_path, output_pcap_path, observe_after_sec,
            resource_sink=resource_sink,
        )
        dynamic_network_sec = time.perf_counter() - dynamic_network_start
        if stage_out == "TIMEOUT":
            timeout_msg = f"{DYNAMIC_NETWORK_STAGE_TIMEOUT_SEC}s 초과"
            # 잔버그 f: 타임아웃이 트립되면 백그라운드 스레드는 계속 남아있을 수
            # 있으니, 그 스레드가 만들어둔(있다면) frida 컨트롤러 + 알려진 adb
            # 프로세스명(패키지, tcpdump)을 여기서 최선을 다해 강제로 정리한다.
            _force_cleanup_after_timeout(package_name, resource_sink.get("controller"))
            dynamic_result = ModuleResult(status="timeout", error=timeout_msg)
            network_result = ModuleResult(status="timeout", error=timeout_msg)
        else:
            dynamic_result, network_result = stage_out
        _notify(on_progress, "dynamic", dynamic_result.status)
        _notify(on_progress, "network", network_result.status)

    # 2. 위험도 스코어링 — 정적/동적/네트워크 하위 점수를 가중평균해 종합 점수 산정.
    #    risk_aggregator가 부분 리포트(모듈 실패)도 알아서 처리하므로 여기서는 그대로 넘긴다.
    modules = {
        "static": static_result.to_dict(),
        "dynamic": dynamic_result.to_dict(),
        "network": network_result.to_dict(),
    }
    risk_score = aggregate_risk(modules)

    total_sec = time.perf_counter() - pipeline_start
    timings = {
        "static_sec": round(static_sec, 3),
        "dynamic_network_sec": round(dynamic_network_sec, 3) if dynamic_network_sec is not None else None,
        "total_sec": round(total_sec, 3),
    }

    return {
        "apk_name": Path(apk_path).name,
        "package_name": package_name,
        "analyzed_at": analyzed_at,
        "modules": modules,
        "risk_score": risk_score,
        "timings": timings,
    }


def main():
    parser = argparse.ArgumentParser(description="Android X-Ray 파이프라인 실행")
    parser.add_argument("apk_path", help="분석 대상 .apk 경로")
    parser.add_argument("--work-dir", default="work")
    parser.add_argument("--hooks-js", default="src/dynamic_analyzer/hooks.bundle.js")
    parser.add_argument("--output-pcap", default="output/capture.pcap")
    parser.add_argument("--observe-sec", type=float, default=8.0)
    parser.add_argument("--output", default="report.json")
    parser.add_argument("--verbose", action="store_true",
                        help="androguard 등 라이브러리 DEBUG 로그까지 전부 출력")
    args = parser.parse_args()

    if not args.verbose:
        _silence_third_party_logs()

    report = run_pipeline(
        apk_path=args.apk_path,
        work_dir=args.work_dir,
        hooks_js_path=args.hooks_js,
        output_pcap_path=args.output_pcap,
        observe_after_sec=args.observe_sec,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    _print_summary(report, args.output)


# 화면(대시보드)과 같은 규칙으로 CLI 출력도 두 층으로 나눈다 — 여기서만 "status=ok"로
# 뭉뚱그리면 터미널에서 돌린 사람은 여전히 "ok = 안전"으로 읽는다.
# 라벨 표는 common.py에도 같은 것이 있지만, src/main.py는 대시보드(저장소 루트)에
# 의존하지 않아야 해서(파이프라인만 단독 실행 가능) 여기 따로 둔다.
_STATUS_LABELS = {
    "ok": "분석 성공",
    "partial": "부분 성공",
    "failed": "분석 실패",
    "timeout": "시간 초과",
}
_MODULE_LABELS = {"static": "정적 분석", "dynamic": "동적 분석", "network": "네트워크 분석"}
_VERDICT_LABELS = {
    "normal": "🟢 정상 (NORMAL)",
    "caution": "🟡 주의 (CAUTION)",
    "suspicious": "🟠 의심 (SUSPICIOUS)",
    "high_risk": "🔴 고위험 (HIGH RISK)",
    "malicious": "⛔ 악성 (MALICIOUS)",
    "unknown": "⚪ 판정 불가 (UNDETERMINED)",
}
DISCLAIMER = (
    "본 결과는 정적·동적·네트워크 분석에서 관찰된 보안 위험 지표를 기반으로 산출된 "
    "위험도이며, 악성 여부를 단독으로 확정하지 않습니다."
)


def _pad_ko(text: str, width: int) -> str:
    """한글은 터미널에서 두 칸을 차지하므로 len()으로 정렬하면 어긋난다.
    east_asian_width가 W/F인 문자를 2칸으로 세서 실제 표시 폭을 맞춘다."""
    import unicodedata

    shown = sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in text)
    return text + " " * max(0, width - shown)


def _silence_third_party_logs() -> None:
    """androguard(loguru)의 DEBUG 로그를 끈다.

    APK 하나를 분석하면 AXML 파서가 수천 줄을 찍어서 정작 필요한 결과 요약이
    스크롤 위로 밀려 올라간다(8주차 로컬 실행에서 확인). CLI 기본값은 조용히,
    필요하면 --verbose로 되살린다. 라이브러리로 import될 때는 호출되지 않게
    main()에서만 부른다 — 남의 로깅 설정을 마음대로 끄지 않기 위함.
    """
    try:
        from loguru import logger
    except ImportError:
        return
    logger.remove()


def _print_summary(report: dict, output_path: str) -> None:
    risk = report.get("risk_score") or {}
    verdict = risk.get("verdict") or {}
    code = verdict.get("code") or risk.get("level") or "unknown"
    score100 = risk.get("score100")

    print("\n" + "=" * 52)
    print("  APK 보안 분석 결과")
    print("=" * 52)
    print(f"  판정        {_VERDICT_LABELS.get(code, code)}")
    print(f"  종합 위험도  {score100 if score100 is not None else '—'} / 100")

    print("\n-- 분석 상태 (앱의 안전 여부가 아니라 실행 성공 여부) --")
    for name, mod in report["modules"].items():
        label = _MODULE_LABELS.get(name, name)
        status = _STATUS_LABELS.get(mod["status"], mod["status"])
        print(f"  {_pad_ko(label, 16)}{status}")
        if mod.get("error"):
            print(f"    └ {mod['error']}")

    indicators = risk.get("indicators") or {}
    print("\n-- 위험 지표 (관찰된 사실) --")
    any_ind = False
    for name in ("static", "dynamic", "network"):
        for ind in indicators.get(name) or []:
            mark = "⚠" if ind.get("strong") else "·"
            print(f"  {mark} [{_MODULE_LABELS.get(name, name)}] {ind['label']}: {ind['value']}")
            any_ind = True
    if not any_ind:
        print("  (관찰된 위험 지표 없음 — '안전함'을 뜻하지는 않음)")

    breakdown_modules = (risk.get("breakdown") or {}).get("modules") or {}
    unavailable = (risk.get("breakdown") or {}).get("unavailable") or []
    if unavailable:
        # 분석 실패로 빠진 것과 "분석은 됐는데 관측된 게 없어서" 빠진 것을 구분한다.
        parts = []
        for n in unavailable:
            label = _MODULE_LABELS.get(n, n)
            reason = (breakdown_modules.get(n) or {}).get("reason_ko")
            parts.append(f"{label}({reason})" if reason else label)
        excluded = ", ".join(parts)
        # 세 모듈이 전부 빠졌으면 "남은 모듈끼리 재정규화"할 대상 자체가 없다.
        tail = " (남은 모듈끼리 가중치 재정규화)" if len(unavailable) < 3 else " — 점수 산정 불가"
        print(f"\n  ※ 점수에서 제외된 모듈: {excluded}{tail}")

    rule = verdict.get("malicious_rule") or {}
    if rule and not rule.get("met") and score100 is not None:
        print(
            f"\n  ※ '악성' 미표시: 점수 {rule['min_score']}점 이상 그리고 강한 지표 "
            f"{rule['min_indicators']}개 이상을 둘 다 충족해야 함 "
            f"(현재 {score100}점 / 강한 지표 {rule.get('strong_indicator_count', 0)}개)"
        )

    timings = report.get("timings") or {}
    if timings:
        dn_sec = timings.get("dynamic_network_sec")
        dn_display = f"{dn_sec:.2f}s" if dn_sec is not None else "건너뜀 (정적 실패)"
        print("\n-- 소요 시간 --")
        print(f"  정적 분석        {timings.get('static_sec', 0):.2f}s")
        print(f"  동적+네트워크    {dn_display}")
        print(f"  전체             {timings.get('total_sec', 0):.2f}s")

    print(f"\n  ⚠ {DISCLAIMER}")
    print(f"\n최종 리포트 저장: {output_path}")


if __name__ == "__main__":
    main()
