"""network_analyzer/pipeline.py (D 작성, 5주차 마무리)

A(capture.py/scenario_capture.py) -> B(dns_parser.py)/C(sni_parser.py) ->
D(report_builder.py)를 하나로 묶는 진입점. static_analyzer.analyzer.analyze_static()과
같은 역할 - 오케스트레이터(추후 main.py)는 이 모듈의 analyze_network() 하나만
import해서 쓰면 된다.
"""

from __future__ import annotations

from typing import Any, Callable, Optional, Tuple

from .dns_parser import parse_dns
from .report_builder import build_network_report
from .schema import NetworkAnalysisResult
from .scenario_capture import capture_during_scenario
from .sni_parser import parse_sni


def analyze_network(
    package_name: str,
    run_scenario_fn: Callable[[], Any],
    output_pcap_path: str = "./output/capture.pcap",
    adb_serial: Optional[str] = None,
) -> Tuple[NetworkAnalysisResult, Any]:
    """캡처 -> DNS/SNI 파싱 -> 화이트리스트/IP 대조까지 한 번에 실행.

    Returns:
        (NetworkAnalysisResult, run_scenario_fn()의 반환값). 후자는 크래시 여부 등
        진단용이라 report_builder.py의 스키마(NetworkAnalysisResult)에는 안 들어간다.

    pcap pull이 실패하면(meta["pcap_file"]이 None) dns_queries/tls_sni를 빈 리스트로
    둔 채 report_builder.py 기존 계약대로 정상 반환한다(report_builder.py 21~25줄 참고).
    """
    meta, scenario_result = capture_during_scenario(
        package_name=package_name,
        output_pcap_path=output_pcap_path,
        run_scenario_fn=run_scenario_fn,
        adb_serial=adb_serial,
    )

    pcap_path = meta["pcap_file"]
    dns_queries = parse_dns(pcap_path) if pcap_path else []
    tls_sni = parse_sni(pcap_path) if pcap_path else []

    report = build_network_report(meta, dns_queries, tls_sni)
    return report, scenario_result


if __name__ == "__main__":
    import json

    from src.dynamic_analyzer.adb_runner import AdbRunner
    from src.dynamic_analyzer.frida_controller import FridaController
    from src.dynamic_analyzer.scenario_runner import ScenarioRunner
    from src.dynamic_analyzer.scenarios import LAUNCH_ONLY

    controller = FridaController()
    controller.connect()
    adb = AdbRunner()
    runner = ScenarioRunner(controller, adb, hooks_js_path="src/dynamic_analyzer/hooks.bundle.js")

    report, scenario_result = analyze_network(
        package_name=LAUNCH_ONLY.package_name,
        run_scenario_fn=lambda: runner.run_scenario(LAUNCH_ONLY),
        output_pcap_path="./output/capture.pcap",
    )

    with open("network_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print("Scenario success:", getattr(scenario_result, "success", None))
    print("Scenario crashed:", getattr(scenario_result, "crashed", None))
    print(f"dns_queries {len(report['dns_queries'])}건 / tls_sni {len(report['tls_sni'])}건")
    print(f"suspicious.domains {len(report['suspicious']['domains'])}건 / suspicious.ips {len(report['suspicious']['ips'])}건")
    print("network_report.json 저장 완료")
