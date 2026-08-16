"""run_pipeline의 단계별 소요시간 계측 테스트. (8주차 계획수정 PDF, 역할1 유예원)

계획수정 PDF가 요구한 "수동 대비 시간 단축 정량화"(B 담당)에 자동 측정치를
공급하기 위해 run_pipeline이 report에 "timings" 필드를 채우게 했다. 이 파일은
그 계측 로직만 검증한다 — 정적/동적/네트워크 모듈 자체의 정확성은 각 모듈의
테스트 파일에서 이미 검증하므로, 여기서는 모듈을 몽키패치로 대체하고
aggregate_risk도 더미로 바꿔서 "타이밍이 맞게 채워지는가"에만 집중한다.
"""

from __future__ import annotations

import time

import main


def _fake_static_ok(apk_path, work_dir):
    time.sleep(0.02)
    return main.ModuleResult(status="ok", data={"meta": {"package_name": "com.example.app"}})


def _fake_static_failed(apk_path, work_dir):
    time.sleep(0.02)
    return main.ModuleResult(status="failed", error="테스트용 정적 실패")


def _fake_dynamic_and_network_ok(
    package_name, scenario, hooks_js_path, output_pcap_path, observe_after_sec
):
    time.sleep(0.02)
    return (
        main.ModuleResult(status="ok", data={"events": []}),
        main.ModuleResult(status="ok", data={"dns_queries": []}),
    )


def _dummy_aggregate_risk(modules):
    # risk_aggregator 자체는 별도 테스트가 있으니 여기서는 형태만 맞춘 더미로 대체.
    return {"total": None, "score100": None, "level": "unknown"}


def test_모든_단계가_성공하면_세_타이밍이_전부_채워진다(monkeypatch):
    monkeypatch.setattr(main, "_run_static_stage", _fake_static_ok)
    monkeypatch.setattr(main, "_run_dynamic_and_network_stage", _fake_dynamic_and_network_ok)
    monkeypatch.setattr(main, "aggregate_risk", _dummy_aggregate_risk)

    report = main.run_pipeline("dummy.apk")

    timings = report["timings"]
    assert timings["static_sec"] > 0
    assert timings["dynamic_network_sec"] > 0
    # 전체 시간은 두 단계 소요시간의 합보다 작을 수 없다 (스코어링 등 부가 작업 포함).
    assert timings["total_sec"] >= timings["static_sec"] + timings["dynamic_network_sec"]


def test_정적_분석이_실패하면_동적_네트워크_타이밍은_0이_아니라_None이다(monkeypatch):
    monkeypatch.setattr(main, "_run_static_stage", _fake_static_failed)
    monkeypatch.setattr(main, "aggregate_risk", _dummy_aggregate_risk)

    report = main.run_pipeline("dummy.apk")

    timings = report["timings"]
    assert timings["static_sec"] > 0
    # "0초 걸림"과 "애초에 안 돌았음"을 구분해야 B의 배수 계산이 왜곡되지 않는다.
    assert timings["dynamic_network_sec"] is None
    assert timings["total_sec"] >= timings["static_sec"]


def test_timings는_라운딩된_float_또는_None이다(monkeypatch):
    monkeypatch.setattr(main, "_run_static_stage", _fake_static_ok)
    monkeypatch.setattr(main, "_run_dynamic_and_network_stage", _fake_dynamic_and_network_ok)
    monkeypatch.setattr(main, "aggregate_risk", _dummy_aggregate_risk)

    report = main.run_pipeline("dummy.apk")

    timings = report["timings"]
    for key in ("static_sec", "dynamic_network_sec", "total_sec"):
        value = timings[key]
        assert value is None or isinstance(value, float)
