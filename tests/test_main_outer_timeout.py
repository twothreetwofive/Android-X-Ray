"""outer timeout이 실제로 즉시 리턴하는지 + 트립 시 강제 정리가 호출되는지 검증.
(8주차 계획수정 PDF, 잔버그 f — 좀비 프로세스, 역할1 유예원)

발견한 문제: `_with_outer_timeout`이 원래 `with ThreadPoolExecutor() as executor:`로
되어 있었는데, `future.result(timeout=...)`가 타임아웃을 던져도 `with` 블록을
빠져나갈 때 `executor.__exit__`이 `shutdown(wait=True)`를 호출해서 **그 작업이
실제로 끝날 때까지 계속 기다리고 있었다.** 즉 "outer timeout"이라는 이름과 달리
실제로는 아무것도 짧아지지 않았다 — 이게 "adb/frida가 좀비로 남는다"는 신고의
진짜 원인이었다(짧게 포기하고 넘어가는 게 아니라 그냥 계속 막혀있었으니까).

이 파일은 그 수정(threading.Thread(daemon=True) + join(timeout=...)으로 교체)이
1) 실제로 timeout_sec만큼만 기다리고 즉시 리턴하는지, 2) 정상 완료 시 결과값을
그대로 돌려주는지, 3) 함수 안에서 예외가 나면 그대로 다시 던져지는지, 4) 트립되면
run_pipeline이 `_force_cleanup_after_timeout`을 호출하는지, 5) 그 함수 자체가
컨트롤러/adb 정리 중 실패해도 예외를 삼키는지를 검증한다.
"""

from __future__ import annotations

import time

import main


# ── 1. _with_outer_timeout 자체 ──────────────────────────────────

def test_timeout보다_오래_걸리면_기다리지_않고_즉시_TIMEOUT을_반환한다():
    def _slow():
        time.sleep(1.0)
        return "완료"

    start = time.perf_counter()
    result = main._with_outer_timeout(_slow, 0.05)
    elapsed = time.perf_counter() - start

    assert result == "TIMEOUT"
    # 원래 버그(ThreadPoolExecutor.__exit__의 shutdown(wait=True))라면 여기서
    # 최소 1.0s는 걸렸어야 한다. 수정 후에는 timeout_sec 근처에서 바로 리턴돼야 함.
    assert elapsed < 0.5, f"즉시 리턴하지 않고 {elapsed:.2f}s 기다림 — 원래 버그가 재발한 것"


def test_timeout_안에_끝나면_결과값을_그대로_돌려준다():
    def _fast(x, y=0):
        return x + y

    result = main._with_outer_timeout(_fast, 5.0, 3, y=4)

    assert result == 7


def test_함수_안에서_예외가_나면_그대로_다시_던져진다():
    def _boom():
        raise ValueError("테스트용 예외")

    try:
        main._with_outer_timeout(_boom, 5.0)
    except ValueError as e:
        assert "테스트용 예외" in str(e)
    else:
        raise AssertionError("예외가 다시 던져지지 않음")


# ── 2. run_pipeline이 타임아웃 시 강제 정리를 호출하는가 ──────────────

def _fake_static_ok(apk_path, work_dir):
    return main.ModuleResult(status="ok", data={"meta": {"package_name": "com.example.app"}})


def _dummy_aggregate_risk(modules):
    return {"total": None, "score100": None, "level": "unknown"}


def test_동적_네트워크_stage가_timeout되면_강제_정리가_호출된다(monkeypatch):
    monkeypatch.setattr(main, "_run_static_stage", _fake_static_ok)
    monkeypatch.setattr(main, "aggregate_risk", _dummy_aggregate_risk)
    monkeypatch.setattr(main, "DYNAMIC_NETWORK_STAGE_TIMEOUT_SEC", 0.05)

    def _hanging_stage(package_name, scenario, hooks_js_path, output_pcap_path,
                        observe_after_sec, resource_sink=None):
        if resource_sink is not None:
            resource_sink["controller"] = "가짜-컨트롤러"
        time.sleep(0.5)  # outer timeout(0.05s)보다 훨씬 오래 걸리게 해서 확실히 트립시킴
        return (main.ModuleResult(status="ok"), main.ModuleResult(status="ok"))

    monkeypatch.setattr(main, "_run_dynamic_and_network_stage", _hanging_stage)

    calls = []
    monkeypatch.setattr(
        main, "_force_cleanup_after_timeout",
        lambda package_name, controller: calls.append((package_name, controller)),
    )

    report = main.run_pipeline("dummy.apk")

    assert report["modules"]["dynamic"]["status"] == "timeout"
    assert report["modules"]["network"]["status"] == "timeout"
    assert calls == [("com.example.app", "가짜-컨트롤러")]


def test_stage가_timeout_안에_끝나면_강제_정리를_호출하지_않는다(monkeypatch):
    monkeypatch.setattr(main, "_run_static_stage", _fake_static_ok)
    monkeypatch.setattr(main, "aggregate_risk", _dummy_aggregate_risk)

    def _fast_stage(package_name, scenario, hooks_js_path, output_pcap_path,
                     observe_after_sec, resource_sink=None):
        return (main.ModuleResult(status="ok"), main.ModuleResult(status="ok"))

    monkeypatch.setattr(main, "_run_dynamic_and_network_stage", _fast_stage)

    calls = []
    monkeypatch.setattr(
        main, "_force_cleanup_after_timeout",
        lambda package_name, controller: calls.append((package_name, controller)),
    )

    report = main.run_pipeline("dummy.apk")

    assert report["modules"]["dynamic"]["status"] == "ok"
    assert calls == []


# ── 3. _force_cleanup_after_timeout 자체 — 실패해도 절대 예외를 던지면 안 됨 ──

class _FakeController:
    def __init__(self, raise_on_cleanup=False):
        self.cleaned_up = False
        self._raise = raise_on_cleanup

    def cleanup(self):
        self.cleaned_up = True
        if self._raise:
            raise RuntimeError("frida cleanup 실패 (테스트용)")


def test_컨트롤러가_있으면_cleanup을_호출한다(monkeypatch):
    calls = []
    monkeypatch.setattr(
        main.subprocess, "run",
        lambda *a, **k: calls.append(a) or main.subprocess.CompletedProcess(a, 0),
    )

    controller = _FakeController()
    main._force_cleanup_after_timeout("com.example.app", controller)

    assert controller.cleaned_up is True


def test_cleanup이_실패해도_예외를_삼킨다(monkeypatch):
    monkeypatch.setattr(
        main.subprocess, "run",
        lambda *a, **k: main.subprocess.CompletedProcess(a, 0),
    )

    controller = _FakeController(raise_on_cleanup=True)

    # 예외가 밖으로 새면 안 된다 — 정리 실패가 파이프라인을 죽이면 안 되기 때문.
    main._force_cleanup_after_timeout("com.example.app", controller)

    assert controller.cleaned_up is True


def test_adb_명령이_실패해도_예외를_삼킨다(monkeypatch):
    def _raise(*a, **k):
        raise FileNotFoundError("adb 없음 (테스트용)")

    monkeypatch.setattr(main.subprocess, "run", _raise)

    # adb 자체가 없는 환경(예: 정적만 돌리는 CI)에서도 죽으면 안 된다.
    main._force_cleanup_after_timeout("com.example.app", None)


def test_컨트롤러가_없어도_adb_강제종료는_시도한다(monkeypatch):
    calls = []
    monkeypatch.setattr(
        main.subprocess, "run",
        lambda *a, **k: calls.append(a[0]) or main.subprocess.CompletedProcess(a, 0),
    )

    main._force_cleanup_after_timeout("com.example.app", None)

    joined = [" ".join(c) for c in calls]
    assert any("force-stop" in c and "com.example.app" in c for c in joined)
    assert any("pkill" in c and "tcpdump" in c for c in joined)
