"""종합 위험도 뷰를 실제로 그려보는 테스트. (8주차 Day1)

확인하는 것은 하나다: **점수를 못 낸 상태가 점수처럼 보이지 않는가.**

경위 — 7주차 risk_view는 total=None이면 곧바로 더미(72점 "위험")를 그렸다.
aggregate_risk()가 배선되기 전에는 맞는 선택이었지만, 배선된 뒤로 total=None은
"세 모듈 전부 실패"라는 뜻이 됐다. 즉 분석이 통째로 실패한 리포트에서 큼직한
빨간 "72 / 100 위험"이 뜬다. 배너가 같이 뜨긴 해도 발표 화면에서는 숫자가 먼저
읽히므로, 실패를 위험으로 오독하게 만든다.

같은 유형의 실수(값이 없는 것을 0이나 그럴듯한 값으로 채우기)를 정적 뷰에서도
막아뒀다(test_static_view_render.py의 "계산 실패" 표시). 위험도 뷰에도 같은
잠금을 건다.

streamlit이 없는 PC에서는 통째로 skip된다.
"""

import pytest

pytest.importorskip("streamlit", reason="대시보드 렌더링 테스트에는 streamlit이 필요합니다")

from streamlit.testing.v1 import AppTest  # noqa: E402

from views.risk_view import DEMO_FLAG, _DUMMY_RISK  # noqa: E402

TIMEOUT = 60

# 세 모듈이 전부 죽어 aggregate_risk()가 total=None, level="unknown"을 낸 상태.
# main.py의 부분 리포트 정책상 실제로 나올 수 있는 리포트다.
ALL_FAILED = {
    "apk_name": "sample.apk",
    "package_name": "com.example.sample",
    "modules": {
        "static": {"status": "failed", "data": None, "error": "apktool 실행 파일을 찾을 수 없음"},
        "dynamic": {"status": "failed", "data": None, "error": "package_name을 구할 수 없음"},
        "network": {"status": "failed", "data": None, "error": "pcap pull 실패"},
    },
    "risk_score": {"total": None, "level": "unknown", "breakdown": {}},
}

_DUMMY_SCORE_TEXT = str(round(_DUMMY_RISK["total"] * 100))


def _run(report: dict, demo: bool = False) -> AppTest:
    """views/risk_view.render()만 띄운다.

    app.py 전체가 아니라 이 뷰만 그리는 이유: 정적 탭도 같은 리포트에서 경고를
    띄우기 때문에, app.py로 돌리면 어느 탭이 낸 경고인지 구분이 안 된다.
    """
    src = (
        "import streamlit as st\n"
        "from views.risk_view import render, DEMO_FLAG\n"
        f"st.session_state[DEMO_FLAG] = {demo!r}\n"
        "render(st.session_state['_report'])\n"
    )
    at = AppTest.from_string(src, default_timeout=TIMEOUT)
    at.session_state["_report"] = report
    at.run()
    return at


def test_전부_실패해도_화면이_죽지_않는다():
    at = _run(ALL_FAILED)
    assert not at.exception, f"예외 발생: {list(at.exception)}"


def test_전부_실패하면_더미_점수가_뜨지_않는다():
    """이 테스트가 이 파일의 핵심이다."""
    at = _run(ALL_FAILED)

    body = " ".join(str(getattr(el, "value", "")) for el in at.markdown)
    assert _DUMMY_SCORE_TEXT not in body, (
        f"실패한 리포트에 더미 점수({_DUMMY_SCORE_TEXT})가 그려졌습니다"
    )
    assert "판정 불가" in body


def test_전부_실패하면_기여도_표를_그리지_않는다():
    """빈 표나 가짜 표를 그리면 데이터가 있는 것처럼 보인다."""
    at = _run(ALL_FAILED)
    assert len(at.dataframe) == 0


def test_판정_불가가_안전으로_읽히지_않게_문구가_붙는다():
    at = _run(ALL_FAILED)
    warnings = " ".join(w.value for w in at.warning)
    assert "안전하다는 뜻이 아니" in warnings.replace("'", "").replace("*", "")


def test_실패한_모듈_이름이_화면에_나온다():
    """왜 점수가 안 나왔는지를 사람이 화면에서 바로 알 수 있어야 한다."""
    at = _run(ALL_FAILED)
    warnings = " ".join(w.value for w in at.warning)
    for label in ("정적", "동적", "네트워크"):
        assert label in warnings


def test_더미는_명시적으로_켰을_때만_나온다():
    """demo_risk.py가 쓰는 경로. 이게 되어야 D가 기기 없이 화면 작업을 계속할 수 있다."""
    no_score = dict(ALL_FAILED, risk_score=None)

    off = _run(no_score, demo=False)
    assert _DUMMY_SCORE_TEXT not in " ".join(str(getattr(e, "value", "")) for e in off.markdown)

    on = _run(no_score, demo=True)
    assert not on.exception
    assert _DUMMY_SCORE_TEXT in " ".join(str(getattr(e, "value", "")) for e in on.markdown)


def test_실측_점수는_그대로_그려진다():
    """판정 불가 분기가 정상 리포트까지 잡아먹지 않는지 확인한다."""
    report = {
        "modules": {
            "static": {"status": "ok"},
            "dynamic": {"status": "failed"},
            "network": {"status": "ok"},
        },
        "risk_score": {
            "total": 0.41,
            "level": "medium",
            "breakdown": {
                "modules": {
                    "static": {"available": True, "weight": 0.571, "sub_score": 0.52},
                    "dynamic": {"available": False},
                    "network": {"available": True, "weight": 0.429, "sub_score": 0.26},
                },
                "weights_applied": {"static": 0.571, "network": 0.429},
                "unavailable": ["dynamic"],
            },
        },
    }
    at = _run(report)

    assert not at.exception
    body = " ".join(str(getattr(el, "value", "")) for el in at.markdown)
    assert "41" in body
    assert "주의" in body
    assert len(at.dataframe) == 1   # 기여도 표
