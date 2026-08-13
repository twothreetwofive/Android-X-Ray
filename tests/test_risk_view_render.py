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


_MEASURED = {
    "modules": {
        "static": {"status": "ok"},
        "dynamic": {"status": "failed"},
        "network": {"status": "ok"},
    },
    "risk_score": {
        "total": 0.41,
        "score100": 41,
        "level": "caution",
        "verdict": {
            "code": "caution",
            "band_code": "caution",
            "score100": 41,
            "strong_indicators": [],
            "malicious_rule": {"min_score": 80, "min_indicators": 3,
                               "strong_indicator_count": 0, "met": False},
        },
        "indicators": {
            "static": [{"code": "obfuscation", "label": "난독화", "value": "탐지", "strong": False}],
            "dynamic": [],
            "network": [{"code": "suspicious_domain", "label": "의심 도메인",
                         "value": "1건", "strong": False}],
        },
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


def test_실측_리포트는_그대로_그려진다():
    """판정 불가 분기가 정상 리포트까지 잡아먹지 않는지 확인한다."""
    at = _run(_MEASURED)

    assert not at.exception
    # 위험 지표 표 + 기여도 표 = 2개
    assert len(at.dataframe) == 2


def test_위험_지표가_점수와_따로_표시된다():
    """8주차 계획수정 PDF 3항 — "분석이 성공했는가"와 "무엇이 발견됐는가"의 분리."""
    at = _run(_MEASURED)

    body = " ".join(str(getattr(el, "value", "")) for el in at.markdown)
    assert "위험 지표" in body
    assert "모듈별 위험도" in body

    # 관찰된 지표가 표에 실제로 들어가 있어야 한다.
    indicator_table = at.dataframe[0].value
    assert "난독화" in indicator_table.to_string()
    assert "의심 도메인" in indicator_table.to_string()


def test_모듈별_위험도가_0에서_100으로_표시된다():
    at = _run(_MEASURED)
    metric_values = " ".join(str(m.value) for m in at.metric)
    assert "52 / 100" in metric_values   # 정적 sub_score 0.52
    assert "26 / 100" in metric_values   # 네트워크 sub_score 0.26
    # 점수를 못 낸 동적 모듈에 0을 적으면 "위험 없음"으로 읽힌다.
    assert "0 / 100" not in metric_values
    assert "—" in metric_values


def test_악성이_아닌_이유가_화면에_나온다():
    """PDF 5항 — 점수만 높다고 '악성'이라 쓰지 않으며, 그 규칙을 화면에 드러낸다."""
    at = _run(_MEASURED)
    body = " ".join(str(getattr(el, "value", "")) for el in at.markdown)
    assert "판정 근거" in body
    assert "악성" in body and "둘 다" in body


def test_주의_문구가_항상_붙는다():
    at = _run(_MEASURED)
    infos = " ".join(str(getattr(i, "value", "")) for i in at.info)
    assert "악성 여부를 단독으로 확정하지 않습니다" in infos
