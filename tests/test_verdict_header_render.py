"""최상단 판정 카드(views/verdict_header.py) 렌더링 테스트. (8주차 신규)

잠그는 것: **분석 상태와 보안 판정이 화면에서 섞이지 않는가.**

8주차 계획수정 PDF 1항이 지적한 문제 — 세 모듈이 "✅ 정상"으로 표시되던 것이
"APK가 안전하다"로 읽혔다. 실제 뜻은 "분석이 성공했다"였다. 그래서
  - 분석 상태 라벨은 "분석 성공"이어야 하고("정상"이면 안 됨)
  - 앱의 위험 판정은 그것과 별도의 표현(정상/주의/의심/고위험/악성)이어야 한다.

streamlit이 없는 PC에서는 통째로 skip된다.
"""

import pytest

pytest.importorskip("streamlit", reason="대시보드 렌더링 테스트에는 streamlit이 필요합니다")

from streamlit.testing.v1 import AppTest  # noqa: E402

TIMEOUT = 60

# 세 모듈 모두 분석 성공 + 위험 지표는 관찰된 상태.
# PDF가 문제로 든 바로 그 조합이다("성공"과 "안전"이 헷갈리는 상황).
ANALYZED_OK_BUT_RISKY = {
    "apk_name": "sample.apk",
    "package_name": "com.example.sample",
    "modules": {
        "static": {"status": "ok", "data": {}},
        "dynamic": {"status": "ok", "data": {}},
        "network": {"status": "ok", "data": {}},
    },
    "risk_score": {
        "total": 0.64,
        "score100": 64,
        "level": "suspicious",
        "verdict": {
            "code": "suspicious",
            "band_code": "suspicious",
            "score100": 64,
            "strong_indicators": [],
            "malicious_rule": {"min_score": 80, "min_indicators": 3,
                               "strong_indicator_count": 1, "met": False},
        },
        "indicators": {"static": [], "dynamic": [], "network": []},
        "breakdown": {"modules": {}, "weights_applied": {}, "unavailable": []},
    },
}

ALL_FAILED = {
    "apk_name": "sample.apk",
    "package_name": "com.example.sample",
    "modules": {
        "static": {"status": "failed", "data": None},
        "dynamic": {"status": "failed", "data": None},
        "network": {"status": "failed", "data": None},
    },
    "risk_score": {
        "total": None, "score100": None, "level": "unknown",
        "verdict": {"code": "unknown", "band_code": "unknown", "score100": None,
                    "strong_indicators": [], "malicious_rule": {}},
        "indicators": {}, "breakdown": {},
    },
}


def _run(report: dict) -> AppTest:
    src = (
        "import streamlit as st\n"
        "from views import verdict_header\n"
        "verdict_header.render(st.session_state['_report'])\n"
    )
    at = AppTest.from_string(src, default_timeout=TIMEOUT)
    at.session_state["_report"] = report
    at.run()
    return at


def _body(at: AppTest) -> str:
    return " ".join(str(getattr(el, "value", "")) for el in at.markdown)


def test_화면이_죽지_않는다():
    for report in (ANALYZED_OK_BUT_RISKY, ALL_FAILED):
        at = _run(report)
        assert not at.exception, f"예외 발생: {list(at.exception)}"


def test_분석_상태는_정상이_아니라_분석_성공으로_표시된다():
    """이 파일의 핵심. '정상'이라는 단어가 상태 자리에 있으면 안 된다."""
    at = _run(ANALYZED_OK_BUT_RISKY)
    body = _body(at)

    assert "분석 성공" in body
    # 판정(의심)과 상태(분석 성공)가 둘 다 보이되, 상태 쪽에 "정상"이 없어야 한다.
    status_part = body.split("분석 상태", 1)[-1]
    assert "정상" not in status_part


def test_보안_판정이_점수와_함께_표시된다():
    at = _run(ANALYZED_OK_BUT_RISKY)
    body = _body(at)

    assert "의심" in body
    assert "SUSPICIOUS" in body
    assert "64" in body
    assert "종합 위험도" in body


def test_두_축이_라벨로_구분된다():
    """'분석 상태'라는 라벨이 명시돼야 ✅가 무엇을 뜻하는지 알 수 있다."""
    at = _run(ANALYZED_OK_BUT_RISKY)
    body = _body(at)

    assert "분석 상태" in body
    assert "APK 보안 분석 결과" in body


def test_판정_불가는_0점으로_표시되지_않는다():
    """점수 자리에 0을 넣으면 '위험도 0 = 안전'으로 정반대로 읽힌다."""
    at = _run(ALL_FAILED)
    body = _body(at)

    assert "판정 불가" in body
    assert "0 / 100" not in body


def test_주의_문구가_붙는다():
    at = _run(ANALYZED_OK_BUT_RISKY)
    captions = " ".join(str(getattr(c, "value", "")) for c in at.caption)
    assert "악성 여부를 단독으로 확정하지 않습니다" in captions
