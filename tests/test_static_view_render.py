"""정적 뷰를 실제로 그려보는 테스트. (B, 7주차)

test_static_view.py는 화면이 쓰는 "값"만 검증한다. 그것만으로는 부족한데,
6주차에 겪은 문제가 정확히 그 유형이었기 때문이다 — 어댑터 테스트가 전부
fixture dict 기반이라 원천에서 필드가 빠지는 걸 못 잡았다. 여기서도 값만
맞추고 st.dataframe 인자를 틀리면 테스트는 통과하는데 화면은 죽는다.

그래서 streamlit이 공식 제공하는 AppTest로 **화면을 실제로 렌더링**한다.
브라우저 없이 스크립트를 그대로 실행해서 예외와 위젯 목록을 확인할 수 있다.

이 파일이 확인하는 것은 하나다:
    **어떤 상태로 와도 화면이 죽지 않는가.**
7주차 계획의 검증 포인트("일부러 모듈을 실패시켜도 대시보드가 안 죽고
배지만 뜨는지")를 정적 탭에 대해 자동으로 돌리는 것이다.

streamlit이 안 깔린 PC에서는 통째로 skip된다 — 정적 분석 모듈만 만지는
사람이 streamlit 때문에 테스트를 못 돌리는 일이 없게 하려는 것.
"""

import pytest

pytest.importorskip("streamlit", reason="대시보드 렌더링 테스트에는 streamlit이 필요합니다")

from pathlib import Path  # noqa: E402

from streamlit.testing.v1 import AppTest  # noqa: E402

from views.static_samples import SAMPLES, as_report  # noqa: E402

# AppTest.from_file()의 상대경로는 이 테스트 파일이 있는 tests/ 기준으로 풀리기
# 때문에 "app.py"라고 쓰면 못 찾는다. 저장소 루트에서 절대경로로 지정한다.
APP_PY = str(Path(__file__).resolve().parents[1] / "app.py")

# 실제 APK 분석 없이 화면만 그리는 것이라 오래 걸리지 않지만, CI가 느린 PC에서
# 기본값(3초)에 걸리는 일이 있어 넉넉히 준다.
TIMEOUT = 60


@pytest.mark.parametrize("label", list(SAMPLES))
def test_어떤_상태로_와도_정적_탭이_죽지_않는다(label):
    """app.py 전체를 띄우고 정적 탭을 그린다.

    뷰 함수만 부르지 않고 A의 app.py를 통째로 실행하는 이유: 화면이 죽는
    원인은 뷰 안쪽보다 import 순서나 탭 배치처럼 연결 부분에서 더 자주 생긴다.
    실제로 이 방식으로 확인하다가 views/static_data.py가 app.py의 import
    순서에 의존하고 있던 것을 발견했다.
    """
    at = AppTest.from_file(APP_PY, default_timeout=TIMEOUT)
    at.session_state["report"] = as_report(SAMPLES[label])
    at.run()

    assert not at.exception, f"{label}에서 예외 발생: {list(at.exception)}"


def test_점수_계산_실패는_0점으로_표시되지_않는다():
    """화면에 실제로 찍히는 문자열까지 확인한다.

    static_score_100()이 None을 돌려주는 것과, 그 None이 화면에 "계산 실패"로
    찍히는 것은 다른 문제다. metric에 0이 찍히면 "위험도 0 = 안전한 앱"으로
    읽히므로 표시 문자열을 직접 본다.
    """
    at = AppTest.from_file(APP_PY, default_timeout=TIMEOUT)
    at.session_state["report"] = as_report(SAMPLES["일부 단계 실패"])
    at.run()

    values = [m.value for m in at.metric]
    assert values == ["계산 실패"]
    assert "0" not in values


def test_모듈이_실패해도_안내_문구만_뜬다():
    """정적 분석이 통째로 실패한 경우. 화면은 살아 있고 경고만 떠야 한다."""
    at = AppTest.from_file(APP_PY, default_timeout=TIMEOUT)
    at.session_state["report"] = as_report(SAMPLES["모듈 전체 실패"])
    at.run()

    assert not at.exception
    assert any("결과가 없습니다" in w.value for w in at.warning)
    # 표는 하나도 그려지지 않아야 한다(빈 표를 그리면 데이터가 있는 것처럼 보임).
    assert len(at.dataframe) == 0


def test_자가서명_경고가_실제로_화면에_뜬다():
    at = AppTest.from_file(APP_PY, default_timeout=TIMEOUT)
    at.session_state["report"] = as_report(SAMPLES["악성 앱 예시 (정상 분석)"])
    at.run()

    assert any("자가 서명" in w.value for w in at.warning)


def test_정상_앱에는_자가서명_경고가_뜨지_않는다():
    # 경고가 늘 떠 있으면 경고로서 의미가 없다.
    at = AppTest.from_file(APP_PY, default_timeout=TIMEOUT)
    at.session_state["report"] = as_report(SAMPLES["정상 앱 예시 (대조용)"])
    at.run()

    assert not any("자가 서명" in w.value for w in at.warning)
