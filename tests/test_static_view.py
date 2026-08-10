"""정적 분석 뷰 테스트. (B, 7주차)

화면 자체는 눈으로 봐야 하지만, 화면이 쓰는 "판단"은 전부 views/static_data.py에
모아뒀으므로 그 부분은 streamlit 없이 검증할 수 있다. 여기서 고정하는 것:

  - 위험한 권한이 표 위쪽에 오는가 (정렬)
  - 값이 없을 때 0으로 채우지 않는가 (계산 실패 / 파싱 실패 구분)
  - 리포트가 깨진 형태로 와도 예외를 던지지 않는가

마지막 항목이 이 파일의 핵심이다. 7주차 검증 포인트가 "한 모듈이 죽어도
대시보드는 안 죽는다"인데, 뷰 함수 하나가 TypeError를 던지면 탭 하나가 아니라
app.py 전체가 죽는다. 그래서 None/타입 이상값을 일부러 넣어서 확인한다.
"""

import pytest

from views.static_data import (
    NO_VALUE,
    SDK_PARSE_FAILED,
    breakdown_matches_raw,
    build_breakdown_rows,
    build_certificate_rows,
    build_code_flags,
    build_exported_component_rows,
    build_highlights,
    build_meta_rows,
    build_permission_rows,
    build_strings_view,
    build_suspicious_api_rows,
    count_by_level,
    factor_label_ko,
    format_sdk,
    is_self_signed,
    static_score_100,
)
from static_analyzer.risk_scorer import calculate_risk_with_breakdown
from views.static_samples import SAMPLE_FAILED, SAMPLE_NORMAL, SAMPLE_OK, SAMPLE_PARTIAL

OK = SAMPLE_OK["data"]
NORMAL = SAMPLE_NORMAL["data"]
PARTIAL = SAMPLE_PARTIAL["data"]

# 뷰가 실제로 마주칠 수 있는 "이상한 입력" 모음. 전부 예외 없이 처리돼야 한다.
BROKEN_INPUTS = [
    None,
    {},
    {"manifest": None, "certificate": None, "code_analysis": None, "strings": None},
    {"manifest": "문자열이 들어온 경우", "risk_breakdown": []},
    {"manifest": {"permissions": None, "components": None}},
    {"risk_score": "0.8"},  # 숫자가 아닌 점수
    {"risk_breakdown": {"raw": None, "breakdown": [{"factor": None, "weight": None}]}},
]


# ────────────────────────────────────────────────────────────
# 권한
# ────────────────────────────────────────────────────────────

def test_권한은_위험한_것부터_정렬된다():
    rows = build_permission_rows(OK)
    levels = [r["risk_level"] for r in rows]

    assert levels == sorted(levels, key=lambda lv: {"high": 0, "medium": 1, "low": 2}[lv])
    # 같은 등급 안에서는 가중치가 큰 것이 먼저
    high = [r["weight"] for r in rows if r["risk_level"] == "high"]
    assert high == sorted(high, reverse=True)


def test_가장_위험한_권한이_맨_위에_온다():
    rows = build_permission_rows(OK)
    # 접근성/오버레이(가중치 10)가 1~2위여야 한다. INTERNET이 위로 오면 안 된다.
    assert rows[0]["weight"] == 10
    assert rows[0]["risk_level"] == "high"
    assert rows[-1]["risk_level"] == "low"


def test_가중치가_없는_권한도_표에서_빠지지_않는다():
    # INTERNET은 PERMISSION_WEIGHTS에 없어서 가중치 0이지만, 사용자에게는
    # "이 앱이 통신을 한다"는 정보라 표에 남아야 한다.
    names = {r["name"] for r in build_permission_rows(OK)}
    assert "android.permission.INTERNET" in names


def test_권한_개수_요약이_실제_행_수와_맞는다():
    rows = build_permission_rows(OK)
    counts = count_by_level(rows)
    assert sum(counts.values()) == len(rows)


def test_강조할_권한_3종이_검출된다():
    highlights = build_highlights(build_permission_rows(OK))
    detected = {h["group"]: h["detected"] for h in highlights}

    assert detected == {"문자(SMS) 접근": True, "접근성 서비스": True, "화면 덮어쓰기": True}


def test_검출되지_않은_강조_항목도_목록에서_사라지지_않는다():
    # 앱마다 항목이 나타났다 사라지면 여러 앱을 비교할 때 헷갈리므로,
    # 없어도 "없음"으로 남긴다.
    rows = build_permission_rows({"manifest": {"permissions": ["android.permission.INTERNET"]}})
    highlights = build_highlights(rows)

    assert len(highlights) == 3
    assert all(h["detected"] is False for h in highlights)


def test_권한_설명이_비어있지_않다():
    # 가중치가 붙은 권한인데 악용 예시가 없으면 표에 빈 칸이 생긴다.
    rows = build_permission_rows(OK)
    weighted = [r for r in rows if r["weight"] > 0]

    assert weighted
    assert all(r["abuse_example"] for r in weighted)


# ────────────────────────────────────────────────────────────
# 값이 없을 때 — 0으로 채우지 않는다
# ────────────────────────────────────────────────────────────

def test_점수_계산_실패는_0이_아니라_None이다():
    # 0으로 내려보내면 화면에 "0점 = 안전한 앱"으로 표시돼 정반대로 읽힌다.
    assert static_score_100(PARTIAL) is None
    assert static_score_100({}) is None
    assert static_score_100({"risk_score": None}) is None


def test_정상_점수는_100점_만점으로_변환된다():
    assert static_score_100(OK) == 100.0
    assert static_score_100(NORMAL) == 12.0


def test_점수가_불리언이면_None이다():
    # True는 파이썬에서 숫자로 취급돼 1.0점이 돼버린다.
    assert static_score_100({"risk_score": True}) is None


@pytest.mark.parametrize(
    "value, expected",
    [(21, "21"), (0, SDK_PARSE_FAILED), (None, NO_VALUE)],
)
def test_sdk의_0은_파싱_실패로_구분된다(value, expected):
    # apk_extractor._safe_int()가 파싱 실패 시 0을 넣는다. "SDK 0"이 아니다.
    assert format_sdk(value) == expected


def test_일부_실패한_결과도_기본정보_표가_그려진다():
    rows = build_meta_rows(PARTIAL)
    values = {r["항목"]: r["값"] for r in rows}

    assert values["패키지명"] == "com.example.sample.banker"
    assert values["타깃 SDK"] == SDK_PARSE_FAILED


def test_인증서가_없으면_표_대신_None을_돌려준다():
    assert build_certificate_rows(PARTIAL) is None
    assert build_certificate_rows({}) is None
    assert build_certificate_rows({"certificate": {}}) is None


def test_자가서명_경고는_True일_때만_뜬다():
    assert is_self_signed(OK) is True
    assert is_self_signed({"certificate": {"is_self_signed": False}}) is False
    assert is_self_signed({"certificate": {}}) is False   # 값이 없으면 경고 안 함
    assert is_self_signed({}) is False


# ────────────────────────────────────────────────────────────
# 점수 근거 (D의 risk_breakdown을 옮기기만 한다)
# ────────────────────────────────────────────────────────────

def test_근거_항목의_합이_raw와_일치한다():
    assert breakdown_matches_raw(OK) is True


def test_근거가_빠지면_합_불일치를_잡아낸다():
    # 화면에 경고를 띄우기 위한 장치가 실제로 동작하는지 확인.
    broken = {"risk_breakdown": {"raw": 82.0, "breakdown": [{"factor": "a", "weight": 1}]}}
    assert breakdown_matches_raw(broken) is False


def test_raw가_없으면_판정하지_않는다():
    assert breakdown_matches_raw(PARTIAL) is None
    assert breakdown_matches_raw({}) is None


def test_근거는_기여도가_큰_순서다():
    weights = [r["weight"] for r in build_breakdown_rows(OK)]
    assert weights == sorted(weights, reverse=True)


def test_근거에서_점수를_다시_계산하지_않는다():
    # D가 준 weight를 그대로 옮기기만 해야 한다. 여기서 재계산하면 두 값이 어긋난다.
    rows = {r["factor"]: r["weight"] for r in build_breakdown_rows(OK)}
    assert rows["obfuscation_detected"] == 15
    assert rows["exported_components×2 (3개)"] == 6


@pytest.mark.parametrize(
    "factor, expected_in",
    [
        ("android.permission.READ_SMS", "READ_SMS"),
        ("exported_components×2 (3개)", "외부에 열린 컴포넌트"),
        ("obfuscation_detected", "난독화"),
        ("certificate.is_self_signed", "자가 서명"),
    ],
)
def test_근거_항목이_한국어로_설명된다(factor, expected_in):
    assert expected_in in factor_label_ko(factor)


def test_모르는_근거_항목도_빈칸이_되지_않는다():
    # D가 나중에 새 factor를 추가해도 표가 비지 않아야 한다.
    assert factor_label_ko("무언가_새로운_항목") == "무언가_새로운_항목"


# ────────────────────────────────────────────────────────────
# 컴포넌트 / 코드 / 문자열
# ────────────────────────────────────────────────────────────

def test_외부에_열린_컴포넌트만_나온다():
    rows = build_exported_component_rows(OK)
    assert len(rows) == 3
    assert all(r["type"] != "-" for r in rows)  # components에서 종류까지 살아남음


def test_exported가_아니면_제외된다():
    data = {
        "manifest": {
            "exported_components": [],
            "components": [
                {"type": "activity", "name": "A", "exported": False, "intent_filters": []}
            ],
        }
    }
    assert build_exported_component_rows(data) == []


def test_components가_없는_구버전_출력도_이름은_보여준다():
    # 폴백 경로. intent_filters는 원천에서 버려져 복원이 불가능하다.
    data = {"manifest": {"exported_components": ["com.x.A"], "components": []}}
    rows = build_exported_component_rows(data)

    assert [r["name"] for r in rows] == ["com.x.A"]
    assert rows[0]["type"] == "-"


def test_코드_플래그는_항상_4개다():
    # 화면 열 개수가 앱마다 달라지지 않도록 고정.
    assert len(build_code_flags(OK)) == 4
    assert len(build_code_flags(PARTIAL)) == 4
    assert [f["on"] for f in build_code_flags(PARTIAL)] == [False] * 4


def test_의심_API와_문자열이_그대로_전달된다():
    assert len(build_suspicious_api_rows(OK)) == 3

    strings = build_strings_view(OK)
    assert len(strings["urls"]) == 2
    assert strings["ip_addresses"] == ["203.0.113.77"]


def test_문자열_분석이_실패하면_빈_목록이다():
    strings = build_strings_view(PARTIAL)
    assert strings == {"urls": [], "ip_addresses": [], "suspicious_strings": []}


# ────────────────────────────────────────────────────────────
# 깨진 입력 — 화면이 죽지 않아야 한다
# ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("data", BROKEN_INPUTS)
def test_깨진_리포트가_와도_예외를_던지지_않는다(data):
    """뷰 함수 하나가 예외를 던지면 탭이 아니라 app.py 전체가 죽는다."""
    build_meta_rows(data)
    rows = build_permission_rows(data)
    count_by_level(rows)
    build_highlights(rows)
    build_certificate_rows(data)
    is_self_signed(data)
    build_exported_component_rows(data)
    build_code_flags(data)
    build_suspicious_api_rows(data)
    build_strings_view(data)
    static_score_100(data)
    build_breakdown_rows(data)
    breakdown_matches_raw(data)


@pytest.mark.parametrize("data", [OK, NORMAL], ids=["악성 샘플", "정상 샘플"])
def test_샘플의_점수가_실제_scorer_출력과_일치한다(data):
    """샘플은 손으로 적은 값이라 실제 계산과 어긋날 수 있다.

    실제로 처음 작성했을 때 raw를 82로 적었는데 진짜 값은 140이었고,
    화면에는 그 틀린 값이 그대로 표시됐다. 샘플이 거짓말을 하면 그걸 보고
    맞춘 화면도 같이 틀리므로, D의 계산 함수에 직접 넣어서 대조한다.
    """
    actual = calculate_risk_with_breakdown(
        data["manifest"], data["code_analysis"], data["strings"], data["certificate"]
    )

    assert actual["raw"] == data["risk_breakdown"]["raw"]
    assert actual["total"] == data["risk_breakdown"]["total"] == data["risk_score"]
    assert actual["breakdown"] == data["risk_breakdown"]["breakdown"]


def test_정상_앱_샘플은_낮은_등급으로_나온다():
    # 악성 샘플만 있으면 "모든 앱이 빨갛게 나오는 화면"인지 구분이 안 된다.
    rows = build_permission_rows(NORMAL)
    counts = count_by_level(rows)

    assert counts["high"] == 0
    assert is_self_signed(NORMAL) is False
    assert all(h["detected"] is False for h in build_highlights(rows))


def test_모듈_전체_실패_샘플은_data가_없다():
    # 이 경우 render()는 경고만 띄우고 바로 빠져나온다.
    assert SAMPLE_FAILED["data"] is None
    assert SAMPLE_FAILED["error"]
