"""
common.py — 대시보드 공용 유틸리티 (7~8주차, 역할 A 유예원 담당)

B/C/D의 views/*.py가 공통으로 쓰는 것만 모아둔다:
- status_badge(status): main.py의 module_status(ok/partial/failed/timeout)를
  일관된 색/아이콘으로 표시하는 마크다운 문자열을 만든다.
- safe_get(d, *keys, default=None): report["modules"]["static"]["data"]["meta"]...
  처럼 중첩 dict를 내려갈 때, 중간에 모듈이 실패해서 None이 껴 있어도 죽지 않게 방어.
- STATUS_COLORS / STATUS_ICONS: 네 명 산출물의 색 톤을 맞추기 위한 공용 표.
  D의 위험도 게이지, B의 권한 강조색 등도 이 표를 재사용할 것 — 각자 다른 색을
  쓰면 대시보드가 4명이 따로 만든 것처럼 보인다.

주의: 이 파일은 streamlit 없이도(단위테스트 등에서) safe_get()을 쓸 수 있도록
streamlit import를 최상단에 두지 않고, streamlit이 실제로 필요한 함수 안에서만
지연 import한다.
"""
from __future__ import annotations

from typing import Any, Optional

STATUS_COLORS: dict[str, str] = {
    "ok": "green",
    "partial": "orange",
    "failed": "red",
    "timeout": "gray",
}

STATUS_ICONS: dict[str, str] = {
    "ok": "✅",
    "partial": "⚠️",
    "failed": "❌",
    "timeout": "⏱️",
}

# 분석 "상태"(Status) 라벨 — 8주차에 "정상/실패"에서 "분석 성공/분석 실패"로 바꿨다.
#
# 경위(8주차 계획수정 PDF 1항): 모듈 상태에 "✅ 정상"이라고 적으면 화면에서
# "이 APK가 안전하다"로 읽힌다. 실제 의미는 "정적 분석이 정상적으로 실행됨"이다.
# 취약 APK를 넣었는데 평문 후보 35건·의심 네트워크 4건이 나오면서도 세 모듈이
# 전부 "정상"으로 표시되던 것이 그 증거다. 그래서 이 표는 **파이프라인이 돌았는가**
# 만 말하고, 앱의 안전 여부는 아래 VERDICT_* (보안 판정) 계층이 따로 말한다.
STATUS_LABELS_KO: dict[str, str] = {
    "ok": "분석 성공",
    "partial": "부분 성공",
    "failed": "분석 실패",
    "timeout": "시간 초과",
}

# ── 보안 판정(Verdict) 색/아이콘/라벨 ──
#
# **분석 상태(STATUS_*)와 완전히 다른 축이다.** 위쪽이 "파이프라인이 돌았는가",
# 이쪽이 "관찰된 지표로 볼 때 이 앱이 얼마나 위험한가"다. 화면에서 두 축이 같은
# 단어(정상/실패)를 쓰지 않게 라벨을 겹치지 않도록 골랐다.
#
# 구간은 8주차 계획수정 PDF 4항 그대로:
#   0–29 🟢 정상 / 30–59 🟡 주의 / 60–79 🟠 의심 / 80–100 🔴 고위험
# "악성"은 점수만으로 주지 않는다 — 강한 지표가 여러 개 동시에 충족될 때만
# risk_aggregator가 승격시킨다(PDF 5항). 판정 근거 없이 "악성 APK"라고 쓰는 것을
# 막기 위한 잠금이다.
VERDICT_COLORS: dict[str, str] = {
    "normal": "#0ca30c",      # good
    "caution": "#fab219",     # warning
    "suspicious": "#e07000",  # 진한 주황 — warning과 critical 사이
    "high_risk": "#d03b3b",   # critical
    "malicious": "#8b1a1a",   # critical(강)
    "unknown": "#898781",     # muted (판정 불가 — 0점=안전으로 오해 방지)
}

VERDICT_ICONS: dict[str, str] = {
    "normal": "🟢",
    "caution": "🟡",
    "suspicious": "🟠",
    "high_risk": "🔴",
    "malicious": "⛔",
    "unknown": "⚪",
}

VERDICT_LABELS_KO: dict[str, str] = {
    "normal": "정상",
    "caution": "주의",
    "suspicious": "의심",
    "high_risk": "고위험",
    "malicious": "악성",
    "unknown": "판정 불가",
}

# 게이지에 깔 구간 밴드(0~100 스케일 상한). src/risk_aggregator.py의 VERDICT_BANDS와
# 반드시 동일하게 유지할 것 — 게이지 구간색과 실제 판정이 어긋나면 안 된다.
# malicious는 점수 구간이 아니라 지표 기반 승격이라 밴드에 넣지 않는다.
VERDICT_BAND_BOUNDS = [(30, "normal"), (60, "caution"), (80, "suspicious"), (100, "high_risk")]

# 화면·리포트 하단에 항상 붙이는 문구 (PDF 5항).
# 위험도는 어디까지나 "관찰된 지표"의 요약이지 악성 판정서가 아니다.
DISCLAIMER = (
    "본 결과는 정적·동적·네트워크 분석에서 관찰된 보안 위험 지표를 기반으로 산출된 "
    "위험도이며, 악성 여부를 단독으로 확정하지 않습니다."
)

# 정적 뷰의 **권한** 위험도(high/medium/low)는 이것과 다른 축이라 views/static_data.py가
# 자체 표(RISK_COLORS/RISK_LABELS_KO)를 갖고 있다. 여기 표를 그쪽에 쓰지 말 것.

# ── 모듈 카테고리 색 (dataviz 카테고리 슬롯 1/2/3, CVD 검증 통과) ──
# static/dynamic/network는 대시보드 전체에서 반복 등장하는 "정체성"이라 카테고리
# 색으로 고정한다. breakdown 막대에서 이 색을 쓰고, 라이트 모드 magenta는 대비가
# 낮아(WARN) 반드시 직접 라벨/표를 함께 보여준다(relief 규칙).
MODULE_COLORS: dict[str, str] = {
    "static": "#2a78d6",   # 파랑
    "dynamic": "#008300",  # 초록
    "network": "#e87ba4",  # 마젠타
}

MODULE_LABELS_KO: dict[str, str] = {
    "static": "정적",
    "dynamic": "동적",
    "network": "네트워크",
}


def verdict_ko(verdict: Optional[str]) -> str:
    """영문 판정 코드를 한글 라벨로. 모르는 값이면 '판정 불가'로 떨어뜨린다."""
    return VERDICT_LABELS_KO.get(verdict or "unknown", VERDICT_LABELS_KO["unknown"])


def verdict_color(verdict: Optional[str]) -> str:
    return VERDICT_COLORS.get(verdict or "unknown", VERDICT_COLORS["unknown"])


def verdict_icon(verdict: Optional[str]) -> str:
    return VERDICT_ICONS.get(verdict or "unknown", VERDICT_ICONS["unknown"])


def status_ko(status: Optional[str]) -> str:
    """분석 상태 코드를 한글 라벨로 (아이콘·색 없이 글자만 필요할 때)."""
    if status is None:
        return "결과 없음"
    return STATUS_LABELS_KO.get(status, status)


def status_badge(status: Optional[str]) -> str:
    """main.py의 module_status를 st.markdown()에 바로 넣을 수 있는 색깔
    텍스트로 변환한다 (streamlit의 `:color[text]` 마크다운 문법 사용).

    사용 예:
        st.markdown(status_badge(report["modules"]["static"]["status"]))
    """
    if status is None or status not in STATUS_COLORS:
        status = "failed" if status is None else status
    color = STATUS_COLORS.get(status, "gray")
    icon = STATUS_ICONS.get(status, "•")
    label = STATUS_LABELS_KO.get(status, status)
    return f":{color}[{icon} {label}]"


def safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """중첩 dict를 안전하게 내려간다. 중간에 None이거나 dict가 아니거나 키가
    없으면 그 즉시 default를 반환한다.

    main.py의 report는 모듈이 실패하면 modules.<name>.data가 None이거나 일부
    필드만 채워진 채로 온다 — dict 체이닝(d["a"]["b"]["c"])을 그대로 쓰면
    KeyError/TypeError로 뷰 전체가 죽는다. views/*.py에서는 이 함수를 통해서만
    report 안쪽 값에 접근할 것.

    예:
        safe_get(report, "modules", "static", "data", "meta", "package_name")
        safe_get(report, "modules", "network", "data", "suspicious", "domains", default=[])
    """
    cur = d
    for k in keys:
        if cur is None:
            return default
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return default
    return cur if cur is not None else default


def render_errors(errors: Optional[list]) -> None:
    """errors 리스트를 접이식(expander)으로 보여주는 공용 컴포넌트.
    views/*.py에서 각 모듈 렌더링 마지막에 호출하면 된다.
    errors가 비었거나 None이면 아무것도 그리지 않는다."""
    import streamlit as st  # 지연 import

    if not errors:
        return
    with st.expander(f"⚠️ 경고/에러 {len(errors)}건", expanded=False):
        for e in errors:
            st.write(f"- {e}")


def render_module_header(report: dict, module_name: str, title: str) -> dict:
    """뷰 파일 맨 위에서 공통으로 하는 일(상태 배지 표시 + error 메시지 표시 +
    module dict 꺼내기)을 한 번에 처리하고, 그 모듈의 raw dict를 반환한다.

    8주차 변경: 제목 옆에 배지를 붙이던 것을 "분석 상태" 라벨을 명시한 한 줄로
    바꿨다. 배지만 있으면 그 ✅가 "분석이 됐다"인지 "앱이 안전하다"인지 화면에서
    구분되지 않기 때문이다(PDF 1항). 각 뷰는 이 아래에 위험 지표를 따로 그린다.

    사용 예 (views/static_view.py):
        module = render_module_header(report, "static", "정적 분석")
        data = module.get("data")
        if data is None:
            return
        ... 실제 시각화 ...
    """
    import streamlit as st  # 지연 import

    module = safe_get(report, "modules", module_name, default={}) or {}
    status = module.get("status")

    st.markdown(f"### {title}")
    st.markdown(f"분석 상태 &nbsp; {status_badge(status)}", unsafe_allow_html=True)

    if module.get("error"):
        st.error(module["error"])

    return module


def render_indicators(indicators: Optional[list], empty_text: str = "관찰된 위험 지표 없음") -> None:
    """모듈 뷰 상단의 "위험 지표" 줄. risk_score["indicators"][모듈명]을 그대로 받는다.

    분석 상태 바로 아래에 두어 "분석은 성공했고, 그 결과 이런 지표가 관찰됐다"는
    두 층이 화면에서 붙어 읽히게 한다(PDF 3항의 구조).

    지표가 없을 때 "안전함"이라고 쓰지 않는 것이 중요하다 — 관찰되지 않은 것과
    없는 것은 다르고, 특히 캡처가 비었을 때 "안전"으로 읽히면 안 된다.
    """
    import streamlit as st  # 지연 import

    if not indicators:
        st.caption(f"위험 지표 &nbsp; {empty_text}")
        return

    lines = []
    for ind in indicators:
        label = ind.get("label", "")
        value = ind.get("value", "")
        mark = "⚠️" if ind.get("strong") else "•"
        lines.append(f"{mark} {label} **{value}**")
    st.markdown("위험 지표 &nbsp; " + " &nbsp;/&nbsp; ".join(lines))
