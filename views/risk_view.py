"""
views/risk_view.py — 종합 위험도 패널 (역할 D 담당, 대시보드의 얼굴)

받는 데이터: report["risk_score"] = src/risk_aggregator.aggregate_risk()의 출력.
    {
      "total": float(0.0~1.0) | None,
      "level": "low"|"medium"|"high"|"unknown",
      "breakdown": {
        "modules": {"static": {"available": bool, "weight": float,
                               "sub_score": float, ...}, "dynamic": {...}, "network": {...}},
        "weights_applied": {...},
        "unavailable": [모듈명, ...],
      },
    }

표시 규약:
- total은 0.0~1.0이라 화면에는 ×100 해서 0~100 점수로 보여준다.
- level은 영문이라 common.risk_level_ko()로 한글(낮음/주의/위험/판정 불가)로 바꿔 배지에 쓴다.
- 게이지 구간색/등급색은 common.RISK_LEVEL_COLORS(= B의 권한 강조색과 같은 표)를 쓴다.

주의(A가 골격에 남긴 것 유지): total이 None인 상태(스코어링 미반영 또는 입력 모듈
전부 실패)를 0점(안전)으로 오독하지 않게 분기한다. 아래에서는 total이 None이면
UI 확인용 더미 데이터를 대신 그리되 "예시 데이터" 배너를 띄워 실측과 구분한다.
"""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from common import (
    MODULE_COLORS,
    MODULE_LABELS_KO,
    RISK_BAND_BOUNDS,
    RISK_LEVEL_COLORS,
    RISK_LEVEL_ICONS,
    risk_level_color,
    risk_level_ko,
    safe_get,
    status_badge,
)

# total이 None일 때(스코어링 아직 미반영/전부 실패) UI 확인용으로 그리는 더미.
# aggregate_risk()의 실제 출력과 "같은 형태"라, 실제 계산이 붙으면 이 뷰 코드는
# 그대로 살아난다("했다고 치고" 자리). 실측과 구분되게 배너를 띄운다.
_DUMMY_RISK = {
    "total": 0.72,
    "level": "high",
    "breakdown": {
        "modules": {
            "static": {"available": True, "weight": 0.4, "sub_score": 0.85},
            "dynamic": {"available": True, "weight": 0.3, "sub_score": 0.70,
                        "plaintext_candidate_count": 2, "hook_counts": {"cipher": 2, "base64": 1}},
            "network": {"available": True, "weight": 0.3, "sub_score": 0.57,
                        "suspicious_domain_count": 1, "suspicious_ip_count": 1},
        },
        "weights_applied": {"static": 0.4, "dynamic": 0.3, "network": 0.3},
        "unavailable": [],
    },
}


def render(report: dict) -> None:
    risk = report.get("risk_score") or {}
    total = risk.get("total")

    st.markdown("### 종합 위험도")

    is_dummy = total is None
    if is_dummy:
        st.warning(
            "종합 위험도 계산 결과가 아직 없습니다(모듈 실패 또는 스코어링 미반영). "
            "아래는 **UI 확인용 예시(더미) 데이터**이며 실제 분석 결과가 아닙니다.",
            icon="🧪",
        )
        risk = _DUMMY_RISK
        total = risk["total"]

    level = risk.get("level") or "unknown"
    score100 = round(total * 100)

    # ── 1. 히어로 점수 + 등급 배지 ──
    _render_headline(score100, level)

    # ── 2. 게이지 (0~100, 저/중/고 구간색) ──
    st.altair_chart(_gauge_chart(score100, level), width="stretch")

    st.divider()

    # ── 3. 모듈별 기여도 ──
    st.markdown("#### 모듈별 기여도")
    st.caption("종합 점수는 각 모듈 하위점수(0~100)에 재정규화 가중치를 곱해 합산한 값입니다.")
    _render_breakdown(risk)

    st.divider()

    # ── 4. 모듈 상태 요약 (A 골격에서 유지) ──
    st.markdown("#### 모듈별 상태")
    cols = st.columns(3)
    for col, (name, label) in zip(cols, MODULE_LABELS_KO.items()):
        status = safe_get(report, "modules", name, "status")
        col.markdown(f"**{label}**  \n{status_badge(status)}")


def _render_headline(score100: int, level: str) -> None:
    color = risk_level_color(level)
    icon = RISK_LEVEL_ICONS.get(level, "⚪")
    label_ko = risk_level_ko(level)
    # st.markdown의 :color[] 문법은 임의 hex를 못 받아서 HTML로 배지를 그린다.
    st.markdown(
        f"""
        <div style="display:flex; align-items:baseline; gap:16px; margin:4px 0 8px;">
          <span style="font-size:56px; font-weight:700; line-height:1; color:{color};">
            {score100}<span style="font-size:24px; color:#898781;"> / 100</span>
          </span>
          <span style="display:inline-block; padding:6px 16px; border-radius:999px;
                       background:{color}; color:#ffffff; font-size:20px; font-weight:700;">
            {icon} {label_ko}
          </span>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _gauge_chart(score100: int, level: str) -> alt.LayerChart:
    """0~100 선형 게이지. 저/중/고 구간을 옅은 status 색 밴드로 깔고, 현재 점수를
    진한 눈금(rule) + 점으로 표시한다. 밴드 경계는 RISK_BAND_BOUNDS(=aggregator
    임계값)와 동일하다."""
    prev = 0
    band_rows = []
    for upper, lvl in RISK_BAND_BOUNDS:
        band_rows.append({"start": prev, "end": upper, "level": lvl,
                          "구간": risk_level_ko(lvl)})
        prev = upper
    bands = pd.DataFrame(band_rows)

    level_domain = [risk_level_ko(l) for _, l in RISK_BAND_BOUNDS]
    level_range = [RISK_LEVEL_COLORS[l] for _, l in RISK_BAND_BOUNDS]

    band_layer = (
        alt.Chart(bands)
        .mark_bar(height=26, cornerRadius=4)
        .encode(
            x=alt.X("start:Q", scale=alt.Scale(domain=[0, 100]),
                    axis=alt.Axis(title=None, values=[0, 34, 67, 100], grid=False)),
            x2="end:Q",
            color=alt.Color("구간:N",
                            scale=alt.Scale(domain=level_domain, range=level_range),
                            legend=alt.Legend(title=None, orient="bottom")),
            opacity=alt.value(0.30),
            tooltip=[alt.Tooltip("구간:N"), alt.Tooltip("start:Q", title="이상"),
                     alt.Tooltip("end:Q", title="미만")],
        )
    )

    marker_df = pd.DataFrame({"score": [score100]})
    rule = (
        alt.Chart(marker_df)
        .mark_rule(size=3, color="#0b0b0b")
        .encode(x="score:Q", tooltip=[alt.Tooltip("score:Q", title="종합 점수")])
    )
    dot = (
        alt.Chart(marker_df)
        .mark_point(size=140, filled=True, color=risk_level_color(level),
                    stroke="#ffffff", strokeWidth=2)
        .encode(x="score:Q", tooltip=[alt.Tooltip("score:Q", title="종합 점수")])
    )
    return (band_layer + rule + dot).properties(height=70)


def _render_breakdown(risk: dict) -> None:
    modules = safe_get(risk, "breakdown", "modules", default={}) or {}
    unavailable = safe_get(risk, "breakdown", "unavailable", default=[]) or []

    rows = []
    for name in ("static", "dynamic", "network"):
        m = modules.get(name) or {}
        if not m.get("available"):
            continue
        sub = float(m.get("sub_score") or 0.0)
        weight = float(m.get("weight") or 0.0)
        rows.append({
            "module": name,
            "모듈": MODULE_LABELS_KO[name],
            "기여도": round(sub * weight * 100, 1),   # 종합 점수에 실제로 더해진 몫
            "하위점수": round(sub * 100, 1),           # 그 모듈 자체 위험도(0~100)
            "가중치": round(weight, 2),
        })

    if not rows:
        st.info("기여도를 계산할 수 있는 모듈이 없습니다.")
        return

    df = pd.DataFrame(rows)
    module_domain = [MODULE_LABELS_KO[r["module"]] for r in rows]
    module_range = [MODULE_COLORS[r["module"]] for r in rows]

    bars = (
        alt.Chart(df)
        .mark_bar(cornerRadiusEnd=4, height=26)
        .encode(
            x=alt.X("기여도:Q", title="종합 점수 기여도 (점)",
                    scale=alt.Scale(domain=[0, max(1, df["기여도"].max()) * 1.25])),
            y=alt.Y("모듈:N", sort="-x", title=None),
            color=alt.Color("모듈:N",
                            scale=alt.Scale(domain=module_domain, range=module_range),
                            legend=None),
            tooltip=[alt.Tooltip("모듈:N"), alt.Tooltip("기여도:Q", title="기여도(점)"),
                     alt.Tooltip("하위점수:Q", title="모듈 위험도(0~100)"),
                     alt.Tooltip("가중치:Q")],
        )
    )
    # 라이트 모드 magenta 대비 WARN → 직접 라벨로 relief.
    labels = bars.mark_text(align="left", dx=4, color="#0b0b0b").encode(
        text=alt.Text("기여도:Q", format=".1f")
    )
    st.altair_chart((bars + labels).properties(height=len(rows) * 44 + 10),
                    width="stretch")

    # 표 병기 (relief 규칙 + 근거 확인용)
    st.dataframe(
        df[["모듈", "기여도", "하위점수", "가중치"]],
        hide_index=True,
        width="stretch",
    )

    if unavailable:
        excluded = ", ".join(MODULE_LABELS_KO.get(n, n) for n in unavailable)
        st.caption(f"⚪ 점수에서 제외된 모듈(실패/타임아웃): {excluded} — 남은 모듈끼리 가중치를 재정규화했습니다.")
