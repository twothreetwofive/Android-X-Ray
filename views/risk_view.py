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
전부 실패)를 0점(안전)으로 오독하지 않게 분기한다.

total=None일 때의 표시 (8주차 Day1에 변경 — 아래 경위 참고):
    "판정 불가"(회색, common의 unknown 상태)를 그린다. 점수도 게이지도 그리지 않는다.
    UI 확인용 더미는 st.session_state["risk_view_demo"] = True 로 명시적으로 켤 때만
    나온다(demo_risk.py 참고).

    7주차에는 total=None이면 배너를 띄우고 곧바로 더미(72점 "위험")를 그렸다. 그때는
    aggregate_risk()가 아직 배선 전이라 "했다고 치고" 자리로서 맞는 선택이었지만,
    PR #8로 실제 계산이 main.py에 붙은 뒤로는 total=None이 "스코어링 미반영"이 아니라
    "세 모듈이 전부 실패"라는 뜻이 됐다. 즉 분석이 통째로 실패한 리포트에서 56px 짜리
    빨간 "72 / 100 위험"이 뜬다 — 배너가 있어도 발표 화면에서는 그 숫자가 먼저 읽힌다.
    aggregate_risk()가 total=None, level="unknown"을 굳이 따로 두는 이유(실패를 0.0=안전
    으로 오해하지 않게)와도 어긋나서, common의 unknown 상태를 그대로 쓰도록 바꿨다.
    (B가 tests/test_static_view_render.py의 "모듈 전체 실패" 케이스에서 발견)
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

# UI 확인용 더미. aggregate_risk()의 실제 출력과 "같은 형태"라 기기/샘플 없이도
# 게이지·기여도 화면을 손볼 수 있다. 실측 리포트에서 저절로 튀어나오면 안 되므로
# DEMO_FLAG를 켠 경우에만 쓴다.
DEMO_FLAG = "risk_view_demo"

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

    # 더미는 명시적으로 켰을 때만. 실측 리포트에는 절대 섞이지 않는다.
    if total is None and st.session_state.get(DEMO_FLAG):
        st.warning(
            "아래는 **UI 확인용 예시(더미) 데이터**이며 실제 분석 결과가 아닙니다.",
            icon="🧪",
        )
        risk = _DUMMY_RISK
        total = risk["total"]

    if total is None:
        _render_unknown(report)
        return

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
    _render_module_status(report)


def _render_module_status(report: dict) -> None:
    st.markdown("#### 모듈별 상태")
    cols = st.columns(3)
    for col, (name, label) in zip(cols, MODULE_LABELS_KO.items()):
        status = safe_get(report, "modules", name, "status")
        col.markdown(f"**{label}**  \n{status_badge(status)}")


def _render_unknown(report: dict) -> None:
    """total=None — 점수를 낼 수 없는 상태. 숫자도 게이지도 그리지 않는다.

    빈 게이지나 0점을 그리면 "위험도 0 = 안전"으로 정반대로 읽히므로, 점수 자리에는
    "판정 불가"만 두고 대신 **왜 못 냈는지**를 보여준다(어느 모듈이 죽었는지).
    """
    color = RISK_LEVEL_COLORS["unknown"]
    st.markdown(
        f"""
        <div style="display:flex; align-items:baseline; gap:16px; margin:4px 0 8px;">
          <span style="font-size:56px; font-weight:700; line-height:1; color:{color};">
            —<span style="font-size:24px; color:#898781;"> / 100</span>
          </span>
          <span style="display:inline-block; padding:6px 16px; border-radius:999px;
                       background:{color}; color:#ffffff; font-size:20px; font-weight:700;">
            {RISK_LEVEL_ICONS['unknown']} {risk_level_ko('unknown')}
          </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 죽은 모듈을 직접 나열한다 — "점수가 안 나왔다"보다 "무엇을 고쳐야 점수가 나온다"가
    # 실제로 필요한 정보이기 때문.
    broken = [
        f"{label}({safe_get(report, 'modules', name, 'status') or '결과 없음'})"
        for name, label in MODULE_LABELS_KO.items()
        if safe_get(report, "modules", name, "status") not in ("ok", "partial")
    ]
    detail = f" 점수 산정에 쓸 수 있는 모듈이 없습니다 — {', '.join(broken)}." if broken else ""
    st.warning(
        "종합 위험도를 계산할 수 없습니다."
        + detail
        + " **이것은 '안전하다'는 뜻이 아니라 '판정하지 못했다'는 뜻입니다.**",
        icon="⚪",
    )

    st.divider()
    _render_module_status(report)


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
