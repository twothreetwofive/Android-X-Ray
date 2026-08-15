"""
views/risk_view.py — 종합 위험도 패널 (역할 D 담당, 대시보드의 얼굴)

받는 데이터: report["risk_score"] = src/risk_aggregator.aggregate_risk()의 출력.
    {
      "total": float(0.0~1.0) | None,
      "score100": int | None,
      "level": 판정 코드,
      "verdict": {"code", "band_code", "strong_indicators", "malicious_rule"},
      "indicators": {"static": [...], "dynamic": [...], "network": [...]},
      "breakdown": {"modules": {...}, "weights_applied": {...}, "unavailable": [...]},
    }

8주차 구조 변경 (계획수정 PDF 3~5항)
------------------------------------
화면을 네 층으로 나눈다. 이전에는 점수·게이지·기여도만 있어서 "분석이 성공했는가"와
"무엇이 발견됐는가"가 구분되지 않았다.

    1. 위험 지표    — 무엇이 발견됐는가 (관찰 사실, 점수와 별개)
    2. 모듈별 위험도 — 정적/동적/네트워크 각각 XX/100
    3. 게이지 + 기여도 — 종합 점수가 어떻게 나왔는가
    4. 판정 근거 + 주의 문구 — 왜 이 판정인가, 그리고 이것이 확정이 아니라는 고지

최종 판정 배지와 분석 상태 3종은 이 탭이 아니라 화면 최상단(views/verdict_header.py)에
있다 — 어느 탭을 보고 있든 판정이 보여야 하기 때문.

주의(A가 골격에 남긴 것 유지): total이 None인 상태를 0점(안전)으로 오독하지 않게
분기한다. UI 확인용 더미는 st.session_state["risk_view_demo"]를 켤 때만 나온다
(demo_risk.py 참고).
"""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from common import (
    DISCLAIMER,
    MODULE_COLORS,
    MODULE_LABELS_KO,
    VERDICT_BAND_BOUNDS,
    VERDICT_COLORS,
    VERDICT_ICONS,
    safe_get,
    status_badge,
    verdict_color,
    verdict_ko,
)

# UI 확인용 더미. aggregate_risk()의 실제 출력과 "같은 형태"라 기기/샘플 없이도
# 화면을 손볼 수 있다. 실측 리포트에서 저절로 튀어나오면 안 되므로 DEMO_FLAG를
# 켠 경우에만 쓴다.
DEMO_FLAG = "risk_view_demo"

_DUMMY_RISK = {
    "total": 0.72,
    "score100": 72,
    "level": "suspicious",
    "verdict": {
        "code": "suspicious",
        "band_code": "suspicious",
        "score100": 72,
        "strong_indicators": [
            {"code": "suspicious_domain", "label": "의심 도메인", "value": "3건", "module": "network"},
        ],
        "malicious_rule": {"min_score": 80, "min_indicators": 3,
                           "strong_indicator_count": 1, "met": False},
    },
    "indicators": {
        "static": [{"code": "obfuscation", "label": "난독화", "value": "탐지", "strong": False}],
        "dynamic": [{"code": "plaintext", "label": "평문 후보", "value": "2건", "strong": False}],
        "network": [{"code": "suspicious_domain", "label": "의심 도메인", "value": "3건", "strong": True}],
    },
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

    score100 = risk.get("score100")
    if score100 is None:
        score100 = round(total * 100)
    verdict = risk.get("verdict") or {}
    code = verdict.get("code") or risk.get("level") or "unknown"

    # ── 1. 위험 지표 — "무엇이 발견됐는가" ──
    _render_indicator_section(risk)

    st.divider()

    # ── 2. 모듈별 위험도 ──
    _render_module_scores(risk)

    st.divider()

    # ── 3. 게이지 + 기여도 ──
    st.markdown("#### 종합 위험도")
    st.altair_chart(_gauge_chart(score100, code), width="stretch")
    st.markdown(_band_legend_html(), unsafe_allow_html=True)
    st.caption(
        "구간: 0–29 정상 · 30–59 주의 · 60–79 의심 · 80–100 고위험 "
        "(‘악성’은 점수만으로 주지 않고 강한 지표가 여러 개 충족될 때만 표시)"
    )

    st.markdown("#### 모듈별 기여도")
    st.caption("종합 점수는 각 모듈 하위점수(0~100)에 재정규화 가중치를 곱해 합산한 값입니다.")
    _render_breakdown(risk)

    st.divider()

    # ── 4. 판정 근거 + 주의 문구 ──
    _render_verdict_basis(verdict)
    st.info(DISCLAIMER, icon="⚠️")


def _render_indicator_section(risk: dict) -> None:
    """모듈별 위험 지표를 한 표로 모아 보여준다.

    점수와 분리해서 보여주는 것이 핵심이다. 점수는 가중치·상한이 섞인 계산값이지만
    이쪽은 "관찰된 사실" 그대로라, 발표나 보고서에서 근거로 인용할 수 있는 건
    이쪽이다.
    """
    st.markdown("#### 위험 지표")
    st.caption("분석 과정에서 관찰된 사실입니다. 위험도 점수와는 별개이며, 그 자체로 악성을 뜻하지 않습니다.")

    indicators = risk.get("indicators") or {}
    rows = []
    for name, label in MODULE_LABELS_KO.items():
        for ind in indicators.get(name) or []:
            rows.append({
                "": "⚠️" if ind.get("strong") else "",
                "모듈": label,
                "지표": ind.get("label", ""),
                "값": str(ind.get("value", "")),
            })

    if not rows:
        st.caption("관찰된 위험 지표가 없습니다. (지표가 없다는 것이 '안전함'을 뜻하지는 않습니다)")
        return

    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    n_strong = sum(1 for r in rows if r[""] == "⚠️")
    if n_strong:
        st.caption(f"⚠️ 표시 {n_strong}건 = 양성으로 설명하기 어려운 '강한 지표' (악성 판정 규칙에 사용)")


def _render_module_scores(risk: dict) -> None:
    """정적/동적/네트워크 각각의 위험도를 0~100으로 나란히 보여준다 (PDF 최종 구조)."""
    st.markdown("#### 모듈별 위험도")
    modules = safe_get(risk, "breakdown", "modules", default={}) or {}

    cols = st.columns(3)
    for col, (name, label) in zip(cols, MODULE_LABELS_KO.items()):
        m = modules.get(name) or {}
        if m.get("available"):
            sub = float(m.get("sub_score") or 0.0)
            col.metric(f"{label} 위험도", f"{round(sub * 100)} / 100")
        else:
            # 점수를 못 낸 모듈에 0을 적으면 "위험 없음"으로 읽힌다.
            reason = m.get("reason_ko") or "점수를 산정할 수 없는 모듈입니다."
            col.metric(f"{label} 위험도", "—", help=reason)
            if m.get("reason") == "no_observations":
                col.caption("관측 없음 → 점수 제외")


def _render_verdict_basis(verdict: dict) -> None:
    """왜 이 판정이 나왔는지 — 특히 '악성'이 아닌 이유까지 밝힌다.

    PDF 5항의 요구("악성은 여러 강한 지표가 충족됐을 때만")를 화면에서 검증
    가능하게 만드는 부분이다. 규칙을 숨기지 않고 그대로 노출한다.
    """
    rule = verdict.get("malicious_rule") or {}
    if not rule:
        return

    code = verdict.get("code")
    n_strong = rule.get("strong_indicator_count", 0)
    min_score = rule.get("min_score")
    min_ind = rule.get("min_indicators")
    score100 = verdict.get("score100")

    st.markdown("#### 판정 근거")
    if rule.get("met"):
        names = ", ".join(
            f"{MODULE_LABELS_KO.get(i.get('module'), i.get('module'))}: {i.get('label')}"
            for i in verdict.get("strong_indicators") or []
        )
        st.markdown(
            f"- 종합 점수 **{score100}점** ≥ {min_score}점 **그리고** "
            f"강한 지표 **{n_strong}개** ≥ {min_ind}개 → **악성**으로 판정"
        )
        st.markdown(f"- 충족된 강한 지표: {names}")
    else:
        st.markdown(
            f"- 현재 판정: **{verdict_ko(code)}** (점수 구간 기준)"
        )
        st.markdown(
            f"- **‘악성’으로 표시하지 않은 이유**: 악성 판정은 종합 점수 {min_score}점 이상"
            f" **그리고** 강한 지표 {min_ind}개 이상을 **둘 다** 충족해야 합니다"
            f" (현재 점수 {score100}점 / 강한 지표 {n_strong}개)."
        )
        st.caption(
            "취약점 실습용 APK는 평문 처리·테스트 서버 통신 때문에 점수가 쉽게 올라갑니다. "
            "그것은 '취약'이지 '악성'이 아니므로 두 조건을 모두 요구합니다."
        )


def _render_module_status(report: dict) -> None:
    st.markdown("#### 모듈별 분석 상태")
    st.caption("앱의 안전 여부가 아니라, 각 분석이 실행에 성공했는지를 뜻합니다.")
    cols = st.columns(3)
    for col, (name, label) in zip(cols, MODULE_LABELS_KO.items()):
        status = safe_get(report, "modules", name, "status")
        col.markdown(f"**{label}**  \n{status_badge(status)}")


def _render_unknown(report: dict) -> None:
    """total=None — 점수를 낼 수 없는 상태. 숫자도 게이지도 그리지 않는다.

    빈 게이지나 0점을 그리면 "위험도 0 = 안전"으로 정반대로 읽히므로, 점수 자리에는
    "판정 불가"만 두고 대신 **왜 못 냈는지**를 보여준다(어느 모듈이 죽었는지).
    """
    color = VERDICT_COLORS["unknown"]
    st.markdown(
        f"""
        <div style="display:flex; align-items:baseline; gap:16px; margin:4px 0 8px;">
          <span style="font-size:56px; font-weight:700; line-height:1; color:{color};">
            —<span style="font-size:24px; color:#898781;"> / 100</span>
          </span>
          <span style="display:inline-block; padding:6px 16px; border-radius:999px;
                       background:{color}; color:#ffffff; font-size:20px; font-weight:700;">
            {VERDICT_ICONS['unknown']} {verdict_ko('unknown')}
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


def _band_legend_html() -> str:
    """게이지 아래에 둘 판정 구간 범례를 HTML로 만든다.

    vega 하단 범례가 짧은 게이지 높이에서 잘려서, 색만 게이지 밴드와 동일하게
    맞춘 칩 형태 범례로 대체한다. flex-wrap이라 화면이 좁아도 줄바꿈될 뿐
    잘리지 않는다. 색·라벨·순서는 VERDICT_BAND_BOUNDS(=게이지 밴드)와 같은 소스다.
    """
    chips = []
    for _upper, code in VERDICT_BAND_BOUNDS:
        color = VERDICT_COLORS[code]
        label = verdict_ko(code)
        chips.append(
            '<span style="display:inline-flex; align-items:center; gap:6px; '
            'margin:0 16px 4px 0; font-size:13px; white-space:nowrap;">'
            f'<span style="width:14px; height:14px; border-radius:3px; '
            f'background:{color}; display:inline-block;"></span>{label}</span>'
        )
    return (
        '<div style="display:flex; flex-wrap:wrap; justify-content:center; '
        'margin:-6px 0 2px;">' + "".join(chips) + "</div>"
    )


def _gauge_chart(score100: int, verdict_code: str) -> alt.LayerChart:
    """0~100 선형 게이지. 판정 구간을 옅은 색 밴드로 깔고, 현재 점수를 진한
    눈금(rule) + 점으로 표시한다. 밴드 경계는 VERDICT_BAND_BOUNDS(=aggregator의
    VERDICT_BANDS)와 동일하다."""
    prev = 0
    band_rows = []
    for upper, code in VERDICT_BAND_BOUNDS:
        band_rows.append({"start": prev, "end": upper, "code": code,
                          "구간": verdict_ko(code)})
        prev = upper
    bands = pd.DataFrame(band_rows)

    band_domain = [verdict_ko(c) for _, c in VERDICT_BAND_BOUNDS]
    band_range = [VERDICT_COLORS[c] for _, c in VERDICT_BAND_BOUNDS]

    band_layer = (
        alt.Chart(bands)
        .mark_bar(height=26, cornerRadius=4)
        .encode(
            x=alt.X("start:Q", scale=alt.Scale(domain=[0, 100]),
                    axis=alt.Axis(title=None, values=[0, 30, 60, 80, 100], grid=False)),
            x2="end:Q",
            # 범례는 vega 하단 범례(orient="bottom") 대신 HTML로 그린다.
            # 게이지 높이가 70px로 짧아 하단 가로 범례가 렌더 공간 밖으로 밀려
            # 잘리는 문제가 있었다(streamlit+vega). _band_legend_html()이 대신한다.
            color=alt.Color("구간:N",
                            scale=alt.Scale(domain=band_domain, range=band_range),
                            legend=None),
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
        .mark_point(size=140, filled=True, color=verdict_color(verdict_code),
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
        st.caption(
            f"⚪ 점수에서 제외된 모듈: {excluded} — 남은 모듈끼리 가중치를 재정규화했습니다. "
            "**관측된 데이터가 없는 모듈은 0점(=안전)이 아니라 '정보 없음'으로 처리합니다.**"
        )
