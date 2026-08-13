"""
views/verdict_header.py — 화면 최상단 "APK 보안 분석 결과" 카드 (8주차 신규)

8주차 계획수정 PDF의 "내가 추천하는 최종 구조"를 그대로 옮긴 것이다:

                APK 보안 분석 결과
             ⚠ 의심 (SUSPICIOUS)
          종합 위험도  64 / 100
    ─────────────────────────────────
    분석 상태
      정적 분석      ✅ 분석 성공
      동적 분석      ✅ 분석 성공
      네트워크 분석  ✅ 분석 성공

핵심은 **두 층을 시각적으로 분리**하는 것이다.
  - 위층(보안 판정) = 이 앱이 얼마나 위험한가
  - 아래층(분석 상태) = 파이프라인이 돌았는가
7주차까지는 이 둘이 같은 "정상/실패" 표현으로 섞여 있어서, 평문 후보 35건이
나온 취약 APK가 세 모듈 "✅ 정상"으로 표시됐다. 그게 이 파일이 생긴 이유다.

탭 안이 아니라 탭 위에 두는 이유: 판정은 어느 탭을 보고 있든 항상 보여야 한다.
"""
from __future__ import annotations

import streamlit as st

from common import (
    DISCLAIMER,
    MODULE_LABELS_KO,
    safe_get,
    status_badge,
    verdict_color,
    verdict_icon,
    verdict_ko,
)

# 판정 코드 옆에 같이 적을 영문 표기 (PDF의 "⚠ 의심 (SUSPICIOUS)" 형식)
_VERDICT_EN = {
    "normal": "NORMAL",
    "caution": "CAUTION",
    "suspicious": "SUSPICIOUS",
    "high_risk": "HIGH RISK",
    "malicious": "MALICIOUS",
    "unknown": "UNDETERMINED",
}


def render(report: dict) -> None:
    risk = report.get("risk_score") or {}
    verdict = risk.get("verdict") or {}
    code = verdict.get("code") or risk.get("level") or "unknown"
    score100 = risk.get("score100")
    if score100 is None and risk.get("total") is not None:
        score100 = round(risk["total"] * 100)

    color = verdict_color(code)
    icon = verdict_icon(code)
    label = verdict_ko(code)
    label_en = _VERDICT_EN.get(code, code.upper())

    # 점수를 못 낸 경우 숫자 자리에 0을 넣지 않는다 — 0점이 "안전"으로 읽힌다.
    score_html = (
        f'{score100}<span style="font-size:20px; opacity:.75;"> / 100</span>'
        if score100 is not None
        else '<span style="opacity:.75;">판정 불가</span>'
    )

    st.markdown(
        f"""
        <div style="border:2px solid {color}; border-radius:12px; padding:18px 20px;
                    margin:4px 0 14px; text-align:center;">
          <div style="font-size:14px; letter-spacing:.08em; opacity:.75; margin-bottom:6px;">
            APK 보안 분석 결과
          </div>
          <div style="font-size:30px; font-weight:800; color:{color}; line-height:1.25;">
            {icon} {label} <span style="font-size:17px; font-weight:600; opacity:.8;">({label_en})</span>
          </div>
          <div style="font-size:32px; font-weight:700; margin-top:8px;">
            <span style="font-size:15px; font-weight:600; opacity:.75;">종합 위험도 </span>{score_html}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    _render_status_row(report)
    st.caption(f"⚠️ {DISCLAIMER}")


def _render_status_row(report: dict) -> None:
    """분석 상태 3종. 보안 판정과 같은 카드 안에 두되 라벨로 층을 확실히 나눈다."""
    st.markdown("**분석 상태** &nbsp;<span style='opacity:.7;font-size:13px;'>"
                "(앱의 안전 여부가 아니라, 각 분석이 실행에 성공했는지를 뜻합니다)</span>",
                unsafe_allow_html=True)
    cols = st.columns(3)
    for col, (name, label) in zip(cols, MODULE_LABELS_KO.items()):
        status = safe_get(report, "modules", name, "status")
        col.markdown(f"{label} 분석 &nbsp; {status_badge(status)}")
