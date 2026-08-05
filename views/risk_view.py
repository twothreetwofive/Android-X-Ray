"""
views/risk_view.py — 종합 위험도 패널 (역할 D 담당)

TODO(D): render() 안쪽을 실제 시각화로 채워주세요. 지금은 A(예원)가 자리만
만들어둔 상태입니다.

받는 데이터: report["risk_score"] = {"total": float|None, "level": str|None,
"breakdown": list|None} — 6주차 main.py는 이 필드를 인터페이스만 만들어두고
값은 비워뒀다(전부 None). 종합 위험도 계산 로직(6주차 역할4 담당)이 실제 값을
채우면 여기서 그 값을 그대로 시각화하면 된다.

받는 데이터 (교차 참고용): report["modules"]["static"]/"dynamic"/"network"도
그대로 접근 가능 — 예를 들어 B가 제안한 "정적 strings.urls/ip_addresses ↔
네트워크 suspicious.domains/ips 교차 검증"을 여기서 구현해도 자연스럽다.

주의: total이 None인 상태(=아직 스코어링 로직 미완성 또는 입력 모듈들이
전부 실패)를 0점(안전)으로 잘못 표시하지 않도록 반드시 분기 처리할 것.
"""
from __future__ import annotations

import streamlit as st

from common import safe_get, status_badge


def render(report: dict) -> None:
    risk = report.get("risk_score") or {}
    total = risk.get("total")
    level = risk.get("level")

    st.markdown(f"### 종합 위험도")

    if total is None:
        st.info("종합 위험도 계산 로직이 아직 반영되지 않았습니다 (역할4 작업 대기).")
    else:
        col1, col2 = st.columns(2)
        with col1:
            st.metric("종합 점수", total)
        with col2:
            st.metric("등급", level or "-")

    # TODO(D): 아래를 실제 시각화로 교체.
    # 예시 아이디어 (원하는 대로 바꿔도 됨):
    #   - breakdown을 근거별 막대그래프로 (정적/동적/네트워크 기여도)
    #   - 게이지 차트 (0~100, 저/중/고 구간 색으로 구분 — common.STATUS_COLORS 톤과 맞출 것)
    #   - 모듈별 status_badge를 한눈에 모아 보여주는 요약 행
    st.markdown("**모듈별 상태 요약**")
    for name, label in [("static", "정적"), ("dynamic", "동적"), ("network", "네트워크")]:
        status = safe_get(report, "modules", name, "status")
        st.markdown(f"- {label}: {status_badge(status)}")

    if risk.get("breakdown"):
        st.json(risk["breakdown"])
