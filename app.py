"""
app.py — Android X-Ray Streamlit 대시보드 진입점 (7~8주차, 역할 A 유예원 담당)

흐름: apk 업로드 -> pipeline_bridge.run()으로 분석 실행(진행상황 st.status로
표시) -> 결과를 st.session_state에 저장 -> 4개 탭(정적/동적/네트워크/종합위험도)에
각자 뷰(views/*.py) 렌더링.

B/C/D는 이 파일을 건드릴 필요 없이 views/*.py의 render(report) 함수 안쪽만
채우면 된다 — 이 파일과 common.py가 먼저 main에 merge돼 있어야 그 위에서
작업 가능(main 병합 계획 1번).

실행: `streamlit run app.py` (repo 루트에서)
"""
from __future__ import annotations

import tempfile

import streamlit as st

import pipeline_bridge
from common import safe_get
from views import dynamic_view, network_view, risk_view, static_view, verdict_header

st.set_page_config(page_title="Android X-Ray", layout="wide")

st.title("🔍 Android X-Ray")
st.caption("정상/악성 APK 정적·동적·네트워크 분석 통합 대시보드")

uploaded = st.file_uploader("분석할 APK 파일 업로드", type=["apk"])
st.caption(
    "동적·네트워크 분석을 위해 업로드한 APK를 **에뮬레이터에 설치**한 뒤 실행합니다. "
    "악성 샘플을 분석할 때는 실행 전 스냅샷을 저장해 두세요 "
    "(`bash scripts/snapshot.sh save before_run`)."
)
run_clicked = st.button("분석 시작", type="primary", disabled=uploaded is None)

if run_clicked and uploaded is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        tmp.write(uploaded.getbuffer())
        apk_path = tmp.name

    with st.status("파이프라인 실행 중...", expanded=True) as status:
        try:
            report = pipeline_bridge.run(apk_path, progress_status=status)
            status.update(label="분석 완료", state="complete")
            st.session_state["report"] = report
        except Exception as e:  # noqa: BLE001 — 대시보드 자체가 죽으면 안 됨
            status.update(label=f"분석 실패: {e}", state="error")
            st.exception(e)

report = st.session_state.get("report")

if report is None:
    st.info("APK를 업로드하고 '분석 시작'을 누르면 결과가 여기 표시됩니다.")
else:
    apk_name = safe_get(report, "apk_name", default="?")
    package_name = safe_get(report, "package_name", default="?")
    analyzed_at = safe_get(report, "analyzed_at", default="?")

    st.subheader(f"{apk_name}  ·  {package_name}")
    st.caption(f"분석 시각: {analyzed_at}")

    # 최종 보안 판정 + 분석 상태 — 탭 위에 둔다. 어느 탭을 보고 있든 판정이
    # 보여야 하고, "분석 성공"이 "안전"으로 읽히지 않게 두 층을 나눠 표시한다
    # (8주차 계획수정 PDF의 최종 구조).
    verdict_header.render(report)

    tab_static, tab_dynamic, tab_network, tab_risk = st.tabs(
        ["정적 분석", "동적 분석", "네트워크 분석", "종합 위험도"]
    )

    with tab_static:
        static_view.render(report)
    with tab_dynamic:
        dynamic_view.render(report)
    with tab_network:
        network_view.render(report)
    with tab_risk:
        risk_view.render(report)
