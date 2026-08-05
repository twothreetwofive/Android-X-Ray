"""
views/dynamic_view.py — 동적 분석 결과 시각화 (역할 C, 김은아 담당)

TODO(C): render() 안쪽을 실제 시각화로 채워주세요. 지금은 A(예원)가 자리만
만들어둔 상태라 상태 배지 + 원본 JSON만 보여줍니다.

받는 데이터: report["modules"]["dynamic"] = {
    "status": "ok" | "partial" | "failed" | "timeout",
    "data": DynamicAnalysisResult 원본(dict) 또는 None,
    "error": str | None,
    "crashed": bool,   # ScenarioResult.crashed — 다른 모듈엔 없는 dynamic만의 필드
}
DynamicAnalysisResult 필드: package_name / session_duration_sec /
total_events_captured / total_events_filtered / events / plaintext_candidates /
errors. events의 각 항목은 hook_type/timestamp/class_name/method_name/
raw_value/extra/thread_id.

주의: "crashed": true인데 status가 "failed"인 경우와, crashed는 false인데
다른 이유로 실패한 경우를 구분해서 보여주면 좋다(사용자가 "왜 실패했는지"
바로 알 수 있게). data가 None이면 크래시로 report 자체를 못 만든 경우다.
"""
from __future__ import annotations

import streamlit as st

from common import render_errors, render_module_header, safe_get


def render(report: dict) -> None:
    module = render_module_header(report, "dynamic", "동적 분석")
    data = module.get("data")

    if module.get("crashed"):
        st.error("분석 중 앱이 크래시했습니다.")

    if data is None:
        st.warning("동적 분석 결과가 없습니다.")
        return

    # TODO(C): 아래를 실제 시각화로 교체.
    # 예시 아이디어 (원하는 대로 바꿔도 됨):
    #   - total_events_captured 대비 total_events_filtered 비율 (노이즈 필터링 효과)
    #   - hook_type별 이벤트 개수 막대그래프 (string_builder/base64/cipher/custom_xor)
    #   - plaintext_candidates를 표로 - 평문 후보 문자열 목록
    #   - events 타임라인 (timestamp 순 정렬)
    col1, col2 = st.columns(2)
    with col1:
        st.metric("원본 이벤트 수", safe_get(data, "total_events_captured", default="?"))
    with col2:
        st.metric("필터링 후", safe_get(data, "total_events_filtered", default="?"))

    st.json(data)
    render_errors(safe_get(data, "errors"))
