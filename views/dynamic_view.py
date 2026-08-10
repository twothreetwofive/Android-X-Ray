"""
views/dynamic_view.py — 동적 분석 결과 시각화 (역할 C, 김은아 담당)
"""

from __future__ import annotations

from collections import Counter

import pandas as pd
import streamlit as st

from common import render_errors, render_module_header, safe_get


def render(report: dict) -> None:
    module = render_module_header(report, "dynamic", "동적 분석")
    data = module.get("data")

    # ─────────────────────────────────────────────
    # 1. 실패 / 크래시 상태 표시
    # ─────────────────────────────────────────────

    crashed = module.get("crashed", False)
    status = module.get("status")

    if crashed:
        st.error(
            "앱 실행 중 크래시가 발생했습니다. "
            "동적 분석 결과가 일부만 존재하거나 없을 수 있습니다."
        )
    elif status == "failed":
        error_message = module.get("error")
        st.error("동적 분석에 실패했습니다.")
        if error_message:
            st.caption(f"실패 원인: {error_message}")
    elif status == "partial":
        st.warning(
            "동적 분석이 부분적으로 완료되었습니다. "
            "일부 이벤트가 누락되었을 수 있습니다."
        )
    elif status == "timeout":
        st.warning(
            "동적 분석 시간이 초과되었습니다. "
            "수집된 이벤트까지만 표시합니다."
        )

    # 분석 결과 자체가 없는 경우
    if data is None:
        st.warning("동적 분석 결과가 없습니다.")
        return

    # ─────────────────────────────────────────────
    # 2. 주요 통계
    # ─────────────────────────────────────────────

    total_captured = safe_get(
        data, "total_events_captured", default=0
    )
    total_filtered = safe_get(
        data, "total_events_filtered", default=0
    )
    plaintext_candidates = safe_get(
        data, "plaintext_candidates", default=[]
    )
    duration = safe_get(
        data, "session_duration_sec", default=0
    )

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric("원본 이벤트", total_captured)

    with col2:
        st.metric("필터링 후", total_filtered)

    with col3:
        st.metric("평문 후보", len(plaintext_candidates))

    with col4:
        st.metric("분석 시간", f"{duration:.3f}s")

    # ─────────────────────────────────────────────
    # 3. Hook Type별 이벤트 수
    # ─────────────────────────────────────────────

    events = safe_get(data, "events", default=[])

    if events:
        hook_counts = Counter(
            event.get("hook_type", "unknown")
            for event in events
            if isinstance(event, dict)
        )

        st.subheader("후킹 유형별 이벤트")

        hook_df = pd.DataFrame(
            {
                "hook_type": list(hook_counts.keys()),
                "count": list(hook_counts.values()),
            }
        ).set_index("hook_type")

        st.bar_chart(hook_df)

    # ─────────────────────────────────────────────
    # 4. 후킹 이벤트 목록
    # ─────────────────────────────────────────────

    st.subheader("후킹 이벤트")

    if not events:
        st.info("수집된 후킹 이벤트가 없습니다.")
    else:
        event_rows = []

        for event in events:
            if not isinstance(event, dict):
                continue

            event_rows.append(
                {
                    "hook_type": event.get("hook_type", "unknown"),
                    "timestamp": event.get("timestamp", ""),
                    "class_name": event.get("class_name", ""),
                    "method_name": event.get("method_name", ""),
                    "raw_value": event.get("raw_value", ""),
                    "thread_id": event.get("thread_id", ""),
                }
            )

        if event_rows:
            event_df = pd.DataFrame(event_rows)

            st.dataframe(
                event_df,
                use_container_width=True,
                hide_index=True,
            )

    # ─────────────────────────────────────────────
    # 5. 평문 후보
    # ─────────────────────────────────────────────

    st.subheader("평문 후보")

    if not plaintext_candidates:
        st.info("탐지된 평문 후보가 없습니다.")
    else:
        plaintext_df = pd.DataFrame(
            {
                "plaintext_candidate": plaintext_candidates
            }
        )

        st.dataframe(
            plaintext_df,
            use_container_width=True,
            hide_index=True,
        )

    # ─────────────────────────────────────────────
    # 6. 오류
    # ─────────────────────────────────────────────

    errors = safe_get(data, "errors", default=[])
    render_errors(errors)

    # 원본 데이터는 필요할 때만 확인
    with st.expander("원본 Dynamic Analysis JSON"):
        st.json(data)
