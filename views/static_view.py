"""
views/static_view.py — 정적 분석 결과 시각화 (역할 B, 왕은서 담당)

받는 데이터: report["modules"]["static"] = {
    "status": "ok" | "partial" | "failed" | "timeout",
    "data": analyze_static() 원본(dict) 또는 None,
    "error": str | None,
}
필드: meta / manifest / certificate / code_analysis / strings /
third_party_sdks / risk_score / errors (+ risk_breakdown, PR #2에서 추가됨).
main.py는 analyze_static() 원본을 변환 없이 그대로 통과시키므로
`schemas/static_report.schema.json`(레거시)이 아니라 `src/static_analyzer/
schema.py`의 StaticAnalysisResult 형태로 온다.

화면 구성 (5~6주차 보고서에서 이 탭에 담기로 한 것 + 7주차 계획 B 항목):
    1. 정적 분석 점수 (종합 위험도와 별개임을 라벨에 명시)
    2. 특히 주의할 권한 3종 — 문자 / 접근성 / 화면 덮어쓰기
    3. 요청 권한 표 (위험한 것부터, 악용 예시 포함)
    4. 서명 인증서 (자가 서명이면 경고)
    5. 코드에서 발견된 것 — 난독화·리플렉션·동적로딩 배지, 의심 API, 의심 문자열
    6. 외부에 열린 컴포넌트
    7. 점수 근거 (risk_breakdown)

── 이 파일에 로직을 두지 않은 이유 ──
값을 고르고 정렬하고 None을 처리하는 판단은 전부 views/static_data.py에 있고
이 파일은 그걸 화면에 배치하기만 한다. static_data.py에는 streamlit이 없어서
pytest로 검증되지만(tests/test_static_view.py), 이 파일은 눈으로 봐야만
확인된다 — 검증 가능한 쪽에 판단을 몰아두려는 것이다.

── 값이 없을 때 ──
risk_score는 계산 실패 시 0.0이 아니라 None으로 올 수 있다(그때 status는
"partial"). 0으로 표시하면 "위험도 0 = 안전"으로 오독되므로 "계산 실패"로
표시한다. min_sdk/target_sdk의 0도 값이 아니라 파싱 실패라서 구분한다.

── 색 ──
A의 common.STATUS_COLORS와 같은 streamlit 색 이름을 static_data.RISK_COLORS로
재사용한다. 7주차 계획의 "D의 위험도 게이지와 B의 권한 강조 색을 통일" 항목이라
여기서 새 hex를 정하지 않았다.

── risk_breakdown 주의 ──
data.risk_breakdown은 정적 분석 "안에서만" 나온 점수 근거다.
report["risk_score"]["breakdown"](risk_view.py가 쓰는 것)은 3개 모듈을 합친
"종합" 위험도의 근거라 서로 다르다. 이 뷰는 data.risk_breakdown만 쓴다.

참고: HANDOFF_B_to_A_D.md에서 제안한 "strings.urls/ip_addresses를 네트워크
모듈의 suspicious.domains/ips와 대조" 아이디어는 D(risk_view.py) 쪽에서 검토 중이라,
여기서는 대조 대상이 되는 주소 목록을 그대로 노출만 해 둔다.
"""
from __future__ import annotations

from typing import Any

import streamlit as st

from common import render_errors, render_indicators, render_module_header, safe_get
from views.static_data import (
    NO_VALUE,
    RISK_COLORS,
    build_breakdown_rows,
    build_certificate_rows,
    build_code_flags,
    build_exported_component_rows,
    build_highlights,
    build_meta_rows,
    build_permission_rows,
    build_strings_view,
    build_suspicious_api_rows,
    breakdown_matches_raw,
    count_by_level,
    is_self_signed,
    static_score_100,
)


def render(report: dict) -> None:
    """정적 분석 탭. 정적 분석이 실패해도 이 함수는 예외를 던지지 않는다 —
    "한 모듈이 죽어도 나머지는 계속 진행"이 대시보드에서도 지켜지는지가
    7주차 검증 항목이라, 여기서 예외가 나면 탭 하나가 아니라 app.py가 통째로
    죽는다."""
    module = render_module_header(report, "static", "정적 분석")
    # 분석 상태 바로 아래에 "무엇이 발견됐는가"를 붙인다 — 두 층을 같이 읽히게
    # 하려는 것(8주차 계획수정 PDF 3항).
    render_indicators(safe_get(report, "risk_score", "indicators", "static", default=[]))
    data = module.get("data")

    if data is None:
        st.warning("정적 분석 결과가 없습니다. 위 오류 내용을 확인해 주세요.")
        return

    errors = safe_get(data, "errors")
    if errors:
        # 접지 않고 펼친 채로 띄운다. analyze_static()은 하위 단계가 실패해도
        # 예외를 던지지 않아서, 이걸 안 보면 코드 스캔이 전부 실패한 결과도
        # 정상 결과로 오해하게 된다.
        st.warning(
            f"일부 단계가 실패했습니다({len(errors)}건). 아래 값이 불완전할 수 있습니다."
        )

    _render_score(data)
    st.divider()
    _render_highlights(data)
    _render_permissions(data)
    st.divider()
    _render_certificate(data)
    _render_code_and_strings(data)
    _render_components(data)
    _render_breakdown(data)
    _render_meta(data)

    render_errors(errors)


# ────────────────────────────────────────────────────────────

def _render_score(data: Any) -> None:
    score = static_score_100(data)

    col_score, col_note = st.columns([1, 2])
    with col_score:
        st.metric("정적 분석 점수", NO_VALUE if score is None else f"{score} / 100")
    with col_note:
        st.caption("정적 분석만으로 낸 점수입니다. 종합 위험도 탭의 값과는 다릅니다.")
        if score is not None:
            st.progress(min(score / 100, 1.0))

    if score is None:
        st.caption(
            "점수를 0으로 표시하지 않는 이유: 계산 실패를 0점으로 적으면 "
            "'위험도 0 = 안전한 앱'으로 잘못 읽히기 때문입니다."
        )


def _render_highlights(data: Any) -> None:
    highlights = build_highlights(build_permission_rows(data))

    st.markdown("#### 특히 주의할 권한")
    st.caption("뱅킹 트로이목마(Anubis 등)가 함께 요구하는 3종입니다.")

    for col, item in zip(st.columns(len(highlights)), highlights):
        with col:
            st.markdown(f"**{item['group']}**")
            if item["detected"]:
                st.markdown(f":{RISK_COLORS['high']}[**검출**]")
                for short in item["short_names"]:
                    st.caption(short)
            else:
                st.markdown(f":{RISK_COLORS['low']}[없음]")


def _render_permissions(data: Any) -> None:
    rows = build_permission_rows(data)

    st.markdown("#### 요청 권한")
    if not rows:
        st.info("권한 정보를 읽지 못했거나 요청한 권한이 없습니다.")
        return

    counts = count_by_level(rows)
    st.caption(
        f"총 {len(rows)}개 — 높음 {counts['high']}개 / 중간 {counts['medium']}개 "
        f"/ 낮음 {counts['low']}개 (위험한 권한부터 정렬)"
    )

    st.dataframe(
        [
            {
                "권한": r["short_name"],
                "위험도": r["risk_label"],
                "가중치": r["weight"],
                "악용 예시": r["abuse_example"],
            }
            for r in rows
        ],
        width="stretch",
        hide_index=True,
    )


def _render_certificate(data: Any) -> None:
    st.markdown("#### 서명 인증서")

    cert_rows = build_certificate_rows(data)
    if cert_rows is None:
        st.info("인증서 정보를 읽지 못했습니다.")
        return

    if is_self_signed(data):
        st.warning(
            "자가 서명 인증서입니다. 누가 만든 앱인지 제3자가 보증하지 않는다는 뜻이며, "
            "정식 스토어를 거치지 않고 배포된 앱에서 주로 보입니다."
        )

    st.dataframe(cert_rows, width="stretch", hide_index=True)


def _render_code_and_strings(data: Any) -> None:
    st.markdown("#### 코드에서 발견된 것")

    flags = build_code_flags(data)
    for col, flag in zip(st.columns(len(flags)), flags):
        with col:
            st.markdown(f"**{flag['label']}**")
            if flag["on"]:
                st.markdown(f":{RISK_COLORS['medium']}[**발견**]")
            else:
                st.markdown(f":{RISK_COLORS['low']}[없음]")

    api_rows = build_suspicious_api_rows(data)
    if api_rows:
        with st.expander(f"의심 API 호출 {len(api_rows)}건"):
            st.dataframe(api_rows, width="stretch", hide_index=True)

    strings = build_strings_view(data)
    for key, label in (
        ("suspicious_strings", "의심 문자열"),
        ("urls", "코드에 하드코딩된 URL"),
        ("ip_addresses", "코드에 하드코딩된 IP"),
    ):
        values = strings[key]
        if not values:
            continue
        with st.expander(f"{label} {len(values)}건"):
            if key in ("urls", "ip_addresses"):
                st.caption(
                    "네트워크 탭의 통신 목록과 겹치는 주소가 있다면, 코드에 박혀 있던 "
                    "주소로 실제 통신까지 했다는 뜻입니다."
                )
            for value in values:
                st.code(value, language=None)


def _render_components(data: Any) -> None:
    rows = build_exported_component_rows(data)
    if not rows:
        return

    with st.expander(f"외부에 열린 컴포넌트 {len(rows)}개"):
        st.caption("다른 앱이 직접 호출할 수 있는 진입점입니다. 개수만큼 점수에 반영됩니다.")
        st.dataframe(
            [
                {
                    "이름": r["name"],
                    "종류": r["type"],
                    "intent-filter": ", ".join(r["intent_filters"]) or "-",
                }
                for r in rows
            ],
            width="stretch",
            hide_index=True,
        )


def _render_breakdown(data: Any) -> None:
    rows = build_breakdown_rows(data)
    if not rows:
        return

    with st.expander("이 점수가 나온 근거"):
        if breakdown_matches_raw(data) is False:
            st.warning(
                "근거 항목의 합이 원점수(raw)와 맞지 않습니다. 점수 계산 경로를 확인해 주세요."
            )
        st.dataframe(
            [{"항목": r["label"], "점수": r["weight"]} for r in rows],
            width="stretch",
            hide_index=True,
        )


def _render_meta(data: Any) -> None:
    with st.expander("앱 기본 정보"):
        st.dataframe(build_meta_rows(data), width="stretch", hide_index=True)

    sdks = safe_get(data, "third_party_sdks", default=[])
    if sdks:
        with st.expander(f"서드파티 SDK {len(sdks)}개"):
            st.caption("점수 계산에는 반영되지 않습니다(6주차 D 확정 사항).")
            for sdk in sdks:
                st.write(f"- {sdk}")
