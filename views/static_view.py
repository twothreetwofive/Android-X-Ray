"""
views/static_view.py — 정적 분석 결과 시각화 (역할 B, 왕은서 담당)

TODO(B): render() 안쪽을 실제 시각화로 채워주세요. 지금은 A(예원)가 자리만
만들어둔 상태라 상태 배지 + 원본 JSON만 보여줍니다.

받는 데이터: report["modules"]["static"] = {
    "status": "ok" | "partial" | "failed" | "timeout",
    "data": analyze_static() 8필드 원본(dict) 또는 None,
    "error": str | None,
}
필드: meta / manifest / certificate / code_analysis / strings /
third_party_sdks / risk_score / errors (+ risk_breakdown, PR #2에서 추가됨).
main.py는 analyze_static() 원본을 필드 개수와 무관하게 변환 없이 그대로
통과시킨다(6주차_Day1_통합인터페이스_스펙.md 6-1절 참고) — 즉
`schemas/static_report.schema.json`(레거시) 형태가 아니라 `src/static_analyzer/
schema.py`의 StaticAnalysisResult 그대로 온다.

주의: risk_score는 계산 실패 시 0.0이 아니라 None으로 올 수 있다(그리고 그때
status는 "partial"). 0으로 표시하면 "위험도 0 = 안전"으로 오독되니 None 처리를
따로 해줄 것.

risk_breakdown 관련 주의(헷갈리기 쉬움): data.risk_breakdown은 정적 분석
"안에서만" 나온 점수 근거({"total","raw","breakdown":[{factor,weight},...]})다.
report["risk_score"]["breakdown"](risk_view.py가 쓰는 것)는 정적+동적+네트워크
3개를 합친 "종합" 위험도의 근거라 서로 다른 것 — 이름이 비슷해서 헷갈리기 쉬우니
주의. 정적 뷰에서는 data.risk_breakdown을 보여주면 된다.

참고: B의 HANDOFF_B_to_A_D.md에서 제안한 "strings.urls/ip_addresses를
네트워크 모듈의 suspicious.domains/ips와 대조" 아이디어는 D(risk_view.py) 쪽에서
반영 검토 중.
"""
from __future__ import annotations

import streamlit as st

from common import render_errors, render_module_header, safe_get


def render(report: dict) -> None:
    module = render_module_header(report, "static", "정적 분석")
    data = module.get("data")

    if data is None:
        st.warning("정적 분석 결과가 없습니다.")
        return

    # TODO(B): 아래를 실제 시각화로 교체.
    # 예시 아이디어 (원하는 대로 바꿔도 됨):
    #   - permissions: risk_level별로 색 다르게(고위험 강조), abuse_example 툴팁
    #   - components: exported=true인 것만 먼저 보여주고 intent_filters 같이 표시
    #   - risk_score: st.metric 또는 게이지로 (None이면 "계산 실패" 별도 표시)
    #   - code_analysis: 난독화/리플렉션/동적로딩 여부를 배지로
    risk_score = safe_get(data, "risk_score")
    if risk_score is None:
        st.metric("위험도 점수", "계산 실패")
    else:
        st.metric("위험도 점수", f"{risk_score:.2f}" if isinstance(risk_score, (int, float)) else str(risk_score))

    st.json(data)
    render_errors(safe_get(data, "errors"))
