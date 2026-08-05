"""
views/network_view.py — 네트워크 분석 결과 시각화 (역할 D 담당)

TODO(D): render() 안쪽을 실제 시각화로 채워주세요. 지금은 A(예원)가 자리만
만들어둔 상태라 상태 배지 + 원본 JSON만 보여줍니다.

받는 데이터: report["modules"]["network"] = {
    "status": "ok" | "partial" | "failed" | "timeout",
    "data": NetworkAnalysisResult 원본(dict) 또는 None,
    "error": str | None,
}
NetworkAnalysisResult 필드: meta(package_name/capture_started_at/
capture_duration_sec/pcap_file) / dns_queries / tls_sni / suspicious(domains,
ips). pcap pull 자체가 실패한 경우 data는 {"meta": {...}}만 있고 dns_queries/
tls_sni/suspicious가 없을 수 있으니 safe_get으로 방어해서 접근할 것.

참고: B가 제안한 "정적 분석 strings.urls/ip_addresses ↔ 여기 suspicious.domains/
ips 교차 검증"은 risk_view.py(종합 위험도) 쪽에서 다루는 게 자연스러울 수도
있음 — D가 두 뷰 다 담당이니 편한 쪽에 넣으면 됨.
"""
from __future__ import annotations

import streamlit as st

from common import render_errors, render_module_header, safe_get


def render(report: dict) -> None:
    module = render_module_header(report, "network", "네트워크 분석")
    data = module.get("data")

    if data is None:
        st.warning("네트워크 분석 결과가 없습니다.")
        return

    # TODO(D): 아래를 실제 시각화로 교체.
    # 예시 아이디어 (원하는 대로 바꿔도 됨):
    #   - suspicious.domains / suspicious.ips 강조 표시 (화이트리스트 미포함 = 의심)
    #   - dns_queries / tls_sni 타임라인 또는 표
    #   - 화이트리스트 통과 vs 의심 도메인 비율 파이차트
    suspicious_domains = safe_get(data, "suspicious", "domains", default=[])
    suspicious_ips = safe_get(data, "suspicious", "ips", default=[])
    col1, col2 = st.columns(2)
    with col1:
        st.metric("의심 도메인", len(suspicious_domains))
    with col2:
        st.metric("의심 IP", len(suspicious_ips))

    st.json(data)
    render_errors(safe_get(data, "errors"))
