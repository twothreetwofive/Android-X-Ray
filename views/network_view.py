"""
views/network_view.py — 네트워크 분석 결과 시각화 (역할 D 담당)

받는 데이터: report["modules"]["network"] = {
    "status": "ok" | "partial" | "failed" | "timeout",
    "data": NetworkAnalysisResult 원본(dict) 또는 None,
    "error": str | None,
}
NetworkAnalysisResult 필드: meta(package_name/capture_started_at/
capture_duration_sec/pcap_file) / dns_queries / tls_sni / suspicious(domains, ips).
pcap pull 자체가 실패하면 data가 {"meta": {...}}만 있고 dns_queries/tls_sni/
suspicious가 없을 수 있으니 safe_get으로 방어 접근한다.

구성:
1. suspicious(의심 도메인/IP)를 맨 위에 빨간색(critical) 강조 — 색만으로 전달하지
   않도록 아이콘+라벨을 함께 붙인다.
2. 화이트리스트 대비 결과 — 관측 도메인 중 통과 vs 의심 비율.
3. dns_queries / tls_sni 표 (의심 항목은 🔴 표시).
색은 common의 공용 표(status 팔레트/모듈색)를 재사용해 다른 뷰와 톤을 맞춘다.
"""
from __future__ import annotations

import altair as alt
import pandas as pd
import streamlit as st

from common import (
    VERDICT_COLORS,
    render_errors,
    render_indicators,
    render_module_header,
    safe_get,
)

_GOOD = VERDICT_COLORS["normal"]        # 통과(초록)
_CRITICAL = VERDICT_COLORS["high_risk"]  # 의심(빨강)


def render(report: dict) -> None:
    module = render_module_header(report, "network", "네트워크 분석")
    # 분석 상태 아래에 "무엇이 발견됐는가"를 나란히 둔다(8주차 계획수정 PDF 3항).
    render_indicators(safe_get(report, "risk_score", "indicators", "network", default=[]))
    data = module.get("data")

    if data is None:
        st.warning("네트워크 분석 결과가 없습니다.")
        return

    dns_queries = safe_get(data, "dns_queries", default=[]) or []
    tls_sni = safe_get(data, "tls_sni", default=[]) or []
    suspicious_domains = safe_get(data, "suspicious", "domains", default=[]) or []
    suspicious_ips = safe_get(data, "suspicious", "ips", default=[]) or []

    # ── 1. 의심 항목 강조 (맨 위) ──
    _render_suspicious(suspicious_domains, suspicious_ips)

    st.divider()

    # ── 2. 화이트리스트 대비 결과 ──
    suspicious_domain_names = {d.get("domain") for d in suspicious_domains}
    observed_domains = {q.get("domain") for q in dns_queries} | {s.get("sni") for s in tls_sni}
    observed_domains.discard(None)
    _render_whitelist_summary(observed_domains, suspicious_domain_names,
                              n_dns=len(dns_queries), n_sni=len(tls_sni),
                              n_susp_ip=len(suspicious_ips))

    st.divider()

    # ── 3. DNS / TLS 표 ──
    _render_dns_table(dns_queries, suspicious_domain_names)
    _render_sni_table(tls_sni, suspicious_domain_names)

    render_errors(safe_get(data, "errors"))


def _render_suspicious(domains: list, ips: list) -> None:
    n = len(domains) + len(ips)
    st.markdown("#### 🔴 의심 도메인 / IP")
    if n == 0:
        # 초록 success 배지를 쓰지 않는다 — 캡처가 비었을 때도 이 분기로 오기 때문에
        # "안전 확인됨"으로 읽히면 안 된다(8주차 계획수정 PDF 1항과 같은 취지).
        st.info(
            "화이트리스트를 벗어난 의심 도메인·IP가 **관찰되지 않았습니다**. "
            "트래픽 자체가 없었을 수도 있으므로 안전하다는 뜻은 아닙니다.",
            icon="ℹ️",
        )
        return

    st.error(f"화이트리스트 미포함 등으로 의심되는 항목 {n}건이 발견되었습니다 (C&C 후보).",
             icon="🚨")

    col1, col2 = st.columns(2)
    with col1:
        st.markdown(f"**의심 도메인 {len(domains)}건**")
        if domains:
            df = pd.DataFrame(domains).rename(columns={"domain": "도메인", "reason": "사유"})
            st.dataframe(_style_critical(df), hide_index=True, width="stretch")
        else:
            st.caption("없음")
    with col2:
        st.markdown(f"**의심 IP {len(ips)}건**")
        if ips:
            df = pd.DataFrame(ips).rename(columns={"ip": "IP", "reason": "사유"})
            st.dataframe(_style_critical(df), hide_index=True, width="stretch")
        else:
            st.caption("없음")


def _render_whitelist_summary(observed: set, suspicious_names: set,
                              n_dns: int, n_sni: int, n_susp_ip: int) -> None:
    st.markdown("#### 화이트리스트 대비 결과")

    total = len(observed)
    n_suspicious = len(observed & suspicious_names)
    n_pass = total - n_suspicious

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("관측 도메인", total)
    c2.metric("화이트리스트 통과", n_pass)
    c3.metric("의심 도메인", n_suspicious)
    c4.metric("DNS / TLS 레코드", f"{n_dns} / {n_sni}")

    if total == 0:
        st.caption("관측된 도메인이 없어 비율을 계산할 수 없습니다 (캡처 실패 또는 트래픽 없음).")
        return

    # 통과 vs 의심 비율 — 가로 누적 막대(status 색). 색만으로 전달 안 되게 라벨 병기.
    df = pd.DataFrame([
        {"구분": "통과", "건수": n_pass},
        {"구분": "의심", "건수": n_suspicious},
    ])
    chart = (
        alt.Chart(df)
        .mark_bar(height=30, cornerRadius=4)
        .encode(
            x=alt.X("건수:Q", stack="normalize", title="비율",
                    axis=alt.Axis(format="%")),
            color=alt.Color("구분:N",
                            scale=alt.Scale(domain=["통과", "의심"], range=[_GOOD, _CRITICAL]),
                            legend=alt.Legend(title=None, orient="bottom")),
            tooltip=["구분:N", "건수:Q"],
        )
        .properties(height=60)
    )
    st.altair_chart(chart, width="stretch")


def _render_dns_table(dns_queries: list, suspicious_names: set) -> None:
    st.markdown(f"#### DNS 조회 ({len(dns_queries)}건)")
    if not dns_queries:
        st.caption("DNS 조회 기록이 없습니다.")
        return
    rows = [{
        "의심": "🔴" if q.get("domain") in suspicious_names else "",
        "도메인": q.get("domain"),
        "응답 IP": q.get("resolved_ip") or "-",
        "시각": q.get("timestamp"),
    } for q in dns_queries]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def _render_sni_table(tls_sni: list, suspicious_names: set) -> None:
    st.markdown(f"#### TLS SNI ({len(tls_sni)}건)")
    if not tls_sni:
        st.caption("TLS SNI 기록이 없습니다.")
        return
    rows = [{
        "의심": "🔴" if s.get("sni") in suspicious_names else "",
        "SNI(목적지)": s.get("sni"),
        "목적지 IP": s.get("dest_ip") or "-",
        "포트": s.get("dest_port") or "-",
        "시각": s.get("timestamp"),
    } for s in tls_sni]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def _style_critical(df: pd.DataFrame):
    """의심 항목 표에 옅은 빨강 배경을 입힌다(색 단독이 아니라 '의심' 섹션 안 + 사유
    컬럼과 함께라 접근성 문제 없음). pandas Styler를 반환한다."""
    return df.style.set_properties(**{"background-color": "rgba(208,59,59,0.08)"})
