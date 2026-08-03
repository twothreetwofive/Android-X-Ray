"""network_analyzer/report_builder.py (D 작성, 5주차 3~4일차)

A(packet_capturer.py)/B(dns_parser.py)/C(sni_parser.py)의 출력을 받아
schema.py의 NetworkAnalysisResult(= network_report.json) 형태로 최종 조립한다.
README의 D 역할("화이트리스트 구축 + 의심 도메인/IP 판별 + 최종 조립") 중
마지막 항목을 담당하는 파일.
"""

from typing import List

from .ip_checker import find_suspicious_ips
from .schema import CaptureMeta, DnsQuery, NetworkAnalysisResult, TlsSni
from .whitelist_checker import find_suspicious_domains


def build_network_report(
    meta: CaptureMeta,
    dns_queries: List[DnsQuery],
    tls_sni: List[TlsSni],
) -> NetworkAnalysisResult:
    """A/B/C 출력을 그대로 받아 network_report.json 최종 형태로 조립한다.

    dns_queries/tls_sni는 A의 캡처가 실패하거나(예: 앱-시스템 간 통신이 전부
    루프백으로 잡혀서 실제 DNS/TLS가 하나도 안 잡힌 경우) B/C가 아직 통합 전이면
    빈 리스트일 수 있다 — 이 경우 suspicious도 빈 채로 정상 반환된다.
    """
    candidate_domains = [q["domain"] for q in dns_queries] + [s["sni"] for s in tls_sni]
    candidate_ips = [q["resolved_ip"] for q in dns_queries if q.get("resolved_ip")] + [
        s["dest_ip"] for s in tls_sni if s.get("dest_ip")
    ]

    return {
        "meta": meta,
        "dns_queries": dns_queries,
        "tls_sni": tls_sni,
        "suspicious": {
            "domains": find_suspicious_domains(candidate_domains),
            "ips": find_suspicious_ips(candidate_ips),
        },
    }


if __name__ == "__main__":
    import json

    # C가 5주차 1일차에 SNI 구조 학습용으로 실제 캡처한 도메인 목록
    # (docs/네트워크분석/유예원_5주차_C.pdf). 우리 안드로이드 앱 트래픽은 아니고
    # 일반 PC 트래픽이라 화이트리스트 최종 검증용은 아니지만, tls_sni 실데이터가
    # 파이프라인을 어떻게 통과하는지 확인하기엔 충분함.
    real_sni_sample = [
        "settings-win.data.microsoft.com",
        "velog.io",
        "content-autofill.googleapis.com",
        "login.microsoftonline.com",
        "webshell.suite.office.com",
        "www.inflearn.com",
        "www.google.com",
        "www.googleapis.com",
        "www.googleusercontent.com",
        "lh3.google.com",
        "ogads-pa.clients6.google.com",
        "lh3.googleusercontent.com",
        "github.com",
        "outlook.office.com",
        "res.public.onecdn.static.microsoft",
        "play.google.com",
        "beacons.gcp.gvt2.com",
        "outlook.cloud.microsoft",
        "loki.delve.office.com",
        "res-1.cdn.office.net",
    ]

    demo_meta: CaptureMeta = {
        "package_name": "demo.sample",
        "capture_started_at": "2026-07-25T05:55:57+00:00",
        "capture_duration_sec": 15,
        "pcap_file": "output/capture.pcap",
    }
    demo_tls_sni: List[TlsSni] = [
        {"sni": sni, "timestamp": demo_meta["capture_started_at"], "dest_ip": None, "dest_port": 443}
        for sni in real_sni_sample
    ]
    # IP 판별 검증용으로 하드코딩 공인 IP 하나, 사설 IP(에뮬레이터 대역) 하나 섞음
    demo_dns_queries: List[DnsQuery] = [
        {"domain": "1.1.1.1", "timestamp": demo_meta["capture_started_at"], "resolved_ip": "1.1.1.1"},
        {"domain": "www.google.com", "timestamp": demo_meta["capture_started_at"], "resolved_ip": "10.0.2.15"},
    ]

    report = build_network_report(demo_meta, demo_dns_queries, demo_tls_sni)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\nsuspicious.domains {len(report['suspicious']['domains'])}건")
    print(f"suspicious.ips {len(report['suspicious']['ips'])}건")
