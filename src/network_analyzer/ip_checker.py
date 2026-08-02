"""network_analyzer/ip_checker.py (D 작성, 5주차 3~4일차)

IP 기반 의심 판별. whitelist_checker.py의 1~2일차 산출물에서 4일차 범위로
남겨뒀던 suspicious.ips를 채운다.

판별 기준(3~4일차에 정한 1차 규칙):
1. 사설/루프백/링크로컬 IP는 정상 트래픽으로 간주하고 애초에 후보에서 제외한다.
   A가 5주차 실제 캡처에서 겪은 사례가 근거임 — 에뮬레이터 앱-시스템 간 통신이
   127.0.0.1 루프백으로만 잡혀서 dns_queries/tls_sni가 텅 빈 채로 나왔음
   (`docs/네트워크분석/5주차보고서(1).md`, A 5주차 과제 참고). 이런 대역까지
   suspicious로 잡으면 정상 로컬 트래픽이 전부 오탐 처리된다.
2. 남은 공인 IP는 전부 1차로 "하드코딩된 직접 접속 후보"로 분류한다. 정상 앱은
   보통 도메인을 DNS로 조회한 뒤 접속하므로, dns_queries/tls_sni에 IP만 있고
   대응하는 도메인이 없다는 것 자체가 C&C가 도메인 블록리스트를 우회하려고
   IP를 하드코딩했을 가능성을 뜻한다. 이 규칙은 "공인 IP면 전부 의심"이라 오탐이
   많을 수 있는 1차 버전이고, 실제 CDN/클라우드 IP 대역 화이트리스트는 팀 논의 후
   추가해야 한다 (README 참고).
"""

import ipaddress
from typing import List

from .schema import SuspiciousIP


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        # IP 형식이 아니면(파싱 오류 등) 내부 IP로 취급하지 않고 상위에서 걸러지게 둔다.
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    )


def is_ip_literal(value: str) -> bool:
    """domain/sni 필드에 호스트명이 아니라 IP 주소가 그대로 들어있는지 확인.

    정상적인 DNS 쿼리 도메인이나 TLS SNI는 호스트명이어야 한다. IP가 그대로
    들어있다면 DNS 조회 없이 하드코딩된 IP로 바로 접속했다는 뜻이라 의심스럽다.
    """
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def find_suspicious_ips(ips: List[str]) -> List[SuspiciousIP]:
    """사설/루프백이 아닌 공인 IP만 골라 suspicious.ips 형식으로 반환.

    dns_queries의 resolved_ip와 tls_sni의 dest_ip를 합쳐서 넘기면 된다.
    """
    seen = set()
    result: List[SuspiciousIP] = []
    for ip in ips:
        normalized = ip.strip()
        if not normalized or normalized in seen or _is_internal(normalized):
            continue
        seen.add(normalized)
        result.append(
            {"ip": normalized, "reason": "사설/루프백이 아닌 공인 IP (하드코딩된 직접 접속 후보)"}
        )
    return result


if __name__ == "__main__":
    # A가 5주차에 실제로 캡처한 값(127.0.0.1 루프백 2건) + 임의의 공인 IP 섞어서 검증
    sample_ips = [
        "127.0.0.1",
        "127.0.0.1",  # 중복 제거 확인용
        "10.0.2.15",  # 에뮬레이터 사설 대역
        "192.168.1.1",
        "8.8.8.8",  # 공인 IP (구글 DNS, 그래도 1차 규칙상 IP 리터럴이면 의심 후보)
        "1.1.1.1",  # 공인 IP (Cloudflare DNS)
        "203.0.113.7",  # TEST-NET-3(RFC 5737, 문서용 예약 대역) — Python ipaddress가
        # is_private=True로 분류해서 사설 IP와 동일하게 걸러짐 (아래 출력에서 확인 가능)
    ]
    print("=== find_suspicious_ips 검증 ===")
    for entry in find_suspicious_ips(sample_ips):
        print(entry)

    print("\n=== is_ip_literal 검증 ===")
    for value in ["googleapis.com", "8.8.8.8", "203.0.113.7", "login.microsoftonline.com"]:
        print(f"{value}: {is_ip_literal(value)}")
