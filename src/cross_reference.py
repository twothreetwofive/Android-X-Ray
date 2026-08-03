"""cross_reference.py

정적 분석(strings.urls - 코드에 하드코딩된 URL)과 네트워크 분석
(suspicious.domains - 실제로 통신했는데 화이트리스트에 없는 도메인)을 대조한다.
"코드에 이 주소가 박혀있고, 실제로 거기로 통신도 했다"는 두 모듈 중 하나만으로는
낼 수 없는 근거라서 static_analyzer/network_analyzer 어느 쪽에도 속하지 않는
이 파일에 둔다. main.py가 두 analyze_*() 결과를 다 갖고 있을 때 호출하면 된다.
"""

from __future__ import annotations

from typing import List, TypedDict
from urllib.parse import urlparse


class HardcodedUrlContacted(TypedDict):
    url: str
    domain: str
    reason: str  # suspicious.domains 쪽에 기록된 사유 그대로


def find_hardcoded_urls_contacted(
    urls: List[str],
    suspicious_domains: List[dict],
) -> List[HardcodedUrlContacted]:
    """코드에 하드코딩된 URL 중, 실제 캡처된 의심 도메인과 호스트명이 일치하는 것만 반환.

    Args:
        urls: static_analyzer.string_extractor.extract_strings()가 채운
            strings_data["urls"] 필드.
        suspicious_domains: network_analyzer.report_builder.build_network_report()가
            채운 network_report["suspicious"]["domains"] 필드.

    호스트명 완전 일치만 근거로 삼는다 - 서브도메인 매칭(whitelist_checker.is_whitelisted
    같은) 방식은 여기선 안 씀. "코드에 박힌 주소로 실제 통신했다"는 강한 증거를 내려는
    목적이라, 애매한 퍼지 매칭으로 오탐을 만들기보다는 정확히 같은 호스트명일 때만
    잡는 게 맞다.
    """
    reason_by_domain = {d["domain"]: d["reason"] for d in suspicious_domains}

    seen = set()
    result: List[HardcodedUrlContacted] = []
    for url in urls:
        host = urlparse(url).hostname
        if not host:
            continue
        host = host.lower().rstrip(".")
        if host not in reason_by_domain or (url, host) in seen:
            continue
        seen.add((url, host))
        result.append({"url": url, "domain": host, "reason": reason_by_domain[host]})
    return result


if __name__ == "__main__":
    sample_urls = [
        "https://evil-c2.example.net/beacon",
        "https://www.google.com/",
        "http://192.168.0.1/admin",
    ]
    sample_suspicious_domains = [
        {"domain": "evil-c2.example.net", "reason": "화이트리스트 미포함"},
        {"domain": "another-domain.example", "reason": "화이트리스트 미포함"},
    ]
    matches = find_hardcoded_urls_contacted(sample_urls, sample_suspicious_domains)
    print(f"코드에 하드코딩되어 있으면서 실제로 통신까지 확인된 주소: {len(matches)}건")
    for m in matches:
        print(" -", m)
