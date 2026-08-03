"""network_analyzer/whitelist_checker.py (D 작성, 5주차 1~2일차)

화이트리스트 도메인 목록과 판별 로직.
B(dns_parser.py)/C(sni_parser.py)가 만드는 도메인 목록을 이 화이트리스트와
대조해서 suspicious.domains를 채우는 데 쓴다.

IP 기반 판별(suspicious.ips)은 ip_checker.py 참고(3~4일차에 완성).
"""

from typing import List

from .ip_checker import is_ip_literal
from .schema import SuspiciousDomain

# 카테고리별 정리. 전체를 다 덮을 순 없어서, 실제 캡처에서 자주 보이는데
# 놓친 도메인이 나오면 팀 공유 후 추가한다.
WHITELIST_DOMAINS: frozenset = frozenset(
    {
        # Google / Play services / Firebase
        "googleapis.com",
        "gstatic.com",
        "google.com",
        "googleusercontent.com",
        "app-measurement.com",
        "firebaseinstallations.googleapis.com",
        "firebaseio.com",
        "crashlytics.com",
        "googlesyndication.com",
        "doubleclick.net",
        "googleadservices.com",
        "clients3.google.com",
        "connectivitycheck.gstatic.com",
        "android.googleapis.com",
        "play.googleapis.com",
        "youtube.com",
        "ytimg.com",
        # 광고 SDK
        "unity3d.com",
        "unityads.unity3d.com",
        "applovin.com",
        "adcolony.com",
        "vungle.com",
        "ironsource.mobi",
        "chartboost.com",
        "mopub.com",
        "facebook.com",
        "graph.facebook.com",
        "connect.facebook.net",
        "fbcdn.net",
        # 분석 / 크래시 리포팅
        "amplitude.com",
        "mixpanel.com",
        "sentry.io",
        "flurry.com",
        "onesignal.com",
        # 시간 동기화 / OS 시스템 체크
        "pool.ntp.org",
        "ntp.org",
        # CDN
        "cloudflare.com",
        "cloudfront.net",
        "akamaiedge.net",
        "akamaitechnologies.com",
        "fastly.net",
    }
)


def is_whitelisted(domain: str) -> bool:
    """domain이 화이트리스트에 등록된 도메인이거나 그 서브도메인이면 True."""
    normalized = domain.lower().rstrip(".")
    return any(
        normalized == entry or normalized.endswith("." + entry)
        for entry in WHITELIST_DOMAINS
    )


def find_suspicious_domains(domains: List[str]) -> List[SuspiciousDomain]:
    """화이트리스트에 없는 도메인만 골라 suspicious.domains 형식으로 반환.

    domain/sni 필드에 호스트명 대신 IP가 그대로 들어있는 경우(예: DNS 조회 없이
    하드코딩된 IP로 접속)는 화이트리스트 미포함과 구분해서 "하드코딩된 형태"로 표시한다.
    """
    seen = set()
    result: List[SuspiciousDomain] = []
    for domain in domains:
        normalized = domain.lower().rstrip(".")
        if normalized in seen:
            continue
        if is_ip_literal(normalized):
            seen.add(normalized)
            result.append({"domain": normalized, "reason": "하드코딩된 형태"})
            continue
        # 점이 없는 단일 라벨 호스트명(TLD 없음)은 실캡처 검증 중 실제로 관찰됨 -
        # Android NetworkMonitor가 캡티브 포털/DNS 하이재킹 탐지용으로 날리는
        # 랜덤 문자열 프로브(예: "dgbszpfhdgn")라 항상 미응답이고 앱 통신도 아님.
        # 등록 가능한 도메인이 아니라서(진짜 C2든 화이트리스트 도메인이든 TLD가 있음)
        # 걸러내지 않으면 정상 기기에서도 매번 의심 도메인으로 오탐된다.
        if "." not in normalized:
            seen.add(normalized)
            continue
        if is_whitelisted(normalized):
            continue
        seen.add(normalized)
        result.append({"domain": normalized, "reason": "화이트리스트 미포함"})
    return result
