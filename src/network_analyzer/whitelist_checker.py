"""network_analyzer/whitelist_checker.py (D 작성, 5주차 1~2일차)

화이트리스트 도메인 목록과 판별 로직.
B(dns_parser.py)/C(sni_parser.py)가 만드는 도메인 목록을 이 화이트리스트와
대조해서 suspicious.domains를 채우는 데 쓴다.

IP 기반 판별(suspicious.ips, 하드코딩된 IP 패턴)은 4일차 범위라 아직 없음.
"""

from typing import List

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
    """화이트리스트에 없는 도메인만 골라 suspicious.domains 형식으로 반환."""
    seen = set()
    result: List[SuspiciousDomain] = []
    for domain in domains:
        normalized = domain.lower().rstrip(".")
        if normalized in seen or is_whitelisted(normalized):
            continue
        seen.add(normalized)
        result.append({"domain": normalized, "reason": "화이트리스트 미포함"})
    return result
