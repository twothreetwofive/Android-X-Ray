"""network_analyzer/schema.py
네트워크 분석 모듈 출력 타입 정의. (D 작성, 5주차 과제)

이 파일이 팀 공유 계약이다 — 아래 필드명/타입을 임의로 바꾸면 다른 모듈이 깨진다.
필드를 바꿔야 하면 schemas/network_report.schema.json부터 고치고 팀 전체에 공유한 뒤
이 파일에 반영한다.
"""

from typing import List, Optional, TypedDict


class CaptureMeta(TypedDict):
    package_name: str
    capture_started_at: str  # ISO 8601
    capture_duration_sec: int  # 동적 분석(Frida) 실행 구간과 동기화된 캡처 시간
    pcap_file: Optional[str]


class DnsQuery(TypedDict):
    domain: str
    timestamp: str
    resolved_ip: Optional[str]


class TlsSni(TypedDict):
    sni: str
    timestamp: str
    dest_ip: Optional[str]
    dest_port: Optional[int]


class SuspiciousDomain(TypedDict):
    domain: str
    reason: str  # 예: "화이트리스트 미포함", "하드코딩된 형태"


class SuspiciousIP(TypedDict):
    ip: str
    reason: str


class Suspicious(TypedDict):
    domains: List[SuspiciousDomain]
    ips: List[SuspiciousIP]


class NetworkAnalysisResult(TypedDict):
    meta: CaptureMeta
    dns_queries: List[DnsQuery]
    tls_sni: List[TlsSni]
    suspicious: Suspicious
