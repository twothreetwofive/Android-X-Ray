"""network_analyzer/pcap_fallback.py — tshark가 없는 PC용 scapy 기반 파서. (8주차)

왜 필요한가
-----------
dns_parser.py / sni_parser.py는 `tshark` 서브프로세스를 쓴다. 그런데 tshark는
Wireshark에 딸린 시스템 패키지라 설치에 관리자 권한이 필요하고, 팀원 PC마다
있고 없고가 갈린다(6주차부터 반복된 "환경 편차" 문제). 실제로 8주차 로컬 실행에서
캡처는 성공했는데 파싱 단계에서

    DNS/SNI 파싱 또는 조립 실패: [Errno 2] No such file or directory: 'tshark'

로 네트워크 모듈이 통째로 실패했다.

scapy는 이미 requirements.txt에 있고 pip로 설치되므로 관리자 권한이 필요 없다.
그래서 **tshark가 있으면 그대로 쓰고, 없으면 이 모듈로 넘어오게** 한다.
출력 형식(dict 키)은 tshark 경로와 완전히 동일하게 맞췄다.

정확도 차이
-----------
- DNS: 차이 없음. scapy가 DNSQR/DNSRR을 그대로 파싱한다.
- TLS SNI: scapy의 TLS 레이어는 선택 설치(`scapy[tls]`)라, 여기서는 의존하지 않고
  ClientHello 바이트를 직접 훑어 server_name 확장(type 0x0000)만 꺼낸다.
  TCP 세그먼트가 쪼개진 ClientHello는 놓칠 수 있다 — 그 경우 tshark 쪽이 더 정확하다.
"""

from __future__ import annotations

import shutil
from datetime import datetime, timezone


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat()


def parse_dns_scapy(pcap_path: str) -> list[dict]:
    """dns_parser.parse_dns()와 같은 형식으로 DNS 질의를 뽑는다."""
    from scapy.all import DNS, DNSQR, DNSRR, rdpcap  # 지연 import

    packets = rdpcap(pcap_path)

    resolved_by_id: dict[int, str] = {}
    pending: list[dict] = []

    for pkt in packets:
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]

        # 응답: A 레코드에서 첫 IP를 트랜잭션 ID에 저장
        if dns.qr == 1:
            if dns.ancount and dns.an is not None:
                for i in range(dns.ancount):
                    try:
                        rr = dns.an[i]
                    except (IndexError, TypeError):
                        break
                    if isinstance(rr, DNSRR) and rr.type == 1:  # A 레코드
                        resolved_by_id.setdefault(int(dns.id), _decode(rr.rdata))
                        break
            continue

        # 질의
        if not dns.qdcount or dns.qd is None:
            continue
        qd = dns.qd[0] if hasattr(dns.qd, "__getitem__") else dns.qd
        if not isinstance(qd, DNSQR):
            continue
        domain = _decode(qd.qname).rstrip(".")
        if not domain:
            continue

        pending.append({
            "domain": domain,
            "timestamp": _iso(pkt.time),
            "_dns_id": int(dns.id),
        })

    queries: list[dict] = []
    unresolved = 0
    for entry in pending:
        dns_id = entry.pop("_dns_id")
        resolved_ip = resolved_by_id.get(dns_id)
        if resolved_ip is None:
            unresolved += 1
        entry["resolved_ip"] = resolved_ip
        queries.append(entry)

    if unresolved:
        print(f"[경고] 응답 매칭 실패 쿼리 {unresolved}건 (타임아웃 또는 캡처 구간 밖 응답 가능성)")
    return queries


def parse_sni_scapy(pcap_path: str) -> list[dict]:
    """sni_parser.parse_sni()와 같은 형식으로 TLS ClientHello의 SNI를 뽑는다."""
    from scapy.all import IP, IPv6, TCP, rdpcap  # 지연 import

    packets = rdpcap(pcap_path)
    entries: list[dict] = []
    skipped_no_sni = 0

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
        payload = bytes(pkt[TCP].payload)
        if len(payload) < 6:
            continue
        # TLS record: content_type(0x16=handshake), version(2), length(2)
        # handshake: type(0x01=ClientHello)
        if payload[0] != 0x16 or payload[5] != 0x01:
            continue

        sni = _extract_sni(payload)
        if not sni:
            skipped_no_sni += 1
            continue

        if pkt.haslayer(IP):
            dest_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            dest_ip = pkt[IPv6].dst
        else:
            dest_ip = None

        entries.append({
            "sni": sni,
            "timestamp": _iso(pkt.time),
            "dest_ip": dest_ip,
            "dest_port": int(pkt[TCP].dport),
        })

    if skipped_no_sni:
        print(f"[경고] SNI 없는 ClientHello {skipped_no_sni}건 건너뜀 (ECH 또는 세션 재개 가능성)")
    return entries


def _decode(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _extract_sni(record: bytes) -> str | None:
    """TLS ClientHello 레코드 바이트에서 server_name 확장을 직접 파싱한다.

    구조를 순서대로 건너뛴다:
      레코드헤더(5) → 핸드셰이크헤더(4) → 버전(2) → 랜덤(32)
      → session_id(1+n) → cipher_suites(2+n) → compression(1+n)
      → extensions(2+n) 안에서 type==0x0000 찾기
    길이 필드를 신뢰하지 않고 매번 경계를 확인한다(잘린 패킷 방어).
    """
    try:
        i = 5 + 4 + 2 + 32                      # 레코드+핸드셰이크+버전+랜덤
        if i >= len(record):
            return None

        sid_len = record[i]; i += 1 + sid_len            # session_id
        if i + 2 > len(record):
            return None
        cs_len = int.from_bytes(record[i:i + 2], "big"); i += 2 + cs_len   # cipher suites
        if i >= len(record):
            return None
        comp_len = record[i]; i += 1 + comp_len          # compression methods
        if i + 2 > len(record):
            return None

        ext_total = int.from_bytes(record[i:i + 2], "big"); i += 2
        end = min(i + ext_total, len(record))

        while i + 4 <= end:
            ext_type = int.from_bytes(record[i:i + 2], "big")
            ext_len = int.from_bytes(record[i + 2:i + 4], "big")
            i += 4
            if ext_type == 0x0000:               # server_name
                # server_name_list(2) + type(1) + length(2) + host
                if i + 5 > len(record):
                    return None
                host_len = int.from_bytes(record[i + 3:i + 5], "big")
                host = record[i + 5:i + 5 + host_len]
                return host.decode("utf-8", errors="replace") or None
            i += ext_len
    except (IndexError, ValueError):
        return None
    return None
