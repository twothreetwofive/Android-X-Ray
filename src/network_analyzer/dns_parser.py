"""DNS 쿼리 파싱 모듈. (B 담당, 5주차)

pcap 파일에서 DNS 쿼리를 추출해서 network_report.schema.json의
dns_queries 필드 형식으로 반환한다.

C의 sni_parser.py와 동일하게 tshark subprocess를 사용한다 (scapy로 DNSQR
레이어 구조를 먼저 학습했지만, 팀 파이프라인 전체가 이미 tshark 기반이라
sni_parser.py/verify_and_handoff.py와 일관성을 맞춤).
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone


def parse_dns(pcap_path: str) -> list[dict]:
    """pcap 파일에서 DNS 쿼리/응답을 추출해 dns_queries 형식으로 반환한다.

    질의(query)와 응답(response)은 서로 다른 패킷이라, dns.id(트랜잭션 ID)로
    질의-응답을 짝지어 resolved_ip를 채운다. 매칭되는 응답이 없으면(타임아웃,
    캡처 구간 밖에서 응답이 온 경우 등) resolved_ip는 None으로 남는다.

    Returns:
        dns_queries 필드 형식의 리스트. 각 항목:
        {"domain": str, "timestamp": ISO8601 str, "resolved_ip": str | None}
    """
    cmd = [
        "tshark",
        "-r", pcap_path,
        # udp.port==53로 제한 - "dns" 필터만 쓰면 로컬 기기 탐색(mDNS, udp/5353)까지
        # 같이 잡혀서 TLD 없는 랜덤 호스트명이 suspicious.domains에 노이즈로 섞임
        "-Y", "dns && udp.port==53",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "dns.flags.response",
        "-e", "dns.id",
        "-e", "dns.qry.name",
        "-e", "dns.a",
        "-E", "separator=|",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    resolved_by_id: dict[str, str] = {}
    pending: list[dict] = []

    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) != 5:
            continue
        epoch_str, is_response, dns_id_raw, qry_name_raw, answers_raw = parts

        # dns.id 하나로 질의/응답을 매칭하므로, 값이 없으면 매칭 불가능해 건너뜀
        if not dns_id_raw:
            continue
        dns_id = dns_id_raw.split(",")[0]

        # tshark 버전/옵션에 따라 dns.flags.response가 "1"/"0" 또는 "True"/"False"로
        # 나올 수 있어 둘 다 방어적으로 처리한다.
        if is_response.strip().lower() in ("1", "true"):
            # 다중 A 레코드 응답이면 tshark가 콤마로 이어붙여서 반환한다
            # (예: "1.2.3.4,5.6.7.8"). 대표값으로 첫 번째 IP만 사용한다.
            if answers_raw:
                resolved_by_id[dns_id] = answers_raw.split(",")[0]
            continue

        # 질의: 응답이 먼저 처리됐을 수도, 나중에 나올 수도 있으니 일단 보류하고
        # 전체 라인을 다 읽은 뒤 마지막에 resolved_by_id와 매칭한다.
        if not qry_name_raw:
            continue

        timestamp = datetime.fromtimestamp(
            float(epoch_str.split(",")[0]), tz=timezone.utc
        ).isoformat()

        pending.append({
            "domain": qry_name_raw.split(",")[0],
            "timestamp": timestamp,
            "_dns_id": dns_id,
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

    if unresolved > 0:
        print(f"[경고] 응답 매칭 실패 쿼리 {unresolved}건 (타임아웃 또는 캡처 구간 밖 응답 가능성)")

    return queries


if __name__ == "__main__":
    import json
    import sys

    pcap_arg = sys.argv[1] if len(sys.argv) > 1 else "./output/capture.pcap"
    results = parse_dns(pcap_arg)
    with open("sample_dns_queries_output.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"총 {len(results)}개 DNS 쿼리 추출됨 -> sample_dns_queries_output.json 저장 완료")
