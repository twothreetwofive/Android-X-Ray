"""TLS ClientHello SNI 파싱 모듈. (C 담당, 5주차)

pcap 파일에서 TLS ClientHello의 SNI(Server Name Indication) 필드를 추출해서
network_report.schema.json의 tls_sni 필드 형식으로 반환한다.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone


def parse_sni(pcap_path: str) -> list[dict]:
    """pcap 파일에서 TLS ClientHello의 SNI를 추출한다.

    Returns:
        tls_sni 필드 형식의 리스트. 각 항목:
        {"sni": str, "timestamp": ISO8601 str, "dest_ip": str, "dest_port": int}
    """
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-Y", "tls.handshake.type==1",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "tls.handshake.extensions_server_name",
        "-E", "separator=|",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)

    entries: list[dict] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) != 4:
            continue
        epoch_str, dest_ip, dest_port, sni = parts
        if not sni:
            continue
        timestamp = datetime.fromtimestamp(float(epoch_str), tz=timezone.utc).isoformat()
        entries.append({
            "sni": sni,
            "timestamp": timestamp,
            "dest_ip": dest_ip,
            "dest_port": int(dest_port) if dest_port else None,
        })
    return entries


if __name__ == "__main__":
    results = parse_sni(r"C:\Users\mindy\Downloads\test.pcapng")  # 어제 저장한 파일 경로로 교체
    for r in results:
        print(r)
    print(f"\n총 {len(results)}개 SNI 추출됨")