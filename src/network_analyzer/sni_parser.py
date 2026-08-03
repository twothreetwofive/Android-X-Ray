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
    skipped_no_sni = 0
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) != 4:
            continue
        epoch_str, dest_ip, dest_port_raw, sni = parts

        if not sni:
            skipped_no_sni += 1
            continue  # ECH 사용 또는 세션 재개(resumption) 가능성

        # tshark가 필드값을 콤마로 여러 개 반환하는 경우 방어 (예: "443,443")
        dest_port = None
        if dest_port_raw:
            try:
                dest_port = int(dest_port_raw.split(",")[0])
            except ValueError:
                dest_port = None

        timestamp = datetime.fromtimestamp(
            float(epoch_str.split(",")[0]), tz=timezone.utc
        ).isoformat()

        entries.append({
            "sni": sni.split(",")[0],
            "timestamp": timestamp,
            "dest_ip": dest_ip.split(",")[0] if dest_ip else None,
            "dest_port": dest_port,
        })

    if skipped_no_sni > 0:
        print(f"[경고] SNI 없는 ClientHello {skipped_no_sni}건 건너뜀 (ECH 또는 세션 재개 가능성)")

    return entries

import json

if __name__ == "__main__":
    results = parse_sni(r"C:\workspace\23.25\Android-X-Ray\test.pcapng")
    with open("sample_tls_sni_output.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"총 {len(results)}개 SNI 추출됨 -> sample_tls_sni_output.json 저장 완료")