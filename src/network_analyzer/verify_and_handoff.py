"""
verify_and_handoff.py
Android X-Ray - Role A

목적:
- capture.pcap이 실제로 파싱 가능한 상태인지 확인
- DNS / TLS 정보 존재 여부 사전 점검
- 전체 패킷 수 및 프로토콜 통계 확인
- B(dns_parser.py) / C(sni_parser.py)에게 인수인계용 리포트 생성
"""

import subprocess
import json
import sys
from pathlib import Path
from datetime import datetime


def _run_tshark(args: list[str]) -> str:
    result = subprocess.run(
        ["tshark"] + args,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"tshark 실행 실패:\n{result.stderr}"
        )

    return result.stdout


def verify_capture(pcap_path: str) -> dict:
    pcap = Path(pcap_path)

    if not pcap.exists():
        raise FileNotFoundError(f"pcap 파일이 없습니다: {pcap_path}")

    if pcap.stat().st_size == 0:
        raise ValueError("pcap 파일 크기가 0바이트입니다")

    # -------------------------------------------------------
    # 1. 전체 통계
    # -------------------------------------------------------
    capture_summary = _run_tshark([
        "-r", str(pcap),
        "-q",
        "-z", "io,stat,0"
    ])

    # -------------------------------------------------------
    # 2. 프로토콜 계층 통계
    # -------------------------------------------------------
    protocol_hierarchy = _run_tshark([
        "-r", str(pcap),
        "-q",
        "-z", "io,phs"
    ])

    # -------------------------------------------------------
    # 3. 전체 패킷 수
    # -------------------------------------------------------
    frame_numbers = _run_tshark([
        "-r", str(pcap),
        "-T", "fields",
        "-e", "frame.number"
    ])

    packet_count = len([
        x for x in frame_numbers.splitlines()
        if x.strip()
    ])

    # -------------------------------------------------------
    # 4. DNS
    # -------------------------------------------------------
    dns_raw = _run_tshark([
        "-r", str(pcap),
        "-Y", "dns.flags.response==0",
        "-T", "fields",
        "-e", "dns.qry.name"
    ])

    dns_queries = [
        d.strip()
        for d in dns_raw.splitlines()
        if d.strip()
    ]

    # -------------------------------------------------------
    # 5. TLS SNI
    # -------------------------------------------------------
    sni_raw = _run_tshark([
        "-r", str(pcap),
        "-Y", "tls.handshake.type==1",
        "-T", "fields",
        "-e", "tls.handshake.extensions_server_name"
    ])

    sni_list = [
        s.strip()
        for s in sni_raw.splitlines()
        if s.strip()
    ]

    # -------------------------------------------------------
    # 6. 리포트 생성
    # -------------------------------------------------------
    report = {
        "pcap_path": str(pcap.resolve()),
        "pcap_size_bytes": pcap.stat().st_size,
        "verified_at": datetime.now().isoformat(timespec="seconds"),

        "packet_count": packet_count,

        "dns_query_count": len(dns_queries),
        "dns_query_sample": dns_queries[:10],

        "tls_sni_count": len(sni_list),
        "tls_sni_sample": sni_list[:10],

        "capture_summary": capture_summary.strip(),
        "protocol_hierarchy": protocol_hierarchy.strip(),

        "notes": [],
    }

    # -------------------------------------------------------
    # 7. 분석 메모
    # -------------------------------------------------------
    if packet_count == 0:
        report["notes"].append(
            "[x] pcap에는 패킷이 없습니다. tcpdump 캡처 실패 가능성이 높습니다."
        )

    if packet_count > 0 and report["dns_query_count"] == 0:
        report["notes"].append(
            "[WARNING] DNS 쿼리가 없습니다. DoH/DoT 사용 또는 캡처 인터페이스 문제일 수 있습니다."
        )

    if packet_count > 0 and report["tls_sni_count"] == 0:
        report["notes"].append(
            "[WARNING] TLS ClientHello가 없습니다. TLS 재사용(Session Resume), ECH 또는 평문 통신 가능성을 확인하세요."
        )

    if (
        packet_count > 0
        and report["dns_query_count"] == 0
        and report["tls_sni_count"] == 0
    ):
        report["notes"].append(
            "[WARNING] 패킷은 존재하지만 DNS/TLS가 모두 없습니다. protocol_hierarchy를 확인하여 실제 프로토콜을 분석하세요."
        )

    return report


def write_handoff_md(
    report: dict,
    out_path: str = "./HANDOFF_to_B_C.md"
):
    lines = [
        "# 3일차 인수인계 - A -> B, C",
        "",

        f"- pcap 경로: `{report['pcap_path']}`",
        f"- 파일 크기: {report['pcap_size_bytes']:,} bytes",
        f"- 전체 패킷 수: {report['packet_count']:,}",
        f"- 검증 시각: {report['verified_at']}",

        "",

        "## DNS (for B)",
        f"- 감지된 쿼리 수: {report['dns_query_count']}",
        f"- 샘플: {report['dns_query_sample']}",

        "",

        "## TLS SNI (for C)",
        f"- 감지된 ClientHello 수: {report['tls_sni_count']}",
        f"- 샘플: {report['tls_sni_sample']}",

        "",

        "## Capture Summary",
        "```",
        report["capture_summary"],
        "```",

        "",

        "## Protocol Hierarchy",
        "```",
        report["protocol_hierarchy"],
        "```",
    ]

    if report["notes"]:
        lines.append("")
        lines.append("## 주의사항")

        for note in report["notes"]:
            lines.append(f"- {note}")

    Path(out_path).write_text(
        "\n".join(lines),
        encoding="utf-8"
    )

    print(f"인수인계 문서 작성 완료: {out_path}")


if __name__ == "__main__":
    pcap_arg = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "./output/capture.pcap"
    )

    rep = verify_capture(pcap_arg)

    print(json.dumps(
        rep,
        indent=2,
        ensure_ascii=False
    ))

    write_handoff_md(rep)