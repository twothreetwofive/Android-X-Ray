"""strings 추출 + URL/IP 정규식 매칭.

jadx 소스 트리를 텍스트로 훑어서 문자열 리터럴 중 URL/IP/의심 키워드를 뽑는다.
난독화된 샘플은 문자열 자체가 암호화돼있어서 여기서 안 잡힐 수 있음 —
그런 경우는 동적 분석(Frida) 단계에서 런타임 복호화된 값을 잡아야 함.
"""

from __future__ import annotations

import re
from pathlib import Path

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
# 각 옥텟을 0~255로 제한한다. 이전 정규식(\d{1,3})은 "8.4.91.697"이나 버전 문자열
# 같은 것도 IP로 잡아서, 정상 앱에서 "하드코딩 IP 발견"이라는 오탐이 났다
# (8주차 실측: 시계 앱에서 8.4.91.697이 IP로 잡힘).
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IP_RE = re.compile(rf"(?<![\d.]){_OCTET}(?:\.{_OCTET}){{3}}(?![\d.])")

SUSPICIOUS_KEYWORDS = ["cmd.exe", "chmod 777", "/system/bin/su", ".onion", "su -c"]


def extract_strings(extracted: dict) -> dict:
    jadx_dir = Path(extracted["jadx_dir"])

    urls: set[str] = set()
    ip_addresses: set[str] = set()
    suspicious_strings: set[str] = set()

    for java_file in jadx_dir.rglob("*.java"):
        text = java_file.read_text(encoding="utf-8", errors="ignore")
        urls.update(URL_RE.findall(text))
        ip_addresses.update(IP_RE.findall(text))
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in text:
                suspicious_strings.add(keyword)

    return {
        "urls": sorted(urls),
        "ip_addresses": sorted(ip_addresses),
        "suspicious_strings": sorted(suspicious_strings),
    }
