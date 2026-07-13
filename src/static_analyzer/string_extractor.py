"""strings 추출 + URL/IP 정규식 매칭.

jadx 소스 트리를 텍스트로 훑어서 문자열 리터럴 중 URL/IP/의심 키워드를 뽑는다.
난독화된 샘플은 문자열 자체가 암호화돼있어서 여기서 안 잡힐 수 있음 —
그런 경우는 동적 분석(Frida) 단계에서 런타임 복호화된 값을 잡아야 함.
"""

from __future__ import annotations

import re
from pathlib import Path

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

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
