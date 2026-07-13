"""서명 인증서 검증/추출.

apk_extractor가 넘겨준 apk_path에서 androguard로 서명 인증서를 직접 읽는다.
manifest_parser와 마찬가지로 디컴파일 결과물은 필요 없다.
"""

from __future__ import annotations

from androguard.core.apk import APK

_EMPTY_CERT = {
    "issuer": "",
    "subject": "",
    "valid_from": "",
    "valid_to": "",
    "is_self_signed": False,
}


def analyze_cert(extracted: dict) -> dict:
    apk = APK(str(extracted["apk_path"]))
    certs = apk.get_certificates()

    if not certs:
        return dict(_EMPTY_CERT)

    # v1/v2/v3 서명에 인증서가 여러 개 섞여 나올 수 있는데, 대표로 첫 번째만 씀.
    cert = certs[0]
    return {
        "issuer": cert.issuer.human_friendly,
        "subject": cert.subject.human_friendly,
        "valid_from": cert.not_valid_before.isoformat(),
        "valid_to": cert.not_valid_after.isoformat(),
        # asn1crypto의 self_signed는 "no"/"maybe" 문자열이라 bool로 변환.
        # "maybe"도 자가서명으로 취급 — 안드로이드 앱은 대부분 자가서명이라 흔한 케이스임.
        "is_self_signed": cert.self_signed != "no",
    }
