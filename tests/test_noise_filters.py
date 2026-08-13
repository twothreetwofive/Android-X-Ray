"""8주차 실샘플 실행에서 드러난 오탐 3종에 대한 회귀 테스트.

전부 "정상 앱이 위험하게 보이던" 문제다. 실측 근거는 각 테스트 주석에 있다.
에뮬레이터 없이 도는 순수 로직 테스트라 어느 PC에서나 실행된다.
"""

import pytest

from dynamic_analyzer.message_parser import (
    extract_plaintext_candidates,
    is_framework_caller,
)
from network_analyzer.pcap_fallback import _extract_sni
from static_analyzer.risk_scorer import calculate_risk_with_breakdown
from static_analyzer.string_extractor import IP_RE


# ────────────────────────────────────────────────────────────
# 1. 동적: 프레임워크 내부 호출을 평문 후보로 세지 않는다
# ────────────────────────────────────────────────────────────
#
# 실측: 에뮬레이터 내장 시계 앱에서 평문 후보 124건이 나왔는데 호출자가 전부
# java.util.Formatter(120) / android.graphics.Typeface(4)였다. 즉 String.format()과
# 폰트 로딩이고 앱 코드는 0건. 이 때문에 동적 위험도가 0.49까지 올라갔다.

def _ev(value: str, caller: str | None):
    extra = {"caller_class": caller} if caller is not None else {}
    return {"raw_value": value, "extra": extra}


@pytest.mark.parametrize("caller", [
    "java.util.Formatter$FormatSpecifier",
    "android.graphics.Typeface",
    "androidx.core.app.NotificationCompat",
    "kotlin.text.StringsKt",
    "com.google.android.gms.common.api.Api",
])
def test_프레임워크_호출은_평문_후보에서_제외(caller):
    assert is_framework_caller(_ev("some plaintext value", caller))
    assert extract_plaintext_candidates([_ev("some plaintext value", caller)]) == []


@pytest.mark.parametrize("caller", [
    "com.ctf.app.LoginActivity",
    "video.lotus19.ridenovel31.Main",
    "org.example.Payload",
])
def test_앱_자체_코드_호출은_남는다(caller):
    assert not is_framework_caller(_ev("stolen token abc", caller))
    assert extract_plaintext_candidates([_ev("stolen token abc", caller)]) == ["stolen token abc"]


def test_호출자_정보가_없으면_거르지_않는다():
    """정보가 없다는 이유로 실제 신호를 버리면 안 된다 (구버전 hooks.js 대비)."""
    assert not is_framework_caller(_ev("value", None))
    assert extract_plaintext_candidates([_ev("value here", None)]) == ["value here"]


# ────────────────────────────────────────────────────────────
# 2. 정적: 잘못된 IP 문자열을 하드코딩 IP로 잡지 않는다
# ────────────────────────────────────────────────────────────
#
# 실측: 시계 앱에서 "8.4.91.697"이 하드코딩 IP로 잡혔다(697은 옥텟 범위 초과).

@pytest.mark.parametrize("text", ["8.4.91.697", "1.2.3.999", "300.1.1.1", "1.2.3", "1.2.3.4.5"])
def test_잘못된_IP는_매칭되지_않는다(text):
    assert IP_RE.findall(text) == []


@pytest.mark.parametrize("text", ["192.168.0.1", "8.8.8.8", "203.0.113.255", "10.0.0.1"])
def test_정상_IP는_매칭된다(text):
    assert IP_RE.findall(text) == [text]


# ────────────────────────────────────────────────────────────
# 3. 정적: 의심 API를 건수가 아니라 위험도 종류로 센다
# ────────────────────────────────────────────────────────────
#
# 실측: 시계 앱의 의심 API 14건이 42점(건수×3)이었다. 그 안에는 Gson 매퍼의
# Base64.decode(low)와 지원 라이브러리의 AccessibilityService(high)가 섞여 있었다.

def test_같은_API가_여러_파일에_있어도_한_종류로_센다():
    many = {"suspicious_api_calls": [
        {"api": "Base64.decode", "location": f"f{i}.java", "risk": "low"} for i in range(20)
    ]}
    one = {"suspicious_api_calls": [
        {"api": "Base64.decode", "location": "f0.java", "risk": "low"}
    ]}
    assert (calculate_risk_with_breakdown(None, many, None, None)["raw"]
            == calculate_risk_with_breakdown(None, one, None, None)["raw"])


def test_고위험_API가_저위험_API보다_점수가_높다():
    high = {"suspicious_api_calls": [{"api": "AccessibilityService", "location": "a", "risk": "high"}]}
    low = {"suspicious_api_calls": [{"api": "Base64.decode", "location": "a", "risk": "low"}]}
    assert (calculate_risk_with_breakdown(None, high, None, None)["raw"]
            > calculate_risk_with_breakdown(None, low, None, None)["raw"])


def test_자체_서명만으로는_점수가_거의_오르지_않는다():
    """안드로이드 앱은 거의 전부 자체 서명이라 변별력이 없다 (구글 정품 앱도 해당)."""
    result = calculate_risk_with_breakdown(None, None, None, {"is_self_signed": True})
    assert result["raw"] <= 2


# ────────────────────────────────────────────────────────────
# 4. 네트워크: tshark 없이도 SNI를 뽑는다
# ────────────────────────────────────────────────────────────

def _client_hello(host: bytes) -> bytes:
    ext_host = (b"\x00\x00" + (len(host) + 5).to_bytes(2, "big")
                + (len(host) + 3).to_bytes(2, "big") + b"\x00"
                + len(host).to_bytes(2, "big") + host)
    ext_other = b"\x00\x0b\x00\x02\x01\x00"          # ec_point_formats (순회 확인용)
    exts = ext_other + ext_host
    body = (b"\x03\x03" + b"\xAA" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
            + len(exts).to_bytes(2, "big") + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


@pytest.mark.parametrize("host", [b"api.example.com", b"c2.malicious-domain.top", b"a.co"])
def test_scapy_fallback이_SNI를_뽑는다(host):
    assert _extract_sni(_client_hello(host)) == host.decode()


def test_잘린_패킷에도_죽지_않는다():
    assert _extract_sni(_client_hello(b"api.example.com")[:40]) is None
    assert _extract_sni(b"") is None
    assert _extract_sni(b"\x16\x03\x01\x00\x05\x01") is None
