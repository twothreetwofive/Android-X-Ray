"""analyze_static()의 결과 조립 테스트. (B, 6주차)

어댑터 테스트(test_static_adapter.py)는 전부 fixture dict 기반이라, analyze_static()이
정말로 그 모양의 dict를 만들어 내는지는 검증하지 못한다. 실제로 6주차 Day 1에
intent_filters가 파싱 단계에서 버려지고 있던 걸 뒤늦게 발견한 적이 있어서, 원천에서
필드가 빠지는 경우를 여기서 잡는다.

이 환경에는 jadx/apktool이 없어 extract_apk()가 디컴파일 단계에서 실패한다. 그래서
하위 단계 6개를 전부 monkeypatch해서 analyze_static()의 "조립" 부분만 떼어내 검증한다.
"""

from pathlib import Path

import pytest

from static_analyzer import analyzer

_STAGES = {
    "parse_manifest": {"permissions": ["android.permission.CAMERA"]},
    "analyze_cert": {"is_self_signed": True},
    "scan_code": {"obfuscation_detected": False},
    "extract_strings": {"urls": []},
    "detect_sdks": ["Firebase"],
}

_EXTRACTED = {
    "meta": {"apk_name": "sample.apk", "package_name": "com.test.app"},
    "apk_path": Path("sample.apk"),
}


@pytest.fixture
def stub_stages(monkeypatch):
    """extract_apk와 하위 분석 5개를 고정값으로 대체한다.

    risk_scorer는 대체하지 않는다 — analyzer가 어떤 함수를 부르는지, 그 반환값을
    어떻게 나눠 담는지가 이 테스트의 검증 대상이기 때문이다.
    """
    monkeypatch.setattr(analyzer, "extract_apk", lambda *a, **kw: _EXTRACTED)
    for name, value in _STAGES.items():
        monkeypatch.setattr(analyzer, name, lambda *a, _v=value, **kw: _v)


def test_risk_score와_risk_breakdown이_함께_채워진다(stub_stages):
    result = analyzer.analyze_static("sample.apk")

    assert isinstance(result["risk_score"], float)
    assert set(result["risk_breakdown"]) == {"total", "raw", "breakdown"}
    assert not result["errors"]


def test_risk_score는_risk_breakdown_total과_항상_같은_값이다(stub_stages):
    """두 값이 어긋나면 리포트에 서로 다른 점수가 두 개 실린다."""
    result = analyzer.analyze_static("sample.apk")

    assert result["risk_score"] == result["risk_breakdown"]["total"]


def test_breakdown_weight_합이_raw와_일치한다(stub_stages):
    result = analyzer.analyze_static("sample.apk")
    breakdown = result["risk_breakdown"]["breakdown"]

    assert sum(item["weight"] for item in breakdown) == result["risk_breakdown"]["raw"]


def test_CAMERA가_점수에_실제로_반영된다(stub_stages):
    """D가 PERMISSION_WEIGHTS를 5개 -> 20개로 확장하기 전엔 CAMERA가 0점이었다.

    표만 늘리고 calculate_risk()가 dangerous_permissions(8점 이상)만 합산하면
    weight 7인 CAMERA는 여전히 점수에 안 잡힌다 — 그 회귀를 여기서 막는다.
    """
    result = analyzer.analyze_static("sample.apk")
    factors = [item["factor"] for item in result["risk_breakdown"]["breakdown"]]

    assert "android.permission.CAMERA" in factors
    assert result["risk_score"] > 0


def test_위험도_계산이_실패하면_둘_다_None이고_errors에_남는다(monkeypatch, stub_stages):
    """점수만 None이고 근거는 남거나 그 반대면 리포트가 앞뒤가 안 맞는다."""
    def boom(*args, **kwargs):
        raise RuntimeError("계산 실패")

    monkeypatch.setattr(analyzer, "calculate_risk_with_breakdown", boom)
    result = analyzer.analyze_static("sample.apk")

    assert result["risk_score"] is None
    assert result["risk_breakdown"] is None
    assert any("위험도 계산 실패" in e for e in result["errors"])


def test_하위_단계가_실패해도_나머지_필드는_채워진다(monkeypatch, stub_stages):
    """analyze_static()의 부분 실패 정책(예외 대신 errors 누적)이 유지되는지 확인."""
    def boom(*args, **kwargs):
        raise RuntimeError("jadx 없음")

    monkeypatch.setattr(analyzer, "scan_code", boom)
    result = analyzer.analyze_static("sample.apk")

    assert result["code_analysis"] is None
    assert result["manifest"] is not None
    assert result["risk_breakdown"] is not None  # code_data=None이어도 계산은 계속됨
    assert any("코드 스캔 실패" in e for e in result["errors"])


def test_어댑터가_기대하는_필드가_전부_존재한다(stub_stages):
    """to_static_report()가 읽는 키가 원천에서 빠지면 여기서 먼저 잡힌다."""
    result = analyzer.analyze_static("sample.apk")

    expected = {
        "meta", "manifest", "certificate", "code_analysis", "strings",
        "third_party_sdks", "risk_score", "risk_breakdown", "errors",
    }
    assert expected == set(result)


def test_meta에_analyzed_at이_채워진다(stub_stages):
    """extract_apk의 meta에는 없고 analyzer가 덧붙이는 값이라 빠지기 쉽다."""
    result = analyzer.analyze_static("sample.apk")

    assert result["meta"]["analyzed_at"]
    assert result["meta"]["apk_name"] == "sample.apk"
