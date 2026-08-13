"""risk_aggregator의 보안 판정(Verdict) 로직 테스트. (8주차)

이 파일이 잠그는 것은 8주차 계획수정 PDF의 핵심 요구다:

    "취약하지만 반드시 악성인 것은 아닌 APK"를 악성으로 표시하지 않는다.

PDF 2항이 든 실제 사례(평문 후보 35건, 의심 도메인 1건 + 의심 IP 3건)를 그대로
케이스로 만들어 뒀다. 8주차 이전 상수(평문 8점/건, CAP 50, 의심 IP 15점/건)로는
이 입력이 92점 "악성"으로 나왔다 — 취약 실습 앱과 뱅킹 트로이목마가 점수에서
구분되지 않았다는 뜻이다.

streamlit이 필요 없는 순수 계산 로직이라 어느 PC에서나 돌아간다.
"""

import pytest

from risk_aggregator import (
    MALICIOUS_MIN_SCORE100,
    MALICIOUS_MIN_STRONG_INDICATORS,
    aggregate_risk,
)


def _module(status="ok", **data):
    return {"status": status, "data": data or None}


def _static(risk_score=0.5, permissions=(), dangerous=(), **code):
    return _module(
        risk_score=risk_score,
        manifest={"permissions": list(permissions), "dangerous_permissions": list(dangerous)},
        code_analysis=code,
        strings={},
        certificate={},
    )


def _dynamic(plaintext=0, cipher=0):
    return _module(
        plaintext_candidates=["p"] * plaintext,
        events=[{"hook_type": "cipher"}] * cipher,
    )


def _network(domains=0, ips=0, dns=0, sni=0):
    return _module(
        suspicious={
            "domains": [{"domain": f"d{i}"} for i in range(domains)],
            "ips": [{"ip": f"10.0.0.{i}"} for i in range(ips)],
        },
        dns_queries=[{}] * dns,
        tls_sni=[{}] * sni,
    )


# ── PDF 2항의 실제 사례 ──
VULNERABLE_APP = {
    "static": _static(
        risk_score=0.79,
        permissions=["android.permission.INTERNET"],
        suspicious_api_calls=[1] * 7,
        obfuscation_detected=True,
        reflection_usage=True,
        dynamic_code_loading=True,
    ),
    "dynamic": _dynamic(plaintext=35, cipher=10),
    "network": _network(domains=1, ips=3, dns=12, sni=4),
}

NORMAL_APP = {
    "static": _static(risk_score=0.10, permissions=["android.permission.INTERNET"]),
    "dynamic": _dynamic(plaintext=0, cipher=0),
    "network": _network(domains=0, ips=0, dns=5, sni=3),
}

BANKING_TROJAN = {
    "static": _static(
        risk_score=0.95,
        permissions=[
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ],
        dangerous=["android.permission.READ_SMS"] * 8,
        suspicious_api_calls=[1] * 20,
        obfuscation_detected=True,
        dynamic_code_loading=True,
        reflection_usage=True,
    ),
    "dynamic": _dynamic(plaintext=20, cipher=30),
    "network": _network(domains=4, ips=4, dns=20, sni=6),
}


# ────────────────────────────────────────────
# 판정 구간
# ────────────────────────────────────────────

def test_정상_앱은_정상_판정():
    r = aggregate_risk(NORMAL_APP)
    assert r["verdict"]["code"] == "normal"
    assert r["score100"] < 30


def test_취약_앱은_의심이지_악성이_아니다():
    """이 파일의 핵심. PDF가 명시적으로 요구한 동작이다."""
    r = aggregate_risk(VULNERABLE_APP)

    assert r["verdict"]["code"] == "suspicious", (
        f"취약 APK가 {r['verdict']['code']}로 판정됐습니다 (점수 {r['score100']})"
    )
    assert r["verdict"]["code"] != "malicious"
    assert 60 <= r["score100"] < 80


def test_뱅킹_트로이목마형은_악성으로_승격된다():
    """반대 방향 잠금 — 규칙이 지나치게 보수적이어서 진짜 악성을 놓치면 안 된다."""
    r = aggregate_risk(BANKING_TROJAN)

    assert r["verdict"]["code"] == "malicious"
    assert r["verdict"]["malicious_rule"]["met"] is True
    assert r["score100"] >= MALICIOUS_MIN_SCORE100


@pytest.mark.parametrize("sub_score,expected", [
    (0.00, "normal"),
    (0.29, "normal"),
    (0.30, "caution"),
    (0.59, "caution"),
    (0.60, "suspicious"),
    (0.79, "suspicious"),
    (0.80, "high_risk"),
    (1.00, "high_risk"),
])
def test_점수_구간_경계(sub_score, expected):
    """0–29 정상 / 30–59 주의 / 60–79 의심 / 80–100 고위험 (PDF 4항)."""
    modules = {
        "static": _static(risk_score=sub_score),
        "dynamic": {"status": "failed", "data": None},
        "network": {"status": "failed", "data": None},
    }
    r = aggregate_risk(modules)
    assert r["verdict"]["band_code"] == expected


# ────────────────────────────────────────────
# 악성 승격 규칙
# ────────────────────────────────────────────

def test_점수만_높으면_악성이_아니다():
    """강한 지표 없이 점수만 높은 경우 — 승격되면 안 된다."""
    modules = {
        "static": _static(risk_score=1.0),
        "dynamic": {"status": "failed", "data": None},
        "network": {"status": "failed", "data": None},
    }
    r = aggregate_risk(modules)

    assert r["score100"] >= MALICIOUS_MIN_SCORE100
    assert r["verdict"]["code"] == "high_risk"
    assert r["verdict"]["malicious_rule"]["met"] is False


def test_강한_지표만_많고_점수가_낮으면_악성이_아니다():
    """반대 조건. 두 조건을 AND로 요구하는지 확인한다."""
    r = aggregate_risk(BANKING_TROJAN)
    assert len(r["verdict"]["strong_indicators"]) >= MALICIOUS_MIN_STRONG_INDICATORS

    # 같은 지표 구성에서 점수만 낮추면 승격이 풀려야 한다.
    lowered = dict(BANKING_TROJAN)
    lowered["static"] = _static(
        risk_score=0.0,
        permissions=[
            "android.permission.READ_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        obfuscation_detected=True,
        dynamic_code_loading=True,
    )
    lowered["dynamic"] = _dynamic(plaintext=0, cipher=0)
    lowered["network"] = _network(domains=3, ips=3)

    r2 = aggregate_risk(lowered)
    assert r2["score100"] < MALICIOUS_MIN_SCORE100
    assert r2["verdict"]["code"] != "malicious"


def test_평문_후보는_강한_지표가_아니다():
    """취약 실습 앱의 대표 특징이라 악성 판별력이 낮다 — 표시는 하되 승격 근거로는 안 쓴다."""
    r = aggregate_risk(VULNERABLE_APP)

    labels = [i["label"] for i in r["indicators"]["dynamic"]]
    assert "평문 후보" in labels                      # 화면에는 나온다
    strong = [i["label"] for i in r["verdict"]["strong_indicators"]]
    assert "평문 후보" not in strong                  # 승격 근거로는 안 쓴다


def test_의심_도메인_1건은_강한_지표가_아니다():
    """화이트리스트가 불완전하다고 스스로 밝히고 있어, 1~2건은 누락일 수 있다."""
    r = aggregate_risk({
        "static": _static(risk_score=0.5),
        "dynamic": {"status": "failed", "data": None},
        "network": _network(domains=1),
    })
    strong = [i["code"] for i in r["verdict"]["strong_indicators"]]
    assert "suspicious_domain" not in strong


def test_동적코드로딩은_난독화와_겹칠_때만_강한_지표():
    """정상 앱(플러그인·핫픽스 SDK)도 동적 로딩을 쓴다."""
    alone = aggregate_risk({
        "static": _static(risk_score=0.5, dynamic_code_loading=True),
        "dynamic": {"status": "failed", "data": None},
        "network": {"status": "failed", "data": None},
    })
    assert not alone["verdict"]["strong_indicators"]

    combined = aggregate_risk({
        "static": _static(risk_score=0.5, dynamic_code_loading=True, obfuscation_detected=True),
        "dynamic": {"status": "failed", "data": None},
        "network": {"status": "failed", "data": None},
    })
    assert [i["code"] for i in combined["verdict"]["strong_indicators"]] == ["dropper_pattern"]


# ────────────────────────────────────────────
# 지표 추출 / 부분 리포트
# ────────────────────────────────────────────

def test_전부_실패하면_판정_불가():
    r = aggregate_risk({
        "static": {"status": "failed", "data": None},
        "dynamic": {"status": "failed", "data": None},
        "network": {"status": "timeout", "data": None},
    })
    assert r["total"] is None
    assert r["score100"] is None
    assert r["verdict"]["code"] == "unknown"
    # 0점으로 떨어뜨리면 "안전"으로 읽힌다.
    assert r["level"] != "normal"


def test_점수를_못_내는_모듈도_지표는_뽑는다():
    """정적 risk_score가 None이어도 관찰된 사실은 남아야 한다."""
    modules = {
        "static": _module(
            risk_score=None,
            manifest={"permissions": [], "dangerous_permissions": ["x"]},
            code_analysis={"obfuscation_detected": True},
            strings={},
            certificate={},
        ),
        "dynamic": {"status": "failed", "data": None},
        "network": {"status": "failed", "data": None},
    }
    r = aggregate_risk(modules)

    assert r["total"] is None                      # 점수는 못 냄
    labels = [i["label"] for i in r["indicators"]["static"]]
    assert "난독화" in labels                       # 지표는 살아 있음


def test_같은_지표가_많아도_점수가_포화되지_않는다():
    """개수 상한(MAX_COUNT) 적용 확인 — 평문 10건과 1000건이 같은 점수여야 한다."""
    a = aggregate_risk({"static": {"status": "failed", "data": None},
                        "dynamic": _dynamic(plaintext=10),
                        "network": {"status": "failed", "data": None}})
    b = aggregate_risk({"static": {"status": "failed", "data": None},
                        "dynamic": _dynamic(plaintext=1000),
                        "network": {"status": "failed", "data": None}})
    assert a["score100"] == b["score100"]
    assert a["score100"] < 100      # 한 종류만으로는 만점이 안 나온다
