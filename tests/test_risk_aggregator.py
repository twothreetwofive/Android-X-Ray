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


# ────────────────────────────────────────────
# "관측 없음"은 "위험 없음"이 아니다 (8주차 선택지 1)
# ────────────────────────────────────────────

def test_관측치가_없는_모듈은_점수에서_제외된다():
    """정상 실행됐지만 아무것도 관측 못 한 모듈을 0점으로 넣으면
    그 축에서 '안전 확인됨'으로 계산된다. 실패 모듈과 똑같이 제외한다."""
    modules = {
        "static": _static(risk_score=0.8),
        "dynamic": _dynamic(plaintext=0, cipher=0),      # 이벤트 0
        "network": _network(dns=0, sni=0),               # 트래픽 0
    }
    r = aggregate_risk(modules)

    assert set(r["breakdown"]["unavailable"]) == {"dynamic", "network"}
    assert r["breakdown"]["modules"]["network"]["reason"] == "no_observations"
    # 정적만 남으므로 가중치가 1.0으로 재정규화되어 정적 점수가 그대로 종합이 된다.
    assert r["score100"] == 80


def test_관측_없음과_분석_실패는_구분된다():
    """화면에서 '분석이 실패했다'와 '분석은 됐는데 볼 게 없었다'는 다르게 읽혀야 한다."""
    r = aggregate_risk({
        "static": _static(risk_score=0.5),
        "dynamic": {"status": "failed", "data": None},
        "network": _network(dns=0, sni=0),
    })
    mods = r["breakdown"]["modules"]

    assert mods["dynamic"].get("reason") is None          # 실패는 사유 표기 없음
    assert mods["network"]["reason"] == "no_observations"
    assert "관측" in mods["network"]["reason_ko"]


def test_관측이_하나라도_있으면_점수에_들어간다():
    """필터가 과하게 먹어서 실제 신호까지 빠지면 안 된다."""
    r = aggregate_risk({
        "static": _static(risk_score=0.5),
        "dynamic": _dynamic(cipher=1),                    # 이벤트 1건
        "network": _network(dns=1),                       # DNS 1건
    })
    assert r["breakdown"]["unavailable"] == []


def test_전부_관측이_없어도_정적이_있으면_판정은_나온다():
    r = aggregate_risk({
        "static": _static(risk_score=0.9),
        "dynamic": _dynamic(),
        "network": _network(),
    })
    assert r["total"] is not None
    assert r["verdict"]["code"] == "high_risk"


# ────────────────────────────────────────────
# 정보탈취 후킹 (source/sink) — 8주차
#
# 위장 정보탈취 앱은 연락처·기기ID를 읽어(source) 밖으로 보낸다(sink). 목적지가
# 루프백이어도(학습용 샘플) network_send 이벤트로 잡히고, "읽기+전송" 조합일 때만
# 강한 지표(info_stealer_pattern)로 승격한다. 개별 신호는 정상 앱도 흔하므로 강한
# 지표로 세지 않는다 — 평문 후보/동적로딩 단독을 안 세는 것과 같은 원칙이다.
# ────────────────────────────────────────────

def _dynamic_behavioral(sensitive=0, send=0, dest_type="loopback"):
    events = [{"hook_type": "sensitive_read", "extra": {"data_type": "contacts"}}] * sensitive
    events += [{"hook_type": "network_send", "extra": {"dest_type": dest_type}}] * send
    return _module(plaintext_candidates=[], events=events)


def test_정보탈취_패턴은_읽기와_전송이_겹칠_때만_강한_지표():
    r = aggregate_risk({
        "static": _static(risk_score=0.4),
        "dynamic": _dynamic_behavioral(sensitive=2, send=1),
        "network": {"status": "failed", "data": None},
    })
    strong = [i["code"] for i in r["verdict"]["strong_indicators"]]
    assert "info_stealer_pattern" in strong


def test_민감정보_읽기만으로는_강한_지표가_아니다():
    r = aggregate_risk({
        "static": _static(risk_score=0.4),
        "dynamic": _dynamic_behavioral(sensitive=3, send=0),
        "network": {"status": "failed", "data": None},
    })
    codes = [i["code"] for i in r["indicators"]["dynamic"]]
    strong = [i["code"] for i in r["verdict"]["strong_indicators"]]
    assert "sensitive_read" in codes            # 지표로는 보여준다
    assert "info_stealer_pattern" not in strong  # 승격 근거로는 안 쓴다


def test_외부_전송만으로는_강한_지표가_아니다():
    r = aggregate_risk({
        "static": _static(risk_score=0.4),
        "dynamic": _dynamic_behavioral(sensitive=0, send=3),
        "network": {"status": "failed", "data": None},
    })
    strong = [i["code"] for i in r["verdict"]["strong_indicators"]]
    assert "info_stealer_pattern" not in strong


def test_행위_후킹만_있어도_관측으로_집계된다():
    """루프백 전송처럼 DNS/암복호화가 없어도, source/sink 이벤트가 있으면
    동적 모듈이 '관측 없음'으로 빠지지 않아야 한다(이 후킹을 넣은 이유)."""
    r = aggregate_risk({
        "static": _static(risk_score=0.4),
        "dynamic": _dynamic_behavioral(sensitive=1, send=1),
        "network": {"status": "failed", "data": None},
    })
    assert "dynamic" not in r["breakdown"]["unavailable"]
    assert r["breakdown"]["modules"]["dynamic"]["available"] is True
