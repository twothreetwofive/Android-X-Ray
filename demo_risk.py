"""
demo_risk.py — 최종 판정 카드 + 종합 위험도 탭을 기기 없이 미리보는 화면

    streamlit run demo_risk.py

B의 demo_static.py와 같은 방식(7주차 B 보고서 C-1 제안). 에뮬레이터도 샘플도 없이
화면을 손볼 수 있게 하려는 것.

8주차 변경
----------
1. 상단 판정 카드(views/verdict_header.py)도 같이 그린다 — app.py에서 보이는 순서
   그대로 확인할 수 있어야 화면 작업이 된다.
2. 손으로 쓴 리포트 fixture를 없애고 **aggregate_risk()를 실제로 호출**해서 만든다.
   이전에는 CASES에 risk_score dict를 직접 적어뒀는데, aggregator 출력 형태가 바뀌면
   (8주차에 verdict/indicators가 추가된 것처럼) 이 파일만 옛 형태로 남아 화면이
   실제와 달라진다. 입력(모듈 결과)만 가짜로 만들고 계산은 진짜를 쓰는 편이 안전하다.

이 파일이 생긴 경위: 8주차 Day1에 views/risk_view.py에서 "total=None이면 더미를
자동으로 그린다"를 뺐다(분석이 통째로 실패한 리포트에 72점 "위험"이 뜨는 문제).
대신 더미는 DEMO_FLAG를 켰을 때만 나오게 했고, 그 플래그를 켜주는 자리가 여기다.
"""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# src/의 risk_aggregator를 쓰기 위해 경로를 넣는다(views/__init__.py와 같은 방식).
_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from risk_aggregator import aggregate_risk  # noqa: E402
from views.risk_view import DEMO_FLAG, render  # noqa: E402
from views import verdict_header  # noqa: E402

st.set_page_config(page_title="Android X-Ray — 판정/위험도 확인용", layout="wide")

st.title("최종 판정 + 종합 위험도 (확인용)")
st.caption(
    "표시되는 값은 전부 가짜이며 실제 분석 결과가 아닙니다. "
    "실제 분석은 `streamlit run app.py`로 하세요."
)


def _mod(status="ok", **data):
    return {"status": status, "data": data or None}


FAILED = {"status": "failed", "data": None, "error": "기기 연결 실패"}


# 입력(모듈 결과)만 가짜다. 판정·점수·지표는 실제 aggregate_risk()가 계산한다.
CASES: dict[str, dict] = {
    "정상 앱": {
        "static": _mod(risk_score=0.10,
                       manifest={"permissions": ["android.permission.INTERNET"],
                                 "dangerous_permissions": []},
                       code_analysis={}, strings={}, certificate={}),
        "dynamic": _mod(plaintext_candidates=[], events=[{"hook_type": "string_builder"}] * 3),
        "network": _mod(suspicious={"domains": [], "ips": []},
                        dns_queries=[{}] * 5, tls_sni=[{}] * 3),
    },
    "취약하지만 악성은 아닌 앱 (PDF 사례)": {
        "static": _mod(risk_score=0.79,
                       manifest={"permissions": ["android.permission.INTERNET"],
                                 "dangerous_permissions": []},
                       code_analysis={"suspicious_api_calls": [1] * 7,
                                      "obfuscation_detected": True,
                                      "reflection_usage": True,
                                      "dynamic_code_loading": True},
                       strings={"suspicious_strings": ["x"]},
                       certificate={"is_self_signed": True}),
        "dynamic": _mod(plaintext_candidates=["p"] * 35,
                        events=[{"hook_type": "cipher"}] * 10),
        "network": _mod(suspicious={"domains": [{"domain": "test.example"}],
                                    "ips": [{"ip": f"10.0.0.{i}"} for i in range(3)]},
                        dns_queries=[{}] * 12, tls_sni=[{}] * 4),
    },
    "뱅킹 트로이목마형 (악성 승격)": {
        "static": _mod(risk_score=0.95,
                       manifest={"permissions": ["android.permission.READ_SMS",
                                                 "android.permission.SYSTEM_ALERT_WINDOW",
                                                 "android.permission.BIND_ACCESSIBILITY_SERVICE"],
                                 "dangerous_permissions": ["android.permission.READ_SMS"] * 8},
                       code_analysis={"suspicious_api_calls": [1] * 20,
                                      "obfuscation_detected": True,
                                      "dynamic_code_loading": True,
                                      "reflection_usage": True},
                       strings={"suspicious_strings": ["x"] * 5, "ip_addresses": ["1.2.3.4"]},
                       certificate={"is_self_signed": True}),
        "dynamic": _mod(plaintext_candidates=["p"] * 20,
                        events=[{"hook_type": "cipher"}] * 30),
        "network": _mod(suspicious={"domains": [{"domain": f"c2-{i}.example"} for i in range(4)],
                                    "ips": [{"ip": f"203.0.113.{i}"} for i in range(4)]},
                        dns_queries=[{}] * 20, tls_sni=[{}] * 6),
    },
    "네트워크만 실패 (가중치 재정규화)": {
        "static": _mod(risk_score=0.52,
                       manifest={"permissions": [], "dangerous_permissions": []},
                       code_analysis={"obfuscation_detected": True}, strings={}, certificate={}),
        "dynamic": _mod(plaintext_candidates=["p"] * 3, events=[{"hook_type": "cipher"}] * 2),
        "network": FAILED,
    },
    "전부 실패 (판정 불가)": {
        "static": FAILED,
        "dynamic": FAILED,
        "network": FAILED,
    },
}

with st.sidebar:
    st.header("샘플 상태 선택")
    choice = st.radio("리포트 상태", list(CASES), label_visibility="collapsed")
    st.caption("어떤 것을 골라도 화면이 죽지 않아야 합니다.")
    st.divider()
    st.caption(
        "입력만 가짜이고 판정·점수는 실제 `aggregate_risk()`가 계산합니다. "
        "구간 상수를 바꾸면 이 화면에 바로 반영됩니다."
    )

modules = CASES[choice]
report = {
    "apk_name": "sample.apk",
    "package_name": "com.example.sample",
    "modules": modules,
    "risk_score": aggregate_risk(modules),
}

# "전부 실패"는 판정 불가 화면이 그대로 나와야 하므로 더미를 끈다.
st.session_state[DEMO_FLAG] = False

verdict_header.render(report)
st.divider()
render(report)
