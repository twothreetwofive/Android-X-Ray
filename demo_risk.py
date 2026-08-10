"""
demo_risk.py — 종합 위험도 탭만 따로 띄워보는 확인용 화면

    streamlit run demo_risk.py

B의 demo_static.py와 같은 방식(7주차 B 보고서 C-1 제안). 기기도 샘플도 없이
게이지·기여도 화면을 손볼 수 있게 하려는 것.

이 파일이 생긴 경위: 8주차 Day1에 views/risk_view.py에서 "total=None이면 더미를
자동으로 그린다"를 뺐다(분석이 통째로 실패한 리포트에 72점 "위험"이 뜨는 문제).
대신 더미는 DEMO_FLAG를 켰을 때만 나오게 했고, 그 플래그를 켜주는 자리가 여기다.
즉 D가 기기 없이 화면을 보던 방법은 그대로 남아 있고, 실측 화면에만 안 섞인다.

왼쪽에서 상태를 바꿔 가며 볼 것. **어느 것을 골라도 화면이 죽지 않아야 한다.**
"""
from __future__ import annotations

import streamlit as st

from views.risk_view import DEMO_FLAG, render

st.set_page_config(page_title="Android X-Ray — 위험도 탭 확인용", layout="wide")

st.title("종합 위험도 탭 (확인용)")
st.caption(
    "표시되는 값은 전부 가짜이며 실제 분석 결과가 아닙니다. "
    "실제 분석은 `streamlit run app.py`로 하세요."
)

# aggregate_risk()의 실제 출력 형태를 그대로 흉내낸 리포트들.
CASES: dict[str, dict] = {
    "정상 (세 모듈 다 살아있음)": {
        "modules": {
            "static": {"status": "ok"},
            "dynamic": {"status": "ok"},
            "network": {"status": "ok"},
        },
        "risk_score": None,  # None이면 아래에서 더미(_DUMMY_RISK)가 그려진다
    },
    "네트워크만 실패 (가중치 재정규화)": {
        "modules": {
            "static": {"status": "ok"},
            "dynamic": {"status": "ok"},
            "network": {"status": "failed"},
        },
        "risk_score": {
            "total": 0.41,
            "level": "medium",
            "breakdown": {
                "modules": {
                    "static": {"available": True, "weight": 0.571, "sub_score": 0.52},
                    "dynamic": {"available": True, "weight": 0.429, "sub_score": 0.26},
                    "network": {"available": False},
                },
                "weights_applied": {"static": 0.571, "dynamic": 0.429},
                "unavailable": ["network"],
            },
        },
    },
    "전부 실패 (판정 불가)": {
        "modules": {
            "static": {"status": "failed"},
            "dynamic": {"status": "failed"},
            "network": {"status": "failed"},
        },
        "risk_score": {"total": None, "level": "unknown", "breakdown": {}},
    },
}

with st.sidebar:
    st.header("상태 선택")
    choice = st.radio("리포트 상태", list(CASES), label_visibility="collapsed")
    st.caption("어떤 것을 골라도 화면이 죽지 않아야 합니다.")

# "정상" 케이스만 더미가 필요하다. "전부 실패"는 판정 불가 화면이 나와야 하므로
# 플래그를 끈다 — 실측에서 이 화면이 어떻게 보이는지를 그대로 확인하려는 것.
st.session_state[DEMO_FLAG] = choice == "정상 (세 모듈 다 살아있음)"

render(CASES[choice])
