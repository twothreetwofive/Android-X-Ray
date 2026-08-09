"""
demo_static.py — 정적 분석 탭만 따로 띄워보는 확인용 화면 (역할 B, 왕은서 담당)

    streamlit run demo_static.py

app.py는 APK 업로드 -> 실제 파이프라인 실행이 있어야 화면이 나오는데, 정적 화면을
고칠 때마다 apktool/jadx를 돌리면 한 번에 몇 분씩 걸린다. 이 파일은
views/static_samples.py의 가짜 데이터를 바로 render()에 넣어서, 분석 도구가
하나도 없는 PC에서도 화면만 즉시 확인할 수 있게 한 것이다.

왼쪽에서 "정상 / 일부 실패 / 전체 실패" 세 가지를 바꿔 가며 볼 수 있다.
**셋 다 화면이 죽지 않고 배지와 안내 문구만 바뀌어야 한다** — 7주차 검증 항목
("일부러 모듈을 실패시켜도 대시보드가 안 죽는지")을 정적 탭에서 미리 확인하는 것.

실제 APK로 확인할 때는 이 파일이 아니라 app.py를 쓸 것.
"""
from __future__ import annotations

import streamlit as st

from views.static_samples import SAMPLES, as_report
from views.static_view import render

st.set_page_config(page_title="Android X-Ray — 정적 탭 확인용", layout="wide")

st.title("정적 분석 탭 (확인용)")
st.caption(
    "표시되는 값은 전부 손으로 만든 샘플이며 실제 분석 결과가 아닙니다. "
    "실제 분석은 `streamlit run app.py`로 하세요."
)

with st.sidebar:
    st.header("샘플 선택")
    choice = st.radio("정적 분석 결과", list(SAMPLES.keys()), label_visibility="collapsed")
    st.caption("어떤 것을 골라도 화면이 죽지 않아야 합니다.")

render(as_report(SAMPLES[choice]))
