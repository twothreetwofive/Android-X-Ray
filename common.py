"""
common.py — 대시보드 공용 유틸리티 (7~8주차, 역할 A 유예원 담당)

B/C/D의 views/*.py가 공통으로 쓰는 것만 모아둔다:
- status_badge(status): main.py의 module_status(ok/partial/failed/timeout)를
  일관된 색/아이콘으로 표시하는 마크다운 문자열을 만든다.
- safe_get(d, *keys, default=None): report["modules"]["static"]["data"]["meta"]...
  처럼 중첩 dict를 내려갈 때, 중간에 모듈이 실패해서 None이 껴 있어도 죽지 않게 방어.
- STATUS_COLORS / STATUS_ICONS: 네 명 산출물의 색 톤을 맞추기 위한 공용 표.
  D의 위험도 게이지, B의 권한 강조색 등도 이 표를 재사용할 것 — 각자 다른 색을
  쓰면 대시보드가 4명이 따로 만든 것처럼 보인다.

주의: 이 파일은 streamlit 없이도(단위테스트 등에서) safe_get()을 쓸 수 있도록
streamlit import를 최상단에 두지 않고, streamlit이 실제로 필요한 함수 안에서만
지연 import한다.
"""
from __future__ import annotations

from typing import Any, Optional

STATUS_COLORS: dict[str, str] = {
    "ok": "green",
    "partial": "orange",
    "failed": "red",
    "timeout": "gray",
}

STATUS_ICONS: dict[str, str] = {
    "ok": "✅",
    "partial": "⚠️",
    "failed": "❌",
    "timeout": "⏱️",
}

STATUS_LABELS_KO: dict[str, str] = {
    "ok": "정상",
    "partial": "부분 실패",
    "failed": "실패",
    "timeout": "타임아웃",
}


def status_badge(status: Optional[str]) -> str:
    """main.py의 module_status를 st.markdown()에 바로 넣을 수 있는 색깔
    텍스트로 변환한다 (streamlit의 `:color[text]` 마크다운 문법 사용).

    사용 예:
        st.markdown(status_badge(report["modules"]["static"]["status"]))
    """
    if status is None or status not in STATUS_COLORS:
        status = "failed" if status is None else status
    color = STATUS_COLORS.get(status, "gray")
    icon = STATUS_ICONS.get(status, "•")
    label = STATUS_LABELS_KO.get(status, status)
    return f":{color}[{icon} {label}]"


def safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """중첩 dict를 안전하게 내려간다. 중간에 None이거나 dict가 아니거나 키가
    없으면 그 즉시 default를 반환한다.

    main.py의 report는 모듈이 실패하면 modules.<name>.data가 None이거나 일부
    필드만 채워진 채로 온다 — dict 체이닝(d["a"]["b"]["c"])을 그대로 쓰면
    KeyError/TypeError로 뷰 전체가 죽는다. views/*.py에서는 이 함수를 통해서만
    report 안쪽 값에 접근할 것.

    예:
        safe_get(report, "modules", "static", "data", "meta", "package_name")
        safe_get(report, "modules", "network", "data", "suspicious", "domains", default=[])
    """
    cur = d
    for k in keys:
        if cur is None:
            return default
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return default
    return cur if cur is not None else default


def render_errors(errors: Optional[list]) -> None:
    """errors 리스트를 접이식(expander)으로 보여주는 공용 컴포넌트.
    views/*.py에서 각 모듈 렌더링 마지막에 호출하면 된다.
    errors가 비었거나 None이면 아무것도 그리지 않는다."""
    import streamlit as st  # 지연 import

    if not errors:
        return
    with st.expander(f"⚠️ 경고/에러 {len(errors)}건", expanded=False):
        for e in errors:
            st.write(f"- {e}")


def render_module_header(report: dict, module_name: str, title: str) -> dict:
    """뷰 파일 맨 위에서 공통으로 하는 일(상태 배지 표시 + error 메시지 표시 +
    module dict 꺼내기)을 한 번에 처리하고, 그 모듈의 raw dict를 반환한다.

    사용 예 (views/static_view.py):
        module = render_module_header(report, "static", "정적 분석")
        data = module.get("data")
        if data is None:
            return
        ... 실제 시각화 ...
    """
    import streamlit as st  # 지연 import

    module = safe_get(report, "modules", module_name, default={}) or {}
    status = module.get("status")

    st.markdown(f"### {title}  {status_badge(status)}")

    if module.get("error"):
        st.error(module["error"])

    return module
