"""
pipeline_bridge.py — Streamlit 대시보드 ↔ 오케스트레이터(src/main.py) 연결
(7~8주차, 역할 A 유예원 담당)

app.py는 src/main.py를 직접 import하지 않고 이 파일의 run() 하나만 부른다.
이렇게 한 겹 감싸두면 나중에 main.py 시그니처가 바뀌어도(예: 6주차 이후 인자
추가) app.py는 안 건드리고 이 파일만 고치면 된다.

진행상황 표시: main.py의 run_pipeline(on_progress=...)이 (stage, status) 콜백을
받게 되어 있어서, 여기서는 그 콜백을 streamlit의 st.status(...) 컨텍스트에
write()로 옮겨주기만 한다. 실제 단계 분리(정적 -> 동적+네트워크 동시 실행) 로직은
전부 main.py 쪽에 있고 여기서는 중복 구현하지 않는다.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# src/ 를 import 경로에 추가한다. 이 파일이 repo 루트에 있고 main.py는
# src/main.py에 있다는 전제 — repo 구조가 바뀌면 이 부분만 고치면 된다.
_REPO_ROOT = Path(__file__).resolve().parent
_SRC_DIR = _REPO_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

import main as orchestrator  # noqa: E402 — sys.path 조정 이후에 import해야 함


STAGE_LABELS = {
    "static": "정적 분석",
    "dynamic": "동적 분석",
    "network": "네트워크 분석",
}


def run(
    apk_path: str,
    work_dir: str = "work",
    progress_status=None,
) -> dict:
    """apk_path를 분석해서 main.py의 통합 report dict를 그대로 반환한다.

    Args:
        apk_path: 분석할 apk 파일의 로컬 경로 (app.py가 업로드 파일을 임시
            저장한 경로를 넘겨줌).
        work_dir: apktool/jadx 작업 폴더.
        progress_status: app.py에서 `st.status(...)`로 만든 컨텍스트 객체(선택).
            넘기면 단계별 진행상황을 그 안에 `.write()`로 찍는다. None이면
            진행 표시 없이 조용히 실행한다 — streamlit 없는 환경(테스트 코드 등)
            에서 이 함수를 그대로 재사용할 수 있게 하기 위함.

    Returns:
        main.run_pipeline()이 반환하는 dict 그대로. 변환하지 않는다 — 6주차
        통합 스펙(6주차_Day1_통합인터페이스_스펙.md)의 "pass-through" 원칙을
        대시보드 레이어에서도 그대로 유지한다.
    """

    def on_progress(stage: str, status: str) -> None:
        if progress_status is None:
            return
        label = STAGE_LABELS.get(stage, stage)
        if status == "running":
            progress_status.write(f"⏳ {label} 실행 중...")
            return
        from common import STATUS_ICONS  # 지연 import, 순환참조 방지

        icon = STATUS_ICONS.get(status, "•")
        progress_status.write(f"{icon} {label}: {status}")

    return orchestrator.run_pipeline(
        apk_path=apk_path,
        work_dir=work_dir,
        on_progress=on_progress,
    )
