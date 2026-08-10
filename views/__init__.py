"""views 패키지 — 대시보드 탭별 화면.

여기서 import 경로를 한 번만 맞춘다 (8주차 Day1, B의 7주차 A-1 요청 처리).

경위:
    views/*.py는 저장소 루트의 common.py와 src/ 아래 분석 모듈을 둘 다 import한다.
    그런데 두 경로를 sys.path에 넣어주는 것은 pipeline_bridge.py이고, app.py가
    우연히 그것을 먼저 import하고 있어서 **동작하는 것처럼 보였다**. 실제로
    `streamlit run demo_static.py`처럼 뷰를 단독으로 띄우면
    ModuleNotFoundError: static_analyzer가 났다(7주차 B 4-(3)).

    7주차에는 views/static_data.py가 스스로 sys.path를 조작해 막았는데, 그대로 두면
    C의 dynamic_analyzer, D의 network_analyzer import에서 같은 코드가 3벌이 된다.
    파이썬은 `views.static_view`를 import할 때 이 __init__.py를 반드시 먼저 실행하므로,
    여기 한 번만 두면 모든 뷰가 덮인다.

    (pytest는 pytest.ini의 `pythonpath = src .`로 이미 해결돼 있어 이 파일과 무관하게
    동작한다. 여기가 필요한 것은 streamlit으로 띄울 때다.)

주의:
    이 파일은 원래 A(유예원)의 골격 파일이다. 8주차 Day1 정리에서 B가 채웠으므로
    A가 한 번 확인할 것.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = _REPO_ROOT / "src"

# 앞쪽에 넣되 순서는 루트 -> src. common.py(루트)가 먼저 잡혀야 한다.
for _p in (_SRC_DIR, _REPO_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
