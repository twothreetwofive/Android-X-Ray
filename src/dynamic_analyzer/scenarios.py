"""
[D] 테스트 시나리오 정의 (1일차 과제: "테스트 시나리오 목록 작성")

여기 정의된 Scenario들을 scenario_runner.py가 AdbRunner로 실행하면서
A/B/C가 만든 frida_controller.py + hooks.bundle.js + message_parser.py로
관찰한다. 사람이 읽는 설명은 docs/동적분석/시나리오_정의서.md 참고 — 이 파일은
그 문서를 코드로 옮긴 것이라 내용이 항상 같이 맞아야 한다.

앱마다 로그인 화면 좌표/텍스트필드 위치가 달라서, LOGIN 시나리오의 좌표값은
현재 팀이 테스트에 쓰고 있는 com.google.android.calendar/deskclock 기준이
아니라 "실제 타겟 앱(anubis.apk 등)이 준비되면 채워야 하는 자리"로 두었다.
B가 custom_xor 훅을 자리만 만들어두고 보류한 것과 같은 이유 — 지금 저장소엔
로그인 화면이 있는 실제 분석 대상 앱이 없다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ScenarioStep:
    action: str                      # "launch" | "wait" | "tap" | "swipe" | "input_text" | "press_key" | "grant_permission"
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Scenario:
    name: str
    package_name: str
    description: str
    steps: List[ScenarioStep]


# ── 1. 기본 실행 시나리오 (좌표 불필요, 어떤 앱에도 적용 가능) ──
# A/C가 검증에 실제로 쓴 com.google.android.calendar / deskclock 기준.
# frida_controller.spawn_and_attach()가 이미 프로세스를 띄우므로 여기선
# launch 스텝을 넣지 않고 관찰 대기만 한다 (scenario_runner가 resume() 이후에 실행).
LAUNCH_ONLY = Scenario(
    name="launch_only",
    package_name="com.google.android.calendar",
    description="추가 조작 없이 앱을 띄우고 초기 구동 중 발생하는 후킹만 관찰하는 베이스라인 시나리오.",
    steps=[
        ScenarioStep("wait", {"seconds": 3}),
    ],
)

# ── 2. 로그인 시나리오 ──
# 좌표(x, y)는 대상 앱 확정 전까지 플레이스홀더. scenario_runner는 이 값을
# 그대로 실행하므로, 실제 타겟 앱으로 테스트하기 전엔 반드시 좌표를 채워야 한다.
LOGIN_FLOW = Scenario(
    name="login_flow",
    package_name="__TARGET_PACKAGE__",  # TODO: 실제 분석 대상 패키지명으로 교체
    description=(
        "로그인 화면에 아이디/비밀번호를 입력하고 로그인 버튼을 누르는 시나리오. "
        "뱅킹 트로이목마류(Anubis 등)가 자격증명을 탈취/전송하는 지점이라 "
        "cipher/base64 후킹이 여기서 실제로 잡힐 가능성이 높음."
    ),
    steps=[
        ScenarioStep("wait", {"seconds": 2}),
        ScenarioStep("tap", {"x": 0, "y": 0}),  # TODO: 아이디 입력란 좌표
        ScenarioStep("input_text", {"text": "testuser"}),
        ScenarioStep("tap", {"x": 0, "y": 0}),  # TODO: 비밀번호 입력란 좌표
        ScenarioStep("input_text", {"text": "testpassword123"}),
        ScenarioStep("tap", {"x": 0, "y": 0}),  # TODO: 로그인 버튼 좌표
        ScenarioStep("wait", {"seconds": 3}),
    ],
)

# ── 3. 권한 요청 시나리오 ──
# 좌표 탭 대신 `pm grant`로 결정적으로 권한을 준다 (AdbRunner.grant_permission 참고).
# 다이얼로그가 실제로 뜨는지 확인해야 하면 tap_permission_dialog()로 바꿔서 쓸 수 있음.
PERMISSION_REQUEST = Scenario(
    name="permission_request",
    package_name="__TARGET_PACKAGE__",  # TODO: 실제 분석 대상 패키지명으로 교체
    description=(
        "런타임 권한(연락처/SMS/접근성 등)을 요청하고 허용하는 시나리오. "
        "권한 오남용(Anubis류가 SMS/접근성 권한을 요구하는 패턴)을 재현하기 위함."
    ),
    steps=[
        ScenarioStep("wait", {"seconds": 2}),
        # TODO: 실제 타겟 앱이 요구하는 권한 문자열로 교체
        ScenarioStep("grant_permission", {"permission": "android.permission.READ_SMS"}),
        ScenarioStep("wait", {"seconds": 3}),
    ],
)


ALL_SCENARIOS: List[Scenario] = [LAUNCH_ONLY, LOGIN_FLOW, PERMISSION_REQUEST]
