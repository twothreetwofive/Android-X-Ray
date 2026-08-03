"""
[B] A(frida_controller) + B(hooks.bundle.js) + C(message_parser)를 실제로 이어붙여서
dynamic_report.json을 뽑아내는 end-to-end 통합 테스트.

각자 파일(frida_controller.py / hooks.bundle.js / message_parser.py)은 건드리지 않고
이미 있는 조각들을 그대로 연결만 한다. 실행 전 준비물:
  - adb로 에뮬레이터/기기 연결 + frida-server 실행 중
  - hooks.js를 고쳤다면 먼저 `npm run build`로 hooks.bundle.js 재생성

사용:
    python run_test.py [package_name] [observe_sec]
"""

from __future__ import annotations

import sys
import os
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dynamic_analyzer.frida_controller import FridaController
from dynamic_analyzer.message_parser import (
    on_message,
    get_captured_events,
    reset_captured_events,
    build_report,
)

HOOKS_BUNDLE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hooks.bundle.js")

def run(package_name: str, observe_sec: float = 5.0, output_path: str | None = None):
    reset_captured_events()
    
    if output_path is None:
        timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        safe_package = package_name.replace(".", "_")
        output_path = f"output/dynamic_report_{safe_package}_{timestamp}.json"

    controller = FridaController()
    controller.connect()
    print("연결된 디바이스:", controller.device.name)

    session_start = datetime.now()
    controller.spawn_and_attach(package_name)
    controller.load_script(HOOKS_BUNDLE)
    controller.script.on("message", on_message)  # C의 실데이터 수신 콜백 추가 등록
    controller.resume()

    print(f"=== {observe_sec}초 동안 관찰 ===")
    time.sleep(observe_sec)

    controller.cleanup() 

    events = get_captured_events()
    report = build_report(package_name, session_start, events, output_path)

    print(f"\n원본 {report['total_events_captured']}개 → 필터링 후 {report['total_events_filtered']}개")
    print(f"평문 후보 {len(report['plaintext_candidates'])}개 발견")
    print(f"결과 저장: {output_path}")
    return report


if __name__ == "__main__":
    pkg = sys.argv[1] if len(sys.argv) > 1 else "com.google.android.calendar"
    sec = float(sys.argv[2]) if len(sys.argv) > 2 else 5.0
    run(pkg, observe_sec=sec)
