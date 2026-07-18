# dynamic_analyzer/message_parser.py
from .schema import HookEvent

def on_message(message: dict, data=None):
    """script.on('message', on_message) 에 그대로 등록할 콜백"""
    print("[디버그] 전체 메시지:", message)  # 이 줄 추가
    if message["type"] == "send":
        payload: HookEvent = message["payload"]
        _handle_hook_event(payload)
    elif message["type"] == "error":
        print(f"[hooks.js 런타임 에러] {message['description']}")

def _handle_hook_event(event: HookEvent):
    # 3일차에 실데이터 들어오면 여기서부터 진짜 처리
    print(f"[{event['hook_type']}] {event['method_name']} → {event['raw_value']}")

# 더미 테스트용 — 3일차 되기 전까지 이걸로 파서 로직 검증
DUMMY_EVENTS = [
    {
        "type": "send",
        "payload": {
            "hook_type": "base64",
            "timestamp": "2026-07-15T10:00:00Z",
            "class_name": "android.util.Base64",
            "method_name": "decode",
            "raw_value": "aGVsbG8gd29ybGQ=",
            "extra": {"direction": "decode"},
            "thread_id": 1
        }
    }
]

if __name__ == "__main__":
    for msg in DUMMY_EVENTS:
        on_message(msg)