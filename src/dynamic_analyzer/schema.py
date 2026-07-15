# dynamic_analyzer/schema.py
"""
동적 분석 모듈 출력 타입 정의. (C 작성, 4주차 과제)
이 파일이 팀 공유 계약이다 — 아래 필드명/타입을 임의로 바꾸면 다른 모듈이 깨진다.
필드를 바꿔야 하면 팀 전체에 공유한 뒤 이 파일부터 고친다.
"""
from typing import Dict, List, Literal, Optional, TypedDict

# ── B가 hooks.js에서 send()로 보내는 개별 후킹 이벤트(변경 가능) ──
HookType = Literal["string_builder", "base64", "cipher", "custom_xor"]

class HookEvent(TypedDict):
    hook_type: HookType          # 어떤 후킹에서 잡혔는지
    timestamp: str               # ISO 8601, JS 쪽 Date().toISOString()
    class_name: str              # 후킹된 클래스 (예: "java.lang.StringBuilder")
    method_name: str             # 후킹된 메서드 (예: "append", "doFinal")
    raw_value: str               # 실제로 잡힌 값 (평문/암호문/조립된 문자열)
    extra: Dict[str, str]        # 후킹 종류별 부가 정보 (아래 예시)
    thread_id: Optional[int]     # 크래시/타이밍 디버깅용, 없어도 됨

# extra 필드 안에 hook_type별로 들어가는 값 예시 (딕셔너리라 자유롭게):
#   string_builder → {}  (보통 부가정보 없음, raw_value가 핵심)
#   base64         → {"direction": "decode" | "encode"}
#   cipher         → {"algorithm": "AES/CBC/PKCS5Padding", "mode": "decrypt"|"encrypt"}
#   custom_xor     → {"detected_pattern": "string_assembly"}


# ── C가 필터링/정제 후 최종적으로 만드는 산출물 ──
class DynamicAnalysisResult(TypedDict):
    package_name: str
    session_duration_sec: int
    total_events_captured: int      # 필터링 전 원본 개수 (노이즈 포함)
    total_events_filtered: int      # 필터링 후 최종 개수
    events: List[HookEvent]         # 정제된 최종 이벤트 리스트
    plaintext_candidates: List[str] # 평문으로 판별된 문자열만 별도로 뽑아둔 것
    errors: List[str]               # 부분 실패 시 누적, 빈 리스트면 성공
    
# total_events_captured/filtered: 노이즈 대비 실제 유효 데이터 비율 구하기(최종발표때)