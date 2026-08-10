"""
views/static_data.py — 정적 분석 뷰가 쓰는 값 가공 (역할 B, 왕은서 담당, 7주차)

static_view.py에서 "dict를 표에 넣을 값으로 바꾸는" 부분만 떼어낸 파일이다.
여기에는 streamlit이 전혀 없어서 `pytest`로 그대로 검증할 수 있다.

왜 나눴는가:
  6주차에 어댑터 테스트가 전부 fixture dict 기반이라 원천에서 필드가 빠지는 걸
  못 잡았던 적이 있다(HANDOFF_B_to_A_D.md 6절). 화면 코드를 통째로 한 파일에
  두면 "눈으로 봐야만 확인되는 코드"가 되어 같은 구멍이 또 생긴다. 정렬 순서,
  None 처리, 점수 표기 같은 판단은 전부 이쪽에 두고 테스트로 고정한다.

값이 없을 때의 원칙:
  analyze_static()은 하위 단계가 실패해도 예외를 던지지 않고 그 값을 None으로
  둔 채 정상 반환한다(errors에만 기록). 따라서 어떤 필드든 None으로 들어올 수
  있다고 가정한다. 특히 **점수가 없을 때 0으로 채우지 않는다** — "위험도 0 =
  안전한 앱"으로 읽히기 때문이고, A도 static_view.py 주석에 같은 주의를 남겼다.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

# src/를 import 경로에 넣는다. app.py로 실행할 때는 pipeline_bridge가 먼저
# import되면서 이미 넣어주지만, 거기에 기대면 "app.py의 import 순서가 바뀌면
# 정적 탭만 깨지는" 상태가 된다. 실제로 demo_static.py를 그냥 실행했을 때
# ModuleNotFoundError: static_analyzer가 났었다. 이 모듈만 단독으로 import해도
# 되도록 여기서 직접 넣는다. (pytest는 pytest.ini의 pythonpath로 이미 해결)
_SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from common import safe_get  # noqa: E402 — sys.path 조정 이후에 import
from static_analyzer.manifest_parser import ABUSE_EXAMPLES, PERMISSION_WEIGHTS  # noqa: E402
from static_analyzer.static_adapter import permission_risk_level  # noqa: E402

# ── 색 ──
# A의 common.py STATUS_COLORS와 같은 streamlit 색 이름을 쓴다. 7주차 계획의
# "D의 위험도 게이지와 B의 권한 강조 색을 통일" 항목 대응 — 여기서 hex를 새로
# 정하면 A의 배지와 톤이 어긋나므로, 같은 팔레트를 그대로 재사용한다.
# D가 위험도 게이지를 만들 때도 이 표를 가져다 쓰면 세 화면의 빨강이 같아진다.
RISK_COLORS: dict[str, str] = {
    "high": "red",      # common.STATUS_COLORS["failed"]와 동일
    "medium": "orange",  # common.STATUS_COLORS["partial"]와 동일
    "low": "gray",       # 초록은 "안전 확인됨"으로 읽혀서 쓰지 않는다
}

RISK_LABELS_KO: dict[str, str] = {"high": "높음", "medium": "중간", "low": "낮음"}

# 값이 없을 때 쓰는 문구. "0"이나 "-"로 적지 않는 이유는 파일 상단 참고.
NO_VALUE = "계산 실패"

# meta.min_sdk / target_sdk가 0이면 "SDK 0"이 아니라 파싱 실패라는 뜻이다
# (apk_extractor._safe_int가 실패 시 0을 넣는다). 6주차에 A가 "구분 표시는
# 대시보드 몫"으로 정한 항목이라 여기서 구분한다.
SDK_PARSE_FAILED = "파싱 실패"

# 보고서에서 "강조"하기로 명시한 3종(문자·접근성·화면 덮어쓰기).
# Anubis 같은 뱅킹 트로이목마가 함께 요구하는 조합이라, 권한 수십 개 사이에
# 섞여 있으면 눈에 안 띈다. 표 위로 따로 뽑아 올린다.
HIGHLIGHT_GROUPS: list[tuple[str, tuple[str, ...]]] = [
    (
        "문자(SMS) 접근",
        (
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
        ),
    ),
    ("접근성 서비스", ("android.permission.BIND_ACCESSIBILITY_SERVICE",)),
    ("화면 덮어쓰기", ("android.permission.SYSTEM_ALERT_WINDOW",)),
]

# risk_breakdown의 factor 중 권한이 아닌 항목의 한국어 설명.
# D의 risk_scorer가 만드는 문자열을 접두사로 매칭한다 — 개수가 붙는 항목
# ("exported_components×2 (3개)")이 있어서 완전일치로는 못 잡는다.
_FACTOR_LABELS_KO: list[tuple[str, str]] = [
    ("exported_components", "외부에 열린 컴포넌트 — 다른 앱이 직접 호출할 수 있음"),
    ("suspicious_api_calls", "의심스러운 API 호출"),
    ("suspicious_strings", "의심스러운 문자열"),
    ("obfuscation_detected", "코드 난독화 — 분석을 어렵게 만들어 둠"),
    ("reflection_usage", "리플렉션 사용 — 호출 대상을 실행 중에 정함"),
    ("dynamic_code_loading", "동적 코드 로딩 — 실행 중 외부 코드를 불러옴"),
    ("certificate.is_self_signed", "자가 서명 인증서 — 공식 배포처를 확인할 수 없음"),
]

_LEVEL_ORDER = {"high": 0, "medium": 1, "low": 2}


def _as_list(value: Any) -> list:
    """리스트가 아니면 빈 리스트. safe_get의 default=[]로는 '값이 있는데 dict'인
    경우를 못 걸러서 타입까지 확인한다."""
    return value if isinstance(value, list) else []


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


# ────────────────────────────────────────────────────────────
# 기본 정보
# ────────────────────────────────────────────────────────────

def format_sdk(value: Any) -> str:
    """min_sdk / target_sdk 표시용. 0은 값이 아니라 파싱 실패라서 구분한다."""
    if value is None:
        return NO_VALUE
    if isinstance(value, bool) or not isinstance(value, int):
        return str(value)
    return SDK_PARSE_FAILED if value == 0 else str(value)


def build_meta_rows(data: Any) -> list[dict[str, str]]:
    """앱 기본 정보 표."""
    size = safe_get(data, "meta", "file_size")
    return [
        {"항목": "패키지명", "값": str(safe_get(data, "meta", "package_name", default=NO_VALUE))},
        {"항목": "버전", "값": str(safe_get(data, "meta", "version_name", default=NO_VALUE))},
        {"항목": "최소 SDK", "값": format_sdk(safe_get(data, "meta", "min_sdk"))},
        {"항목": "타깃 SDK", "값": format_sdk(safe_get(data, "meta", "target_sdk"))},
        {
            "항목": "파일 크기",
            "값": f"{size:,} bytes" if isinstance(size, int) and not isinstance(size, bool) else NO_VALUE,
        },
        {"항목": "SHA-256", "값": str(safe_get(data, "meta", "file_hash", "sha256", default=NO_VALUE))},
    ]


# ────────────────────────────────────────────────────────────
# 권한
# ────────────────────────────────────────────────────────────

def build_permission_rows(data: Any) -> list[dict[str, Any]]:
    """권한 표. 위험한 것이 위로 오도록 정렬한다.

    정렬 기준: 등급(high>medium>low) -> 가중치 내림차순 -> 이름.
    권한이 수십 개인 앱에서 위험 권한이 알파벳 순서에 묻히지 않게 하려는 것이다.
    """
    rows = []
    for raw_name in _as_list(safe_get(data, "manifest", "permissions")):
        name = str(raw_name)
        level = permission_risk_level(name)
        rows.append(
            {
                "name": name,
                # android.permission. 접두사를 뗀 짧은 이름 — 표 폭을 아끼려고.
                "short_name": name.rsplit(".", 1)[-1] if "." in name else name,
                "risk_level": level,
                "risk_label": RISK_LABELS_KO[level],
                "weight": PERMISSION_WEIGHTS.get(name, 0),
                # 설명이 없는 권한은 빈 문자열로 두고 표에서 빈 칸이 된다.
                "abuse_example": ABUSE_EXAMPLES.get(name, ""),
            }
        )

    rows.sort(key=lambda r: (_LEVEL_ORDER[r["risk_level"]], -r["weight"], r["name"]))
    return rows


def count_by_level(rows: list[dict[str, Any]]) -> dict[str, int]:
    """등급별 개수. 표 위 요약 문구용."""
    counts = {"high": 0, "medium": 0, "low": 0}
    for row in rows:
        counts[row["risk_level"]] += 1
    return counts


def build_highlights(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """HIGHLIGHT_GROUPS 3종의 검출 여부.

    검출 안 된 그룹도 목록에서 빼지 않는다 — "SMS 권한이 없다"는 것 자체가
    사용자에게 의미 있는 정보이고, 항목이 사라지면 앱마다 화면 구성이 달라져서
    여러 앱을 비교할 때 헷갈린다.
    """
    found = {r["name"] for r in rows}
    highlights = []
    for group_name, permissions in HIGHLIGHT_GROUPS:
        hit = [p for p in permissions if p in found]
        highlights.append(
            {
                "group": group_name,
                "detected": bool(hit),
                "permissions": hit,
                "short_names": [p.rsplit(".", 1)[-1] for p in hit],
            }
        )
    return highlights


# ────────────────────────────────────────────────────────────
# 인증서 / 컴포넌트
# ────────────────────────────────────────────────────────────

def is_self_signed(data: Any) -> bool:
    """자가 서명 여부. 값이 없으면 False로 본다(경고를 띄우지 않음)."""
    return safe_get(data, "certificate", "is_self_signed") is True


def build_certificate_rows(data: Any) -> Optional[list[dict[str, str]]]:
    """서명 인증서 표. 인증서 분석이 실패했으면 None(표 대신 안내 문구를 띄운다)."""
    cert = safe_get(data, "certificate")
    if not isinstance(cert, dict) or not cert:
        return None

    self_signed = cert.get("is_self_signed")
    if self_signed is True:
        signed_text = "예 — 공식 배포처를 확인할 수 없음"
    elif self_signed is False:
        signed_text = "아니오"
    else:
        signed_text = NO_VALUE

    return [
        {"항목": "발급자(issuer)", "값": str(cert.get("issuer") or NO_VALUE)},
        {"항목": "대상(subject)", "값": str(cert.get("subject") or NO_VALUE)},
        {"항목": "유효기간 시작", "값": str(cert.get("valid_from") or NO_VALUE)},
        {"항목": "유효기간 종료", "값": str(cert.get("valid_to") or NO_VALUE)},
        {"항목": "자가 서명", "값": signed_text},
    ]


def build_exported_component_rows(data: Any) -> list[dict[str, Any]]:
    """외부에 열린 컴포넌트. 개수가 그대로 점수에 들어가는 항목이라 근거로 같이 보여준다."""
    exported_names = {str(n) for n in _as_list(safe_get(data, "manifest", "exported_components"))}

    rows: list[dict[str, Any]] = []
    seen = set()
    for component in _as_list(safe_get(data, "manifest", "components")):
        component = _as_dict(component)
        name = str(component.get("name") or "")
        if not name or component.get("exported") is not True:
            continue
        seen.add(name)
        rows.append(
            {
                "name": name,
                "type": str(component.get("type") or "-"),
                "intent_filters": [str(f) for f in _as_list(component.get("intent_filters"))],
            }
        )

    # components 필드가 없는 구버전 출력용 폴백 — 이름만이라도 보여준다.
    for name in sorted(exported_names - seen):
        rows.append({"name": name, "type": "-", "intent_filters": []})

    return rows


# ────────────────────────────────────────────────────────────
# 코드 / 문자열
# ────────────────────────────────────────────────────────────

def build_code_flags(data: Any) -> list[dict[str, Any]]:
    """코드 분석의 참/거짓 플래그 4종."""
    return [
        {"label": "코드 난독화", "on": safe_get(data, "code_analysis", "obfuscation_detected") is True},
        {"label": "리플렉션 사용", "on": safe_get(data, "code_analysis", "reflection_usage") is True},
        {"label": "동적 코드 로딩", "on": safe_get(data, "code_analysis", "dynamic_code_loading") is True},
        {
            "label": "네이티브 라이브러리",
            "on": bool(_as_list(safe_get(data, "code_analysis", "native_libraries"))),
        },
    ]


def build_suspicious_api_rows(data: Any) -> list[dict[str, str]]:
    """의심 API 호출 목록. {api, location, risk} 형태를 표로 쓸 수 있게 정리."""
    rows = []
    for call in _as_list(safe_get(data, "code_analysis", "suspicious_api_calls")):
        call = _as_dict(call)
        rows.append(
            {
                "API": str(call.get("api") or "-"),
                "위치": str(call.get("location") or "-"),
                "위험도": str(call.get("risk") or "-"),
            }
        )
    return rows


def build_strings_view(data: Any) -> dict[str, list[str]]:
    """코드에서 뽑아낸 URL / IP / 의심 문자열.

    urls와 ip_addresses는 네트워크 모듈의 suspicious.domains/ips와 대조하는 데도
    쓰인다(D가 검토 중) — "코드에 박혀 있던 주소로 실제 통신까지 했다"는 근거가
    되므로 화면에도 그대로 노출한다.
    """
    return {
        "urls": [str(v) for v in _as_list(safe_get(data, "strings", "urls"))],
        "ip_addresses": [str(v) for v in _as_list(safe_get(data, "strings", "ip_addresses"))],
        "suspicious_strings": [
            str(v) for v in _as_list(safe_get(data, "strings", "suspicious_strings"))
        ],
    }


# ────────────────────────────────────────────────────────────
# 점수
# ────────────────────────────────────────────────────────────

def static_score_100(data: Any) -> Optional[float]:
    """정적 분석 자체 점수를 0~100으로. 계산이 실패했으면 None.

    이건 정적 모듈 단독 점수이고, 종합 위험도 탭(D 담당)의 값과는 다른 것이다.
    같은 대시보드에 두 점수가 뜨므로 화면 라벨에 "정적 분석"을 반드시 붙인다.
    """
    score = safe_get(data, "risk_score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        return None
    return round(float(score) * 100, 1)


def factor_label_ko(factor: str) -> str:
    """breakdown의 factor를 사람이 읽는 문구로.

    권한이면 짧은 이름 + 악용 예시, 집계 항목이면 _FACTOR_LABELS_KO의 설명.
    모르는 factor가 와도 원문을 그대로 돌려주므로 표 칸이 비지 않는다.
    """
    if factor.startswith("android.permission.") or factor in PERMISSION_WEIGHTS:
        short = factor.rsplit(".", 1)[-1]
        example = ABUSE_EXAMPLES.get(factor)
        return f"{short} — {example}" if example else short

    for prefix, label in _FACTOR_LABELS_KO:
        if factor.startswith(prefix):
            return label
    return factor


def build_breakdown_rows(data: Any) -> list[dict[str, Any]]:
    """점수 근거 표. 기여도가 큰 항목이 위로 온다.

    D의 calculate_risk_with_breakdown()이 만든 것을 옮기기만 하고 여기서 점수를
    다시 계산하지 않는다 — 계산이 두 군데 있으면 반드시 어긋난다.
    """
    rows = []
    for item in _as_list(safe_get(data, "risk_breakdown", "breakdown")):
        item = _as_dict(item)
        factor = str(item.get("factor") or "")
        weight = item.get("weight")
        if not factor or isinstance(weight, bool) or not isinstance(weight, (int, float)):
            continue
        rows.append({"factor": factor, "label": factor_label_ko(factor), "weight": float(weight)})

    rows.sort(key=lambda r: (-r["weight"], r["factor"]))
    return rows


def breakdown_matches_raw(data: Any) -> Optional[bool]:
    """breakdown 항목의 합이 raw와 맞는지. raw가 없으면 None.

    맞지 않으면 근거가 빠졌거나 중복된 것이므로 화면에 경고를 띄운다.
    6주차에 어댑터에서 권한만 재현했다가 합이 total과 안 맞았던 문제를
    화면 쪽에서도 한 번 더 잡는 장치다.
    """
    raw = safe_get(data, "risk_breakdown", "raw")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    total = sum(r["weight"] for r in build_breakdown_rows(data))
    return abs(total - float(raw)) < 0.01
