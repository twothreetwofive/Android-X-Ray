"""analyze_static() 출력 -> static_report.json 변환. (B 작성, 6주차 통합)

`schemas/static_report.schema.json`(1주차 팀 합의 스키마)이 목표 포맷이다.
현재 구현 출력(schema.py의 StaticAnalysisResult, 8개 필드)과 형태가 달라서
그 사이를 메우는 어댑터가 필요하다. 필드별 매핑 근거와 미해결 항목은
`docs/정적분석/6주차_B_필드매핑.md`에 정리돼 있다.

분석 로직은 전혀 들어있지 않고 순수 dict 변환만 한다. 그래서 실제 APK나
jadx/apktool 없이 fixture dict만으로 테스트할 수 있다.

주의 — analyze_static()은 하위 단계가 실패해도 예외를 던지지 않고 해당 값을
None으로 둔 채 정상 반환한다(errors 리스트에만 기록). 따라서 이 어댑터는 어떤
필드든 None으로 들어올 수 있다고 가정하고 방어한다.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .manifest_parser import ABUSE_EXAMPLES, PERMISSION_WEIGHTS

# risk_level 구간. 상한 8은 manifest_parser의 dangerous_permissions 필터(>= 8)와
# 같은 경계를 쓴 것이다 — 기존에 "위험 권한"이라 부르던 것이 곧 high가 되도록.
RISK_LEVEL_HIGH_MIN = 8
RISK_LEVEL_MEDIUM_MIN = 4

# risk_score.scale에 넣는 고정 문자열. risk_scorer가 0.0~1.0으로 정규화한 값을
# 100배 해서 total로 쓴다(NORMALIZATION_CAP이 100.0이라 사실상 raw 점수 복원).
RISK_SCORE_SCALE = "0-100"

# 통합 스키마에 자리가 없지만 버리기 아까운 필드들. 3-5절 참고.
# JSON Schema draft-07은 additionalProperties를 막지 않으므로 이대로 실어도
# 스키마 검증은 통과한다. A의 통합 스펙이 확정되면 위치를 옮길 수 있다.
PASSTHROUGH_FIELDS = ("certificate", "code_analysis", "strings", "third_party_sdks")

_COMPONENT_LIST_TYPES = (
    ("activities", "activity"),
    ("services", "service"),
    ("receivers", "receiver"),
    ("providers", "provider"),
)


def permission_risk_level(permission: str) -> str:
    """권한 이름 -> "high" | "medium" | "low".

    PERMISSION_WEIGHTS에 없는 권한은 가중치 0으로 취급돼 전부 low가 된다.
    현재 이 표에는 권한이 5개뿐이라 CAMERA, RECORD_AUDIO, READ_CONTACTS 같은
    실제 위험 권한도 low로 떨어진다 — 표 확장은 risk_scorer(D 담당)의 점수를
    바꾸는 일이라 D와 함께 정하기로 하고 보류 중이다.
    """
    weight = PERMISSION_WEIGHTS.get(permission, 0)
    if weight >= RISK_LEVEL_HIGH_MIN:
        return "high"
    if weight >= RISK_LEVEL_MEDIUM_MIN:
        return "medium"
    return "low"


def _build_permissions(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """문자열 목록인 manifest["permissions"]를 스키마의 객체 배열로 감싼다."""
    permissions = []
    for name in manifest.get("permissions") or []:
        entry: dict[str, Any] = {"name": name, "risk_level": permission_risk_level(name)}
        # abuse_example은 스키마상 optional이라, 설명이 없는 권한은 키를 아예 빼서
        # "설명이 비어있음"과 "설명이 아직 없음"을 구분한다.
        abuse_example = ABUSE_EXAMPLES.get(name)
        if abuse_example:
            entry["abuse_example"] = abuse_example
        permissions.append(entry)
    return permissions


def _rebuild_components(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """구버전 parse_manifest 출력(components 필드가 없는 경우) 복원용 폴백.

    4개 리스트에서 type을, exported_components 대조로 exported를 되살린다.
    intent_filters는 원본 파싱 단계에서 버려졌으므로 복원이 불가능해 빈 배열이 된다.
    같은 이름이 여러 종류로 중복 등록돼 있으면 exported 판정이 섞일 수 있다.
    """
    exported_names = set(manifest.get("exported_components") or [])
    components = []
    for list_field, component_type in _COMPONENT_LIST_TYPES:
        for name in manifest.get(list_field) or []:
            components.append(
                {
                    "type": component_type,
                    "name": name,
                    "exported": name in exported_names,
                    "intent_filters": [],
                }
            )
    return components


def _build_components(manifest: dict[str, Any], warnings: list[str]) -> list[dict[str, Any]]:
    components = manifest.get("components")
    if components is None:
        warnings.append(
            "manifest에 components 필드가 없어 기존 4개 리스트로 복원함 "
            "(intent_filters는 복원 불가 — 빈 배열로 채움)"
        )
        return _rebuild_components(manifest)

    # 스키마 필드만 남긴다 — 원본에 다른 키가 붙어도 통합 리포트가 흔들리지 않도록.
    return [
        {
            "type": c.get("type"),
            "name": c.get("name"),
            "exported": bool(c.get("exported")),
            "intent_filters": list(c.get("intent_filters") or []),
        }
        for c in components
    ]


def _build_meta(
    meta: dict[str, Any], apk_path: str | Path | None, warnings: list[str]
) -> dict[str, Any]:
    apk_name = meta.get("apk_name")
    if not apk_name and apk_path is not None:
        apk_name = Path(apk_path).name
    if not apk_name:
        warnings.append("meta.apk_name이 없어 빈 문자열로 채움 (스키마 required 필드)")
        apk_name = ""

    analyzed_at = meta.get("analyzed_at")
    if not analyzed_at:
        # 여기서 만든 값은 "분석 시각"이 아니라 "변환 시각"이라 정확하지 않다.
        # 그래서 경고로 남긴다 — 정상 경로에서는 analyzer가 미리 채워준다.
        analyzed_at = datetime.now(timezone.utc).isoformat()
        warnings.append(
            "meta.analyzed_at이 없어 변환 시점 시각으로 대체함 (실제 분석 시각과 다를 수 있음)"
        )

    built: dict[str, Any] = {
        "apk_name": apk_name,
        "package_name": meta.get("package_name") or "",
        "analyzed_at": analyzed_at,
        "sha256": (meta.get("file_hash") or {}).get("sha256", ""),
    }

    # min_sdk / target_sdk는 스키마상 optional이지만 넣을 거면 integer여야 한다
    # (null 불가). 값이 없으면 None을 넣지 말고 키 자체를 빼야 검증을 통과한다.
    #
    # 참고: apk_extractor의 _safe_int()는 파싱 실패 시 0을 넣기 때문에, 여기까지
    # 0으로 도착한 값은 "SDK 0"이 아니라 "파싱 실패"일 수 있다. 그대로 통과시킬지
    # 구분할지는 A의 통합 스펙에서 정하기로 하고 지금은 손대지 않는다.
    for field in ("min_sdk", "target_sdk"):
        value = meta.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            built[field] = value

    return built


def _build_risk_score(raw: Any, warnings: list[str]) -> dict[str, Any]:
    """float(0.0~1.0) -> 스키마의 risk_score 객체.

    breakdown(점수 계산 근거)은 일부러 만들지 않는다. 어댑터가 접근할 수 있는 건
    권한 가중치뿐인데 실제 raw 점수에는 exported 컴포넌트/의심 API/난독화/리플렉션/
    동적 로딩/의심 문자열도 함께 들어가서, 권한만 재현하면 breakdown 합계가 total과
    맞지 않는다. "근거"의 합이 총점과 다르면 오히려 혼란스러우므로 D(risk_scorer 담당)가
    calculate_risk()에서 근거를 반환해 주면 그때 연결한다.
    """
    if not isinstance(raw, (int, float)) or isinstance(raw, bool):
        # 스키마에서 risk_score.total은 required + number라 null을 넣을 수 없다.
        # 0.0으로 채우되, 그대로 두면 "안전한 앱"으로 오해되므로 반드시 경고를 남긴다.
        warnings.append(
            "risk_score 계산이 실패해 total=0.0으로 처리함 (안전하다는 뜻이 아님)"
        )
        return {"total": 0.0, "scale": RISK_SCORE_SCALE}

    return {"total": round(float(raw) * 100, 1), "scale": RISK_SCORE_SCALE}


def to_static_report(
    result: dict[str, Any],
    apk_path: str | Path | None = None,
    include_extra: bool = True,
) -> dict[str, Any]:
    """analyze_static()의 결과 dict를 static_report.json 형태로 변환한다.

    Args:
        result: analyze_static()의 반환값 (또는 그걸 저장한 JSON을 읽은 dict)
        apk_path: meta.apk_name이 없는 구버전 결과를 위한 보조 입력. 정상 경로에서는
            apk_extractor가 meta.apk_name을 채우므로 넘기지 않아도 된다.
        include_extra: 통합 스키마에 자리가 없는 certificate/code_analysis/strings/
            third_party_sdks를 함께 실을지 여부. 스키마만 남긴 순수 출력이 필요하면 False.

    Returns:
        schemas/static_report.schema.json을 만족하는 dict.
        errors에는 원본 result["errors"]에 어댑터가 발견한 문제(변환 중 채워 넣은
        값, 복원 불가 필드 등)를 이어 붙인다.
    """
    warnings: list[str] = []
    meta = result.get("meta") or {}
    manifest = result.get("manifest")

    if manifest is None:
        # analyze_static()의 부분 실패 정책(예외 대신 계속 진행)을 어댑터도 그대로 따른다.
        # 어댑터만 예외를 던지면 모듈 전체의 정책이 어긋난다. A의 통합 스펙에서
        # 다른 정책이 확정되면 이 부분을 바꾼다.
        warnings.append(
            "manifest 파싱 실패로 permissions/components를 빈 배열로 처리함"
        )
        manifest = {}

    report: dict[str, Any] = {
        "meta": _build_meta(meta, apk_path, warnings),
        "permissions": _build_permissions(manifest),
        "components": _build_components(manifest, warnings),
        "risk_score": _build_risk_score(result.get("risk_score"), warnings),
    }

    if include_extra:
        for field in PASSTHROUGH_FIELDS:
            report[field] = result.get(field)

    # errors는 통합에서 특히 중요하다 — 정적 분석은 부분 실패를 예외로 알리지 않기
    # 때문에, 이 리스트가 비어있는지 여부가 오케스트레이터(A)의 유일한 판단 근거다.
    report["errors"] = list(result.get("errors") or []) + warnings

    return report
