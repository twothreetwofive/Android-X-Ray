"""정적 분석 오케스트레이터. (A 설계, 3주차 과제2)

오케스트레이터(추후 main.py)는 이 모듈의 analyze_static() 하나만 import해서 쓴다.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .apk_extractor import extract_apk
from .cert_analyzer import analyze_cert
from .code_scanner import scan_code
from .manifest_parser import parse_manifest
from .risk_scorer import calculate_risk_with_breakdown
from .sdk_detector import detect_sdks
from .string_extractor import extract_strings


def analyze_static(apk_path: str, work_dir: str | Path = "work") -> dict:
    """APK 정적 분석 수행.

    Args:
        apk_path: 분석 대상 .apk 파일 경로
        work_dir: apktool/jadx 디컴파일 결과물을 풀어둘 작업 폴더

    Returns:
        schema.StaticAnalysisResult 형태의 dict.

    Raises:
        FileNotFoundError: apk_path가 존재하지 않을 때
        StaticAnalysisError: apktool/jadx 실행 실패 등 치명적 에러
        (그 외 하위 모듈의 부분 실패는 예외 대신 result["errors"]에 누적하고 계속 진행)
    """
    errors: list[str] = []

    # 분석 시작 시각. 나중에 리포트를 변환하는 시점이 아니라 "실제로 분석한 시점"이어야
    # 의미가 있어서 여기서 찍는다 (네트워크 모듈의 capture_started_at과 같은 방식).
    analyzed_at = datetime.now(timezone.utc).isoformat()

    # 1. 치명적 실패(apk 파일 자체가 없거나 androguard 파싱 불가)만 위로 전파된다.
    #    apktool/jadx 디컴파일 실패는 더 이상 치명적이지 않다 — meta(package_name)는
    #    androguard로 이미 확보되므로, 디컴파일이 실패해도 뒤 단계(동적/네트워크)까지
    #    돌 수 있게 extract_apk가 None + decompile_warnings로 알려주고 계속 진행한다.
    extracted = extract_apk(apk_path, work_dir)
    errors.extend(extracted.get("decompile_warnings", []))

    # 2. 나머지는 하나가 실패해도 나머지는 계속 진행 (부분 실패 -> errors 누적)
    manifest_data = _run_stage(errors, "manifest 파싱", parse_manifest, apk_path)
    cert_data = _run_stage(errors, "인증서 분석", analyze_cert, extracted)
    code_data = _run_stage(errors, "코드 스캔", scan_code, extracted)
    strings_data = _run_stage(errors, "문자열 추출", extract_strings, extracted)
    sdks = _run_stage(errors, "SDK 탐지", detect_sdks, extracted)

    # calculate_risk()가 아니라 calculate_risk_with_breakdown()을 쓴다 — 점수와 함께
    # "왜 그 점수가 나왔는지"(항목별 기여도)를 같이 받기 위해서다. 두 함수는 내부적으로
    # 같은 _score_breakdown()을 공유하므로 total 값은 calculate_risk()와 항상 동일하다.
    risk = _run_stage(
        errors, "위험도 계산", calculate_risk_with_breakdown,
        manifest_data, code_data, strings_data, cert_data,
    )

    return {
        "meta": {**extracted["meta"], "analyzed_at": analyzed_at},
        "manifest": manifest_data,
        "certificate": cert_data,
        "code_analysis": code_data,
        "strings": strings_data,
        "third_party_sdks": sdks,
        # risk_score는 기존대로 float(0.0~1.0)을 유지한다. schema.py의 팀 계약이고
        # main.py(A)가 8필드를 변환 없이 통과시키는 정책이라 타입을 바꾸면 그쪽이 깨진다.
        "risk_score": risk["total"] if risk else None,
        # 근거는 형제 필드로 따로 뺐다. 계산 실패 시 risk_score와 함께 None이 되므로
        # "점수는 있는데 근거만 없는" 어긋난 상태가 생기지 않는다.
        "risk_breakdown": risk,
        "errors": errors,
    }


def _run_stage(errors: list[str], label: str, func, *args):
    try:
        return func(*args)
    except Exception as e:  # noqa: BLE001 - 부분 실패는 죽이지 않고 기록만 함
        errors.append(f"{label} 실패: {e}")
        return None
