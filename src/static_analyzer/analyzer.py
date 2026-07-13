"""정적 분석 오케스트레이터. (A 설계, 3주차 과제2)

오케스트레이터(추후 main.py)는 이 모듈의 analyze_static() 하나만 import해서 쓴다.
"""

from __future__ import annotations

from pathlib import Path

from .apk_extractor import extract_apk
from .cert_analyzer import analyze_cert
from .code_scanner import scan_code
from .manifest_parser import parse_manifest
from .risk_scorer import calculate_risk
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

    # 1. 치명적 실패(apk 없음, apktool/jadx 실패)는 여기서 그대로 위로 전파시킴 —
    #    디컴파일 자체가 안 되면 뒤 단계를 계속 진행할 의미가 없음.
    extracted = extract_apk(apk_path, work_dir)

    # 2. 나머지는 하나가 실패해도 나머지는 계속 진행 (부분 실패 -> errors 누적)
    manifest_data = _run_stage(errors, "manifest 파싱", parse_manifest, apk_path)
    cert_data = _run_stage(errors, "인증서 분석", analyze_cert, extracted)
    code_data = _run_stage(errors, "코드 스캔", scan_code, extracted)
    strings_data = _run_stage(errors, "문자열 추출", extract_strings, extracted)
    sdks = _run_stage(errors, "SDK 탐지", detect_sdks, extracted)
    risk = _run_stage(errors, "위험도 계산", calculate_risk, manifest_data, code_data, strings_data)

    return {
        "meta": extracted["meta"],
        "manifest": manifest_data,
        "certificate": cert_data,
        "code_analysis": code_data,
        "strings": strings_data,
        "third_party_sdks": sdks,
        "risk_score": risk,
        "errors": errors,
    }


def _run_stage(errors: list[str], label: str, func, *args):
    try:
        return func(*args)
    except Exception as e:  # noqa: BLE001 - 부분 실패는 죽이지 않고 기록만 함
        errors.append(f"{label} 실패: {e}")
        return None
