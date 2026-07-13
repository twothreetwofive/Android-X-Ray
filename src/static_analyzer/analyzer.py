"""정적 분석 오케스트레이터. (A 설계, 3주차 과제2)

오케스트레이터(추후 main.py)는 이 모듈의 analyze_static() 하나만 import해서 쓴다.
"""

from __future__ import annotations

from pathlib import Path

from .apk_extractor import extract_apk
from .manifest_parser import parse_manifest


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
        (부분 실패는 예외 대신 result["errors"]에 누적하고 계속 진행)

    Note:
        3주차 기준 A(구조 설계)/B(디컴파일 연동)/C(Manifest 파싱)만 구현됨.
        certificate/code_analysis/strings/third_party_sdks/risk_score는
        아직 담당 모듈(cert_analyzer/code_scanner/string_extractor/sdk_detector/
        risk_scorer)이 없어서 None으로 남겨두고 errors에 사유를 남긴다.
    """
    errors: list[str] = []

    extracted = extract_apk(apk_path, work_dir)

    try:
        manifest_data = parse_manifest(apk_path)
    except Exception as e:  # noqa: BLE001 - 부분 실패는 죽이지 않고 기록만 함
        errors.append(f"manifest 파싱 실패: {e}")
        manifest_data = None

    for pending in ("certificate", "code_analysis", "strings", "third_party_sdks", "risk_score"):
        errors.append(f"{pending}: 담당 모듈 미구현 (3주차 범위 밖)")

    return {
        "meta": extracted["meta"],
        "manifest": manifest_data,
        "certificate": None,
        "code_analysis": None,
        "strings": None,
        "third_party_sdks": None,
        "risk_score": None,
        "errors": errors,
    }
