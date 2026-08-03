"""network_analyzer/network_scorer.py (D 작성, 6주차 - 종합 위험도 점수 중 네트워크 부분)

network_report(NetworkAnalysisResult)의 suspicious 항목들을 가중치 합산해서
0.0~1.0 네트워크 위험도 점수로 변환한다. static_analyzer.risk_scorer와 같은 설계
(가중치 합산 + NORMALIZATION_CAP 정규화 + breakdown 근거 반환)를 그대로 따라서,
main.py 오케스트레이터가 정적/동적/네트워크 세 점수를 같은 패턴으로 다룰 수 있게 했다.

1차 버전 - static_analyzer.risk_scorer와 마찬가지로 실제 정상/악성 샘플 트래픽으로
검증 안 된 휴리스틱이다. 특히 아래 SUSPICIOUS_IP_WEIGHT는 ip_checker.py의 알려진
오탐(정상 앱도 공인 IP면 전부 잡힘, 실캡처 검증 때 정상 Calendar 앱에서 17건 나왔음)을
고려해서 의도적으로 낮게 잡은 값이다.
"""

from __future__ import annotations

from typing import Any

from .ip_checker import is_ip_literal
from .schema import NetworkAnalysisResult

# raw 점수를 이 값으로 나눠서 0.0~1.0으로 clamp한다. static_analyzer.risk_scorer의
# NORMALIZATION_CAP(100.0)과 같은 스케일로 맞췄다 - main.py가 세 점수를 가중치로
# 합칠 때 스케일이 다르면 비교가 왜곡되기 때문.
NORMALIZATION_CAP = 100.0

# suspicious.domains 중 도메인 필드가 아예 IP 리터럴인 경우 - DNS 조회 없이 코드에
# IP를 하드코딩해서 바로 접속했다는 뜻. 도메인 기반 차단(화이트리스트/블랙리스트)을
# 우회하려는 전형적인 C&C 패턴이라 강한 신호로 취급한다.
HARDCODED_IP_DOMAIN_WEIGHT = 20

# suspicious.domains 중 화이트리스트에 없는 일반 도메인. 화이트리스트가 ~35개짜리
# 1차 목록이라 놓친 정상 도메인일 가능성도 있어 IP 리터럴보다 약하게 잡는다.
UNLISTED_DOMAIN_WEIGHT = 8

# suspicious.ips는 ip_checker.find_suspicious_ips()가 "공인 IP면 전부 의심"이라는
# 노이즈 많은 1차 규칙으로 뽑은 것 (자체 docstring에 "오탐이 많을 수 있는 1차 버전"
# 이라고 명시돼있음). 정상 DNS 조회로 얻은 공인 IP까지 전부 여기 섞여 있어서 개당
# 가중치를 낮게 잡아야 정상 앱 점수가 안 부풀려진다.
SUSPICIOUS_IP_WEIGHT = 1


def _score_breakdown(network_report: NetworkAnalysisResult) -> list[dict[str, Any]]:
    """항목별 raw 기여도 목록. 이 weight들의 합이 곧 raw 총점이다.

    calculate_network_risk()와 calculate_network_risk_with_breakdown()이 이 함수
    하나를 공유해서 점수 계산에 실제로 쓰인 것과 breakdown에 보여주는 게 항상
    일치하게 한다 (static_analyzer.risk_scorer._score_breakdown()과 동일한 이유).
    """
    breakdown: list[dict[str, Any]] = []
    suspicious = network_report.get("suspicious") or {}

    for entry in suspicious.get("domains", []):
        domain = entry["domain"]
        if is_ip_literal(domain):
            breakdown.append(
                {"factor": f"하드코딩된 IP 도메인: {domain}", "weight": HARDCODED_IP_DOMAIN_WEIGHT}
            )
        else:
            breakdown.append(
                {"factor": f"미화이트리스트 도메인: {domain}", "weight": UNLISTED_DOMAIN_WEIGHT}
            )

    for entry in suspicious.get("ips", []):
        breakdown.append({"factor": f"의심 IP: {entry['ip']}", "weight": SUSPICIOUS_IP_WEIGHT})

    return breakdown


def calculate_network_risk(network_report: NetworkAnalysisResult) -> float:
    """network_report -> 0.0~1.0 네트워크 위험도 점수.

    static_analyzer.risk_scorer.calculate_risk()와 같은 이름 규칙(calculate_*_risk) -
    main.py가 세 모듈을 동일한 패턴으로 호출할 수 있게 맞췄다.
    """
    raw = sum(item["weight"] for item in _score_breakdown(network_report))
    return min(raw / NORMALIZATION_CAP, 1.0)


def calculate_network_risk_with_breakdown(network_report: NetworkAnalysisResult) -> dict:
    """근거(breakdown) 포함 버전.

    {"total": 0.0~1.0 (calculate_network_risk()와 동일값), "raw": 정규화 전 합산 점수,
     "breakdown": [{"factor": str, "weight": number}, ...]}

    static_analyzer.risk_scorer.calculate_risk_with_breakdown()과 반환 형태를
    동일하게 맞췄다 - main.py가 두 모듈 결과를 같은 방식으로 다룰 수 있게.
    """
    breakdown = _score_breakdown(network_report)
    raw = sum(item["weight"] for item in breakdown)
    return {"total": min(raw / NORMALIZATION_CAP, 1.0), "raw": raw, "breakdown": breakdown}


if __name__ == "__main__":
    import json

    # 정상 앱(Calendar) 실캡처 검증 때 나온 실제 결과 재현 - suspicious.domains 0건,
    # suspicious.ips 17건(ip_checker 1차 규칙 노이즈). 정상 앱이니 낮은 점수가 나와야
    # 정상이다.
    normal_app_report: NetworkAnalysisResult = {
        "meta": {
            "package_name": "com.google.android.calendar",
            "capture_started_at": "2026-08-02T18:34:17+00:00",
            "capture_duration_sec": 40,
            "pcap_file": "output/capture.pcap",
        },
        "dns_queries": [],
        "tls_sni": [],
        "suspicious": {
            "domains": [],
            "ips": [{"ip": f"142.251.15{i}.119", "reason": "공인 IP"} for i in range(17)],
        },
    }

    # C&C 후보 시나리오 - 화이트리스트 미포함 도메인 1개 + IP 하드코딩 도메인 1개
    suspicious_app_report: NetworkAnalysisResult = {
        "meta": normal_app_report["meta"],
        "dns_queries": [],
        "tls_sni": [],
        "suspicious": {
            "domains": [
                {"domain": "evil-c2.example.net", "reason": "화이트리스트 미포함"},
                {"domain": "1.2.3.4", "reason": "하드코딩된 형태"},
            ],
            "ips": [{"ip": "1.2.3.4", "reason": "공인 IP"}],
        },
    }

    for label, report in [("정상 앱(Calendar)", normal_app_report), ("의심 앱(C2 후보 포함)", suspicious_app_report)]:
        result = calculate_network_risk_with_breakdown(report)
        print(f"=== {label} ===")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        print()
