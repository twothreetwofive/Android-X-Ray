"""risk_aggregator.py — 정적/동적/네트워크 결과를 하나로 합쳐 종합 위험도를 매긴다.
(역할4 담당 자리. main.py Day2 골격의 `risk_score` 플레이스홀더를 실제로 채우는 모듈)

설계 개요
---------
세 모듈은 이미 각자 "위험 신호"를 뽑아둔 상태다:
  - 정적(static_analyzer): risk_scorer가 권한/코드/문자열/인증서를 합산해 0.0~1.0
    정규화 점수(`data["risk_score"]`)와 근거(`data["risk_breakdown"]`)를 이미 만든다.
  - 동적(dynamic_analyzer): 런타임에 후킹된 이벤트(events)와, 암호화 뒤에 숨어있다
    실행 중 드러난 평문(plaintext_candidates)을 준다.
  - 네트워크(network_analyzer): 화이트리스트/IP 검사를 통과 못 한 "이미 의심으로
    판별된" 도메인/IP(`data["suspicious"]`)를 준다.

그래서 이 모듈이 새로 무거운 판별을 다시 하지는 않는다. 각 모듈의 신호를 0.0~1.0
하위 점수(sub-score)로 환산한 뒤, 모듈 가중치로 가중평균해서 종합 total(0.0~1.0)과
등급(level)을 낸다.

가중치/상한(CAP)/등급 임계값은 전부 아래 상수로 빼뒀다. risk_scorer.py와 마찬가지로
정상 앱 2~3개 vs 공개 악성 샘플(Anubis 계열) 2~3개로 실제 돌려보고 점수가 유의미하게
갈리는지 확인한 뒤 다시 맞춰야 하는 휴리스틱 초기값이다.

한 모듈이 실패/타임아웃이면(부분 리포트) 그 모듈은 빼고 남은 모듈끼리 가중치를
재정규화한다 — 예: 네트워크가 죽으면 static 0.4/dynamic 0.3 → static 0.57/dynamic 0.43로
다시 나눠서 total은 항상 0.0~1.0을 유지한다. 세 모듈이 다 못 쓰면 total=None,
level="unknown"으로 둔다(점수를 0.0으로 강제해서 "안전함"으로 오해되지 않게).

입력은 main.py가 조립한 report["modules"] dict를 그대로 받는다. 각 모듈 항목은
{"status": "ok"|"partial"|"failed"|"timeout", "data": {...}, "error": ...} 형태다.
"""

from __future__ import annotations

from typing import Any, Optional

# ── 모듈 가중치 (합 1.0) ──
# 정적 분석이 가장 안정적으로(에뮬레이터/디바이스 없이도) 나오고 신호도 풍부해서 조금
# 더 준다. 동적/네트워크는 실행 환경에 따라 아예 빈 결과가 나올 수 있어 동률로 뒀다.
MODULE_WEIGHTS = {
    "static": 0.4,
    "dynamic": 0.3,
    "network": 0.3,
}

# ── 동적 하위 점수 산정 ──
# hook_type별 raw 가중치. 실행 중 "무언가를 복호화/디코딩했다"는 것 자체가 정적으로는
# 안 보이던 은닉 동작이라 신호로 본다. 평문 후보가 가장 강한 신호(암호화 뒤에 숨겼던
# 실제 값이 드러난 것).
DYNAMIC_PLAINTEXT_WEIGHT = 8      # plaintext_candidates 1건당
DYNAMIC_HOOK_WEIGHTS = {
    "cipher": 5,                  # Cipher.doFinal 등 — 런타임 암복호화
    "custom_xor": 5,             # 자체 XOR 난독화 패턴
    "base64": 2,                 # base64 인코딩/디코딩
    "string_builder": 1,        # 문자열 동적 조립(약한 신호, 정상 앱도 흔함)
}
DYNAMIC_CAP = 50.0               # 이 raw 합을 1.0으로 본다

# ── 네트워크 하위 점수 산정 ──
# suspicious는 D의 화이트리스트/IP 검사를 이미 통과 못 한 "판별 완료된 의심"이라
# 건당 가중치를 세게 준다. C&C 후보 도메인 2~3개면 네트워크 하위 점수가 확 오르게.
NETWORK_SUSPICIOUS_DOMAIN_WEIGHT = 15   # suspicious.domains 1건당
NETWORK_SUSPICIOUS_IP_WEIGHT = 15       # suspicious.ips 1건당
NETWORK_CAP = 60.0

# ── 등급 임계값 (total 기준) ──
LEVEL_THRESHOLDS = [
    (0.34, "low"),
    (0.67, "medium"),
    # 그 이상은 "high"
]


def _usable(module_entry: Optional[dict]) -> Optional[dict]:
    """모듈 항목이 점수 계산에 쓸 수 있으면 data를 반환, 아니면 None.

    status가 failed/timeout이거나 data가 없으면 쓸 수 없다. partial은 일부만
    채워졌어도 있는 신호는 반영하는 게 낫다고 보고 통과시킨다(부분 리포트 정책).
    """
    if not module_entry:
        return None
    if module_entry.get("status") in ("failed", "timeout"):
        return None
    return module_entry.get("data")


def _static_subscore(data: dict) -> Optional[tuple[float, dict]]:
    """정적 하위 점수. risk_scorer가 이미 0.0~1.0으로 정규화한 값을 그대로 쓴다.

    risk_score가 None이면(위험도 계산 stage가 부분 실패한 경우) 하위 점수를 못
    내므로 None을 반환해 이 모듈을 빼도록 한다.
    """
    score = data.get("risk_score")
    if score is None:
        return None
    detail = {
        "sub_score": round(float(score), 4),
        # 근거는 정적 모듈이 만든 breakdown을 그대로 인용만 한다(중복 계산 안 함).
        "source": "static_analyzer.risk_score",
        "static_breakdown": data.get("risk_breakdown"),
    }
    return float(score), detail


def _dynamic_subscore(data: dict) -> Optional[tuple[float, dict]]:
    """동적 하위 점수. 평문 후보 수 + hook_type별 이벤트 수를 raw로 합산 후 CAP으로 정규화."""
    plaintext = data.get("plaintext_candidates") or []
    events = data.get("events") or []

    hook_counts: dict[str, int] = {}
    for ev in events:
        htype = ev.get("hook_type", "unknown")
        hook_counts[htype] = hook_counts.get(htype, 0) + 1

    raw = len(plaintext) * DYNAMIC_PLAINTEXT_WEIGHT
    for htype, count in hook_counts.items():
        raw += count * DYNAMIC_HOOK_WEIGHTS.get(htype, 0)

    sub = min(raw / DYNAMIC_CAP, 1.0)
    detail = {
        "sub_score": round(sub, 4),
        "raw": raw,
        "plaintext_candidate_count": len(plaintext),
        "hook_counts": hook_counts,
    }
    return sub, detail


def _network_subscore(data: dict) -> Optional[tuple[float, dict]]:
    """네트워크 하위 점수. 이미 의심으로 판별된 도메인/IP 개수를 raw로 합산 후 정규화."""
    suspicious = data.get("suspicious") or {}
    n_domains = len(suspicious.get("domains") or [])
    n_ips = len(suspicious.get("ips") or [])

    raw = n_domains * NETWORK_SUSPICIOUS_DOMAIN_WEIGHT + n_ips * NETWORK_SUSPICIOUS_IP_WEIGHT
    sub = min(raw / NETWORK_CAP, 1.0)
    detail = {
        "sub_score": round(sub, 4),
        "raw": raw,
        "suspicious_domain_count": n_domains,
        "suspicious_ip_count": n_ips,
    }
    return sub, detail


_SUBSCORERS = {
    "static": _static_subscore,
    "dynamic": _dynamic_subscore,
    "network": _network_subscore,
}


def _level_for(total: Optional[float]) -> str:
    if total is None:
        return "unknown"
    for threshold, name in LEVEL_THRESHOLDS:
        if total < threshold:
            return name
    return "high"


def aggregate_risk(modules: dict[str, Any]) -> dict:
    """세 모듈 결과(report["modules"])를 받아 종합 위험도를 계산한다.

    Returns:
        {
          "total": float(0.0~1.0) | None,   # 쓸 수 있는 모듈이 하나도 없으면 None
          "level": "low"|"medium"|"high"|"unknown",
          "breakdown": {
            "modules": {                     # 모듈별 하위 점수와 근거
              "static":  {"available": bool, "weight": float, ...detail} , ...
            },
            "weights_applied": {...},        # 재정규화 후 실제 적용된 가중치
            "unavailable": [모듈명, ...],    # 실패/타임아웃 등으로 빠진 모듈
          },
        }

    total은 (하위점수 × 재정규화 가중치)의 합이다. 예외를 던지지 않고 항상 dict를
    반환한다 — main.py의 부분 리포트 허용 정책과 맞춘다.
    """
    module_details: dict[str, dict] = {}
    unavailable: list[str] = []
    # 쓸 수 있는 모듈만: {name: (sub_score, base_weight)}
    usable: dict[str, tuple[float, float]] = {}

    for name in ("static", "dynamic", "network"):
        data = _usable(modules.get(name))
        base_weight = MODULE_WEIGHTS[name]
        if data is None:
            module_details[name] = {"available": False, "weight": 0.0}
            unavailable.append(name)
            continue

        result = _SUBSCORERS[name](data)
        if result is None:
            # data는 있는데 하위 점수를 못 낸 경우(예: 정적 risk_score가 None)
            module_details[name] = {"available": False, "weight": 0.0}
            unavailable.append(name)
            continue

        sub, detail = result
        usable[name] = (sub, base_weight)
        module_details[name] = {"available": True, **detail}

    if not usable:
        return {
            "total": None,
            "level": "unknown",
            "breakdown": {
                "modules": module_details,
                "weights_applied": {},
                "unavailable": unavailable,
            },
        }

    # 남은 모듈끼리 가중치 재정규화(합이 1.0이 되도록)
    weight_sum = sum(w for _, w in usable.values())
    weights_applied: dict[str, float] = {}
    total = 0.0
    for name, (sub, base_weight) in usable.items():
        applied = base_weight / weight_sum
        weights_applied[name] = round(applied, 4)
        module_details[name]["weight"] = round(applied, 4)
        total += sub * applied

    total = round(min(total, 1.0), 4)

    return {
        "total": total,
        "level": _level_for(total),
        "breakdown": {
            "modules": module_details,
            "weights_applied": weights_applied,
            "unavailable": unavailable,
        },
    }
