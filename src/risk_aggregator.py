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
#
# 8주차 재조정 — **개수가 아니라 종류의 다양성을 본다.**
# 이전 상수(평문 8점/건, CAP 50)는 평문 후보 7건이면 동적 하위점수가 1.0으로
# 포화됐다. 실습용 취약 APK는 평문을 일부러 다루기 때문에 35건도 흔히 나오고,
# 그러면 "취약"과 "악성"이 점수에서 구분되지 않는다(8주차 계획수정 PDF 2항).
# 그래서 지표 종류마다 반영 개수 상한(MAX_COUNT)을 두고, 상한을 넘는 건수는
# 점수에 더 얹지 않는다. 같은 종류가 100건이어도 3종류가 겹치는 쪽이 더 위험하다.
DYNAMIC_PLAINTEXT_WEIGHT = 3      # plaintext_candidates 1건당
DYNAMIC_PLAINTEXT_MAX_COUNT = 10  # 이 이상은 점수에 추가 반영하지 않음
DYNAMIC_HOOK_WEIGHTS = {
    "cipher": 3,                  # Cipher.doFinal 등 — 런타임 암복호화
    "custom_xor": 3,              # 자체 XOR 난독화 패턴
    "base64": 1,                  # base64 인코딩/디코딩
    "string_builder": 0.2,        # 문자열 동적 조립(약한 신호, 정상 앱도 흔함)
    # 8주차 정보탈취 후킹. 개별 신호는 정상 앱도 흔하므로(연락처 읽기, 네트워크
    # 접속) 가중치를 낮게 준다 — 판별력은 "둘의 조합"(info_stealer_pattern, 아래
    # _dynamic_indicators)에서 강한 지표로 나온다. 여기서는 관측이 잡히게 하고
    # 소폭만 반영한다. network_send는 사실상 모든 앱이 해서 가장 낮게.
    "sensitive_read": 2,          # 민감정보 읽기(연락처/기기ID/위치 등)
    "network_send": 0.5,          # 외부 전송(URL/Socket 목적지)
}
DYNAMIC_HOOK_MAX_COUNTS = {
    "cipher": 10,
    "custom_xor": 10,
    "base64": 20,
    "string_builder": 50,
    "sensitive_read": 10,
    "network_send": 20,
}
DYNAMIC_CAP = 90.0               # 위 상한을 전부 채웠을 때의 합 = 1.0

# ── 네트워크 하위 점수 산정 ──
# suspicious는 D의 화이트리스트/IP 검사를 이미 통과 못 한 "판별 완료된 의심"이라
# 건당 가중치를 세게 준다. C&C 후보 도메인 2~3개면 네트워크 하위 점수가 확 오르게.
#
# 8주차 재조정 — IP 쪽 가중치를 도메인의 절반으로 낮췄다. ip_checker.py가 스스로
# 밝히듯 "공인 IP면 전부 의심"인 1차 규칙이라 CDN/클라우드 IP가 그대로 잡히는
# 오탐이 많다(모듈 docstring 참고). 반면 화이트리스트를 벗어난 도메인은 상대적으로
# 신호가 분명하다. 개수 상한을 두는 이유는 동적 쪽과 같다.
NETWORK_SUSPICIOUS_DOMAIN_WEIGHT = 12   # suspicious.domains 1건당
NETWORK_SUSPICIOUS_DOMAIN_MAX_COUNT = 4
NETWORK_SUSPICIOUS_IP_WEIGHT = 6        # suspicious.ips 1건당 (오탐 많아 도메인의 절반)
NETWORK_SUSPICIOUS_IP_MAX_COUNT = 4
NETWORK_CAP = 72.0                      # 4×12 + 4×6

# ── 보안 판정(Verdict) 구간 ── (8주차 계획수정 PDF 4항)
#
# 0~100 스케일 상한과 판정 코드. 7주차까지는 low/medium/high 3단계에 임계값이
# 0.34/0.67이었는데, 화면에서 "정상/실패"(분석 상태)와 "낮음/위험"(보안 판정)이
# 섞여 읽히는 문제가 있어 4단계로 다시 나눴다.
#   0–29 정상 / 30–59 주의 / 60–79 의심 / 80–100 고위험
# common.VERDICT_BAND_BOUNDS와 반드시 동일하게 유지할 것(게이지 구간색 = 실제 판정).
VERDICT_BANDS = [
    (30, "normal"),
    (60, "caution"),
    (80, "suspicious"),
    (101, "high_risk"),   # 100점 포함(상한 초과 방지용으로 101)
]

# ── "악성" 승격 규칙 ── (PDF 5항)
#
# 점수가 높다는 것만으로 "악성 APK"라고 화면에 쓰지 않는다. 실습용 취약 APK는
# 일부러 평문을 다루고 테스트 서버와 통신하기 때문에 점수가 쉽게 올라가는데,
# 그건 "취약"이지 "악성"이 아니다. 그래서 고위험 점수 **그리고** 서로 다른 강한
# 지표가 여러 개 동시에 충족될 때만 malicious로 승격한다.
MALICIOUS_MIN_SCORE100 = 80
MALICIOUS_MIN_STRONG_INDICATORS = 3

# 강한 지표 판정 기준값
#
# "강한 지표"는 **양성으로 설명하기 어려운 것**만 뽑는다. 취약 APK에서 흔히 나오는
# 신호(평문 후보, 화이트리스트 누락 도메인 1~2건)는 위험 지표로 표시는 하되 강한
# 지표로는 세지 않는다. 우리 화이트리스트는 스스로 불완전하다고 밝히고 있고
# (whitelist_checker.py), ip_checker.py도 "공인 IP면 전부 의심"인 1차 규칙이라
# 오탐이 섞인다. 그런 신호로 "악성"을 선언하면 근거가 안 된다.
STRONG_SUSPICIOUS_DOMAIN_MIN = 3    # 1~2건은 화이트리스트 누락일 수 있음
STRONG_SUSPICIOUS_IP_MIN = 3        # 오탐이 잦아 3건부터
STRONG_PERMISSION_GROUP_MIN = 2     # 아래 3개 권한군 중 2개 이상 동시 요구

# 뱅킹 트로이목마가 함께 요구하는 권한군. 하나만으로는 흔하지만 둘 이상 겹치면
# 문자 가로채기 + 화면 위조 + 자동 조작이 가능해진다(3~6월 Anubis 분석에서 확인).
PERMISSION_GROUPS: dict[str, tuple[str, ...]] = {
    "문자(SMS)": (
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
    ),
    "화면 덮어쓰기": (
        "android.permission.SYSTEM_ALERT_WINDOW",
    ),
    "접근성/자동조작": (
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
    ),
}


# ── "관측 없음"은 "위험 없음"이 아니다 ── (8주차)
#
# 이 저장소는 같은 원칙을 이미 세 곳에서 지키고 있다:
#   - static_data.py: 점수가 없을 때 0으로 채우지 않는다("위험도 0 = 안전"으로 읽힘)
#   - risk_view._render_unknown(): 빈 게이지·0점을 그리지 않고 "판정 불가"로 표시
#   - aggregate_risk(): 실패한 모듈은 0점이 아니라 **제외 후 가중치 재정규화**
# 그런데 "모듈이 정상 실행됐지만 아무것도 관측되지 않은" 경우만 예외적으로
# 하위점수 0.0으로 계산되어, 사실상 "이 축에서는 안전함"으로 취급되고 있었다.
#
# 실측 근거(8주차): 내장 앱 2종과 드로퍼 1종 모두 앱 트래픽이 한 건도 안 잡혔다.
# 캡처는 성공했으므로 status는 "ok"지만, 네트워크 위험도 0점이 종합 점수의 30%를
# 그대로 끌어내렸다. 특히 사용자가 화면을 누르기 전까지 아무 동작도 하지 않는
# 휴면형 드로퍼는 이 때문에 정상 앱보다 낮은 점수를 받았다.
#
# 실패 모듈과 똑같이 **제외 + 재정규화**로 처리한다. 화면에는 "분석 실패"와 구분해
# "관측된 데이터 없음"으로 표시한다 — 분석은 성공했고, 다만 근거가 없는 것이다.
def _observation_count(name: str, data: dict) -> Optional[int]:
    """이 모듈이 실제로 관측한 것의 개수. None이면 개수 개념이 없는 모듈(정적)."""
    if name == "dynamic":
        # 평문 후보는 events에서 파생되지만, 필터 구성에 따라 한쪽만 남을 수 있어
        # 둘을 합쳐 센다. "무엇이든 하나라도 관측됐는가"를 보는 것이 목적이다.
        return len(data.get("events") or []) + len(data.get("plaintext_candidates") or [])
    if name == "network":
        return len((data.get("dns_queries") or [])) + len((data.get("tls_sni") or []))
    # 정적 분석은 APK 파일 자체가 입력이라 "관측 없음" 상태가 없다.
    return None


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

    # 종류별 반영 개수 상한(MAX_COUNT)을 적용한다 — 파일 상단 상수 주석 참고.
    raw = min(len(plaintext), DYNAMIC_PLAINTEXT_MAX_COUNT) * DYNAMIC_PLAINTEXT_WEIGHT
    for htype, count in hook_counts.items():
        weight = DYNAMIC_HOOK_WEIGHTS.get(htype, 0)
        if not weight:
            continue
        capped = min(count, DYNAMIC_HOOK_MAX_COUNTS.get(htype, count))
        raw += capped * weight

    sub = min(raw / DYNAMIC_CAP, 1.0)
    detail = {
        "sub_score": round(sub, 4),
        "raw": round(raw, 2),
        "plaintext_candidate_count": len(plaintext),
        "hook_counts": hook_counts,
    }
    return sub, detail


def _network_subscore(data: dict) -> Optional[tuple[float, dict]]:
    """네트워크 하위 점수. 이미 의심으로 판별된 도메인/IP 개수를 raw로 합산 후 정규화."""
    suspicious = data.get("suspicious") or {}
    n_domains = len(suspicious.get("domains") or [])
    n_ips = len(suspicious.get("ips") or [])

    raw = (
        min(n_domains, NETWORK_SUSPICIOUS_DOMAIN_MAX_COUNT) * NETWORK_SUSPICIOUS_DOMAIN_WEIGHT
        + min(n_ips, NETWORK_SUSPICIOUS_IP_MAX_COUNT) * NETWORK_SUSPICIOUS_IP_WEIGHT
    )
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


# ────────────────────────────────────────────────────────────
# 위험 지표(indicator) 추출 — "무엇이 발견됐는가"
# ────────────────────────────────────────────────────────────
#
# 점수와 별개로, 화면·리포트에 그대로 나열할 관찰 사실을 모은다. PDF 3항이
# 요구하는 "분석이 성공했는가?"와 "무엇이 발견됐는가?"의 분리에서 뒤쪽을 담당한다.
# strong=True인 항목만 악성 승격 판단에 쓰인다.


def _ind(code: str, label: str, value: Any, strong: bool = False) -> dict:
    return {"code": code, "label": label, "value": value, "strong": strong}


def _static_indicators(data: dict) -> list[dict]:
    out: list[dict] = []
    manifest = data.get("manifest") or {}
    code = data.get("code_analysis") or {}
    strings = data.get("strings") or {}
    cert = data.get("certificate") or {}

    dangerous = manifest.get("dangerous_permissions") or []
    if dangerous:
        out.append(_ind("dangerous_permissions", "위험 권한", f"{len(dangerous)}건"))

    # 권한군 조합 — 개별 권한보다 조합이 신호다.
    perms = set(manifest.get("permissions") or [])
    matched = [g for g, names in PERMISSION_GROUPS.items() if perms & set(names)]
    if len(matched) >= STRONG_PERMISSION_GROUP_MIN:
        out.append(_ind("permission_combo", "고위험 권한 조합",
                        " + ".join(matched), strong=True))
    elif matched:
        out.append(_ind("permission_combo", "주목 권한군", " + ".join(matched)))

    # 패킹된 페이로드: APK 대부분이 정체 불명의 암호화 덩어리라는 것은 양성으로
    # 설명하기 어렵다(정상 앱의 큰 자산은 매직바이트로 식별되는 미디어/압축 포맷이다).
    # 실측 근거는 static_analyzer/code_scanner.py의 _detect_packed_assets 주석 참고.
    packed = code.get("packed_assets") or []
    if packed:
        biggest = max(packed, key=lambda a: a.get("apk_ratio") or 0)
        out.append(_ind(
            "packed_payload", "패킹된 페이로드",
            f"{len(packed)}개 (APK의 {(biggest.get('apk_ratio') or 0) * 100:.0f}%, 엔트로피 {biggest.get('entropy')})",
            strong=True,
        ))

    api_calls = code.get("suspicious_api_calls") or []
    if api_calls:
        out.append(_ind("suspicious_api", "의심 API 호출", f"{len(api_calls)}건"))
    # 동적 코드 로딩 단독은 정상 앱(플러그인·핫픽스 SDK)도 쓴다. 난독화와 겹칠 때만
    # 드로퍼 특징으로 보고 강한 지표로 센다.
    dcl = bool(code.get("dynamic_code_loading"))
    obf = bool(code.get("obfuscation_detected"))
    if dcl and obf:
        out.append(_ind("dropper_pattern", "난독화 + 동적 코드 로딩", "탐지", strong=True))
    else:
        if dcl:
            out.append(_ind("dynamic_code_loading", "동적 코드 로딩", "탐지"))
        if obf:
            out.append(_ind("obfuscation", "난독화", "탐지"))
    if code.get("reflection_usage"):
        out.append(_ind("reflection", "리플렉션 사용", "탐지"))

    n_susp_str = len(strings.get("suspicious_strings") or [])
    if n_susp_str:
        out.append(_ind("suspicious_strings", "의심 문자열", f"{n_susp_str}건"))
    n_ip_str = len(strings.get("ip_addresses") or [])
    if n_ip_str:
        out.append(_ind("hardcoded_ip_string", "하드코딩 IP 문자열", f"{n_ip_str}건"))

    if cert.get("is_self_signed"):
        out.append(_ind("self_signed", "자체 서명 인증서", "예"))

    return out


def _dynamic_indicators(data: dict) -> list[dict]:
    out: list[dict] = []
    plaintext = data.get("plaintext_candidates") or []
    events = data.get("events") or []

    # 평문 후보는 강한 지표가 아니다 — 실습용 취약 APK의 대표 특징이라 악성 판별력이
    # 낮다. 화면에는 그대로 보여주되(관찰 사실), 악성 승격 근거로는 쓰지 않는다.
    if plaintext:
        out.append(_ind("plaintext", "평문 후보", f"{len(plaintext)}건"))

    hook_counts: dict[str, int] = {}
    for ev in events:
        htype = ev.get("hook_type", "unknown")
        hook_counts[htype] = hook_counts.get(htype, 0) + 1

    n_cipher = hook_counts.get("cipher", 0) + hook_counts.get("custom_xor", 0)
    if n_cipher:
        out.append(_ind("runtime_crypto", "런타임 암복호화", f"{n_cipher}건"))

    # 정보탈취 후킹 (source / sink)
    n_sensitive = hook_counts.get("sensitive_read", 0)
    n_send = hook_counts.get("network_send", 0)
    if n_sensitive:
        out.append(_ind("sensitive_read", "민감정보 접근", f"{n_sensitive}건"))
    if n_send:
        # 목적지 유형(loopback/public)이 있으면 함께 보여준다 — 공인망 전송이 더 위험.
        dest_types = sorted({
            (ev.get("extra") or {}).get("dest_type")
            for ev in events if ev.get("hook_type") == "network_send"
        } - {None})
        suffix = f" ({', '.join(dest_types)})" if dest_types else ""
        out.append(_ind("network_send", "외부 전송", f"{n_send}건{suffix}"))

    # 정보탈취 패턴: 민감정보를 읽고(source) 밖으로 내보냈다(sink)면, 목적지가
    # 루프백이든 공인망이든 이 "읽기+전송" 조합 자체가 정보탈취의 정의다. 개별
    # 신호는 정상 앱도 흔하므로 강한 지표로 세지 않지만, 둘이 겹치면 승격한다
    # (난독화+동적로딩=dropper_pattern과 같은 조합-기반 판정).
    if n_sensitive and n_send:
        out.append(_ind("info_stealer_pattern",
                        "정보탈취 패턴 (민감정보 읽기 + 외부 전송)", "탐지", strong=True))

    if events:
        out.append(_ind("hook_events", "후킹 이벤트", f"{len(events)}건"))

    return out


def _network_indicators(data: dict) -> list[dict]:
    out: list[dict] = []
    suspicious = data.get("suspicious") or {}
    domains = suspicious.get("domains") or []
    ips = suspicious.get("ips") or []

    if domains:
        out.append(_ind(
            "suspicious_domain", "의심 도메인", f"{len(domains)}건",
            strong=len(domains) >= STRONG_SUSPICIOUS_DOMAIN_MIN,
        ))
    if ips:
        out.append(_ind(
            "suspicious_ip", "의심 IP", f"{len(ips)}건",
            strong=len(ips) >= STRONG_SUSPICIOUS_IP_MIN,
        ))

    n_dns = len(data.get("dns_queries") or [])
    n_sni = len(data.get("tls_sni") or [])
    if n_dns or n_sni:
        out.append(_ind("traffic_volume", "DNS / TLS", f"{n_dns} / {n_sni}"))

    return out


_INDICATORS = {
    "static": _static_indicators,
    "dynamic": _dynamic_indicators,
    "network": _network_indicators,
}


def _verdict_for(score100: Optional[int]) -> str:
    """점수 구간만으로 내리는 1차 판정. malicious 승격은 여기서 하지 않는다."""
    if score100 is None:
        return "unknown"
    for upper, name in VERDICT_BANDS:
        if score100 < upper:
            return name
    return "high_risk"


def aggregate_risk(modules: dict[str, Any]) -> dict:
    """세 모듈 결과(report["modules"])를 받아 종합 위험도를 계산한다.

    Returns:
        {
          "total": float(0.0~1.0) | None,   # 쓸 수 있는 모듈이 하나도 없으면 None
          "score100": int | None,           # total×100 (표시용 정수 점수)
          "level": 판정 코드 (verdict["code"]와 동일, 기존 키 유지),
          "verdict": {                      # 보안 판정 — 분석 상태와 다른 축
            "code": "normal"|"caution"|"suspicious"|"high_risk"|"malicious"|"unknown",
            "band_code": 점수 구간만으로 낸 판정(악성 승격 전),
            "strong_indicators": [...], "malicious_rule": {...},
          },
          "indicators": {                   # "무엇이 발견됐는가" (점수와 별개)
            "static": [{"code","label","value","strong"}, ...], "dynamic": [...], "network": [...],
          },
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
    # 화면·리포트에 그대로 나열할 "무엇이 발견됐는가" (점수와 별개 축)
    indicators: dict[str, list[dict]] = {"static": [], "dynamic": [], "network": []}

    for name in ("static", "dynamic", "network"):
        data = _usable(modules.get(name))
        base_weight = MODULE_WEIGHTS[name]
        if data is None:
            module_details[name] = {"available": False, "weight": 0.0}
            unavailable.append(name)
            continue

        # 지표는 하위 점수를 못 내는 모듈(예: 정적 risk_score=None)에서도 뽑는다.
        # 점수화에 실패한 것과 아무것도 관찰되지 않은 것은 다르기 때문.
        indicators[name] = _INDICATORS[name](data)

        # 정상 실행됐지만 관측된 것이 하나도 없으면 점수에 넣지 않는다(위 주석 참고).
        observed = _observation_count(name, data)
        if observed == 0:
            module_details[name] = {
                "available": False,
                "weight": 0.0,
                "reason": "no_observations",
                "reason_ko": "관측된 데이터 없음 (분석은 성공)",
            }
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
            "score100": None,
            "level": "unknown",
            "verdict": _build_verdict(None, indicators),
            "indicators": indicators,
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
    score100 = round(total * 100)
    verdict = _build_verdict(score100, indicators)

    return {
        "total": total,
        # 화면·CLI가 매번 ×100 하지 않도록 정수 점수도 같이 낸다(표기 흔들림 방지).
        "score100": score100,
        # level은 verdict.code와 같은 값이다. 기존 소비자(main.py/뷰)가 쓰던 키라 유지.
        "level": verdict["code"],
        "verdict": verdict,
        "indicators": indicators,
        "breakdown": {
            "modules": module_details,
            "weights_applied": weights_applied,
            "unavailable": unavailable,
        },
    }


def _build_verdict(score100: Optional[int], indicators: dict[str, list[dict]]) -> dict:
    """점수 구간 판정 + 악성 승격 규칙을 적용해 최종 보안 판정을 만든다.

    Returns:
        {
          "code": "normal"|"caution"|"suspicious"|"high_risk"|"malicious"|"unknown",
          "band_code": 점수 구간만으로 낸 판정(승격 전),
          "score100": int | None,
          "strong_indicators": [{code,label,value,module}, ...],
          "malicious_rule": {"min_score":…, "min_indicators":…, "met": bool},
        }

    승격 조건을 둘 다 만족해야 "악성"이 된다:
      1) 종합 점수 >= MALICIOUS_MIN_SCORE100
      2) 서로 다른 강한 지표 >= MALICIOUS_MIN_STRONG_INDICATORS 개
    한쪽만 만족하면 승격하지 않는다 — 취약 APK가 악성으로 표시되는 것을 막는 잠금.
    """
    band = _verdict_for(score100)

    strong = [
        {**ind, "module": module}
        for module, inds in indicators.items()
        for ind in inds
        if ind.get("strong")
    ]

    met = (
        score100 is not None
        and score100 >= MALICIOUS_MIN_SCORE100
        and len(strong) >= MALICIOUS_MIN_STRONG_INDICATORS
    )

    return {
        "code": "malicious" if met else band,
        "band_code": band,
        "score100": score100,
        "strong_indicators": strong,
        "malicious_rule": {
            "min_score": MALICIOUS_MIN_SCORE100,
            "min_indicators": MALICIOUS_MIN_STRONG_INDICATORS,
            "strong_indicator_count": len(strong),
            "met": met,
        },
    }
