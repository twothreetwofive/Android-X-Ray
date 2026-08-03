"""AndroidManifest.xml 파싱. (C 작성, 3주차 과제2)

androguard로 apk 파일에서 직접 읽는다 — apktool/jadx 디컴파일 결과물은 필요 없다.
"""

from androguard.core.apk import APK

# 위험 권한 목록 + 가중치. risk_scorer.calculate_risk()가 permissions 전체에 이 표를
# 그대로 적용해서 합산하므로, 여기 없는 권한은 점수에 전혀 반영되지 않는다.
# 숫자 스케일(현재 1~10)은 D의 risk_scorer와 맞춰야 함 — 아직 미확정.
# Anubis류 뱅킹 트로이목마가 실제로 남용하는 패턴(화면 탈취/오버레이 피싱/OTP 가로채기/
# 도청·촬영/연락처 유출) 기준으로 5개 → 확장. 5개뿐이었을 때 CAMERA/RECORD_AUDIO/
# READ_CONTACTS 등은 표에 없어서 weight=0 취급되어 점수에 아예 안 잡혔음.
PERMISSION_WEIGHTS = {
    # 화면 탈취 / 오버레이 피싱 / 기기 장악 - Anubis류 핵심 남용 권한
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 10,
    "android.permission.SYSTEM_ALERT_WINDOW": 10,
    "android.permission.BIND_DEVICE_ADMIN": 9,
    # OTP/문자 가로채기
    "android.permission.READ_SMS": 9,
    "android.permission.RECEIVE_SMS": 9,
    "android.permission.SEND_SMS": 8,
    # 도청 / 촬영 / 위치 추적
    "android.permission.RECORD_AUDIO": 7,
    "android.permission.CAMERA": 7,
    "android.permission.ACCESS_BACKGROUND_LOCATION": 7,
    "android.permission.ACCESS_FINE_LOCATION": 6,
    # 다른 앱 탐지(뱅킹앱 오버레이 타이밍에 악용) / 통화 기록·연락처 유출
    "android.permission.PACKAGE_USAGE_STATS": 7,
    "android.permission.READ_CALL_LOG": 6,
    "android.permission.READ_CONTACTS": 6,
    "android.permission.CALL_PHONE": 6,
    "android.permission.QUERY_ALL_PACKAGES": 5,
    "android.permission.REQUEST_INSTALL_PACKAGES": 5,
    "android.permission.WRITE_CONTACTS": 5,
    # 기기 식별자 / 저장소 / 대략적 위치 - 단독으로는 위험도 낮지만 무시할 정도는 아님
    "android.permission.ACCESS_COARSE_LOCATION": 4,
    "android.permission.READ_PHONE_STATE": 4,
    "android.permission.GET_ACCOUNTS": 4,
    "android.permission.READ_EXTERNAL_STORAGE": 3,
    "android.permission.WRITE_EXTERNAL_STORAGE": 3,
    # 필요한 만큼 계속 추가하면 됨
}

# manifest_data["dangerous_permissions"] 필드(사람이 읽는 "위험 권한 목록") 노출 기준.
# risk_scorer는 이 상수와 무관하게 permissions 전체에 PERMISSION_WEIGHTS를 적용하므로,
# 이 값을 조정해도 점수 계산에는 영향 없음 - "얼마나 심각해야 보고서에 강조할지"만 결정함.
DANGEROUS_PERMISSION_THRESHOLD = 8

NS = "{http://schemas.android.com/apk/res/android}"


def _get_component_info(manifest_root, tag_name):
    """이름 목록 + exported 여부를 함께 뽑는 내부 헬퍼"""
    result = []
    for elem in manifest_root.iter(tag_name):
        name = elem.get(f"{NS}name")
        exported_attr = elem.get(f"{NS}exported")
        has_intent_filter = elem.find("intent-filter") is not None

        if exported_attr is not None:
            exported = exported_attr == "true"
        else:
            exported = has_intent_filter

        result.append({"name": name, "exported": exported})
    return result


def parse_manifest(apk_path: str) -> dict:
    apk = APK(apk_path)
    manifest_root = apk.get_android_manifest_xml()

    # 권한
    all_perms = apk.get_permissions()
    dangerous_perms = [p for p in all_perms if PERMISSION_WEIGHTS.get(p, 0) >= DANGEROUS_PERMISSION_THRESHOLD]

    # 컴포넌트별 정보 (내부적으로만 exported 판단에 사용)
    activities_info = _get_component_info(manifest_root, "activity")
    services_info = _get_component_info(manifest_root, "service")
    receivers_info = _get_component_info(manifest_root, "receiver")
    providers_info = _get_component_info(manifest_root, "provider")

    # exported인 것만 이름만 모아서 통합 리스트로
    exported_components = [
        c["name"]
        for group in (activities_info, services_info, receivers_info, providers_info)
        for c in group
        if c["exported"]
    ]

    return {
        "permissions": all_perms,
        "dangerous_permissions": dangerous_perms,
        "activities": [c["name"] for c in activities_info],
        "services": [c["name"] for c in services_info],
        "receivers": [c["name"] for c in receivers_info],
        "providers": [c["name"] for c in providers_info],
        "exported_components": exported_components,
    }
