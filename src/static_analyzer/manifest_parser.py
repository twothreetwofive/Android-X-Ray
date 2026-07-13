"""AndroidManifest.xml 파싱. (C 작성, 3주차 과제2)

androguard로 apk 파일에서 직접 읽는다 — apktool/jadx 디컴파일 결과물은 필요 없다.
"""

from androguard.core.apk import APK

# 위험 권한 목록 + 가중치. dangerous_permissions 필터링에만 쓰는 내부 참고표.
# 숫자 스케일(현재 1~10)은 D의 risk_scorer와 맞춰야 함 — 아직 미확정.
PERMISSION_WEIGHTS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 10,
    "android.permission.READ_SMS": 9,
    "android.permission.RECEIVE_SMS": 9,
    "android.permission.SYSTEM_ALERT_WINDOW": 10,
    "android.permission.REQUEST_INSTALL_PACKAGES": 5,
    # 필요한 만큼 계속 추가하면 됨
}

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
    dangerous_perms = [p for p in all_perms if PERMISSION_WEIGHTS.get(p, 0) >= 8]

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
