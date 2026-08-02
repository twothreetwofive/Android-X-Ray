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


def _get_intent_filters(elem):
    """컴포넌트의 <intent-filter> 안에 있는 action/category 이름을 평평한 목록으로 모은다.

    schemas/static_report.schema.json의 components[].intent_filters가
    "반응하는 action/category" 문자열 배열이라 그 형태에 맞춘다.
    <data>(딥링크 scheme/host)는 스키마에 자리가 없어서 여기서는 수집하지 않는다.

    intent-filter가 여러 개면 전부 합치되, 중복은 순서를 유지한 채 제거한다.
    """
    names = []
    for intent_filter in elem.findall("intent-filter"):
        for child_tag in ("action", "category"):
            for child in intent_filter.findall(child_tag):
                name = child.get(f"{NS}name")
                if name:
                    names.append(name)
    return list(dict.fromkeys(names))


def _get_component_info(manifest_root, tag_name):
    """컴포넌트별 이름 + exported 여부 + intent-filter 내용을 뽑는 내부 헬퍼

    <activity-alias>는 별도 태그라 여기서 안 잡힌다 — 기존 동작 그대로 유지했다.
    (실제 앱에서 쓰이면 누락되므로 나중에 보완 대상)
    """
    result = []
    for elem in manifest_root.iter(tag_name):
        name = elem.get(f"{NS}name")
        exported_attr = elem.get(f"{NS}exported")
        # exported 기본값 추론은 "intent-filter가 있는가"로 판단한다.
        # 아래 intent_filters가 비어 있어도(action/category 없는 빈 필터) 여기서는
        # True일 수 있으므로, 둘을 같은 것으로 취급하면 안 된다.
        has_intent_filter = elem.find("intent-filter") is not None

        if exported_attr is not None:
            exported = exported_attr == "true"
        else:
            exported = has_intent_filter

        result.append(
            {
                "name": name,
                "exported": exported,
                "intent_filters": _get_intent_filters(elem),
            }
        )
    return result


def parse_manifest(apk_path: str) -> dict:
    apk = APK(apk_path)
    manifest_root = apk.get_android_manifest_xml()

    # 권한
    all_perms = apk.get_permissions()
    dangerous_perms = [p for p in all_perms if PERMISSION_WEIGHTS.get(p, 0) >= 8]

    # 컴포넌트별 정보
    activities_info = _get_component_info(manifest_root, "activity")
    services_info = _get_component_info(manifest_root, "service")
    receivers_info = _get_component_info(manifest_root, "receiver")
    providers_info = _get_component_info(manifest_root, "provider")

    # 종류(type)를 붙여서 하나의 목록으로 합친다. 아래 activities/services/...
    # 4개 리스트는 이름만 남기고 종류 정보가 흩어지기 때문에, 6주차 통합용
    # static_report.schema.json의 components 배열은 이쪽을 쓴다.
    components = [
        {"type": comp_type, **info}
        for comp_type, group in (
            ("activity", activities_info),
            ("service", services_info),
            ("receiver", receivers_info),
            ("provider", providers_info),
        )
        for info in group
    ]

    # exported인 것만 이름만 모아서 통합 리스트로
    exported_components = [c["name"] for c in components if c["exported"]]

    return {
        "permissions": all_perms,
        "dangerous_permissions": dangerous_perms,
        "activities": [c["name"] for c in activities_info],
        "services": [c["name"] for c in services_info],
        "receivers": [c["name"] for c in receivers_info],
        "providers": [c["name"] for c in providers_info],
        "exported_components": exported_components,
        "components": components,
    }
