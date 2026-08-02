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

# 권한별 악용 예시 설명. static_report.schema.json의 permissions[].abuse_example용.
#
# 위 PERMISSION_WEIGHTS와 목적이 다르다 — 이쪽은 사용자에게 "이 권한이 왜 위험한가"를
# 보여주는 설명 텍스트일 뿐이고 위험도 점수 계산에는 전혀 쓰이지 않는다. 그래서
# PERMISSION_WEIGHTS에 없는 권한도 자유롭게 넣을 수 있다 (넣어도 D의 점수는 안 바뀜).
# 반대로 PERMISSION_WEIGHTS 쪽은 risk_scorer가 그대로 합산에 쓰므로 임의로 못 늘린다.
ABUSE_EXAMPLES = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (
        "화면 내용 읽기·입력값 가로채기·자동 클릭이 가능하다. 뱅킹 트로이목마가 "
        "가짜 로그인 화면을 덮어씌우고 2차 인증을 우회하는 데 쓰는 핵심 권한"
    ),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        "다른 앱 위에 창을 띄울 수 있다. 정상 앱 화면 위에 가짜 입력창을 겹쳐 "
        "계정·카드 정보를 가로채는 오버레이 피싱에 쓰인다"
    ),
    "android.permission.READ_SMS": "문자 내용을 읽어 OTP(일회용 비밀번호)를 탈취",
    "android.permission.RECEIVE_SMS": "수신 문자를 실시간으로 가로채 OTP 탈취·스미싱",
    "android.permission.SEND_SMS": "사용자 모르게 유료 문자 발송, 스미싱 링크 확산",
    "android.permission.REQUEST_INSTALL_PACKAGES": (
        "추가 APK 설치를 유도할 수 있다. 최초 앱은 정상인 척하고 나중에 악성 모듈을 "
        "내려받아 설치하는 드로퍼 방식에 쓰인다"
    ),
    "android.permission.READ_CONTACTS": "연락처를 수집해 스미싱 발송 대상 확보",
    "android.permission.READ_PHONE_STATE": "기기 식별자·통신사·통화 상태 수집 (기기 지문화)",
    "android.permission.ACCESS_FINE_LOCATION": "정확한 위치를 지속 수집해 사용자 추적",
    "android.permission.CAMERA": "사용자 모르게 사진·영상 촬영",
    "android.permission.RECORD_AUDIO": "사용자 모르게 주변 소리·통화 녹음",
    "android.permission.READ_EXTERNAL_STORAGE": "저장소의 사진·문서 파일 탈취",
    "android.permission.WRITE_EXTERNAL_STORAGE": "저장소에 악성 파일을 심거나 기존 파일 변조",
    "android.permission.RECEIVE_BOOT_COMPLETED": (
        "부팅될 때마다 자동 실행된다. 사용자가 앱을 직접 열지 않아도 악성 동작이 "
        "계속 살아남는 지속성 확보 수단"
    ),
    "android.permission.QUERY_ALL_PACKAGES": (
        "설치된 앱 목록을 전부 조회한다. 공격 대상 은행 앱이 깔려 있는지 확인하는 데 쓰인다"
    ),
    "android.permission.INTERNET": (
        "외부 서버와 통신한다. 거의 모든 앱이 쓰는 흔한 권한이지만, 탈취한 정보를 "
        "공격자 서버(C&C)로 보내는 통로도 이 권한이다"
    ),
    # 필요한 만큼 계속 추가하면 됨 — 점수에 영향이 없으므로 추가는 자유롭다
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
