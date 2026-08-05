"""manifest_parser의 intent_filters 수집 / components 구조화 테스트. (B, 6주차)

실제 APK 없이 AndroidManifest.xml 구조만 본뜬 XML로 검증한다.
androguard의 APK 클래스만 가짜로 바꿔 끼우면 parse_manifest() 전체를 돌릴 수 있다.
"""

from unittest.mock import patch

import pytest
from lxml import etree  # androguard.get_android_manifest_xml()이 반환하는 것과 같은 라이브러리

from static_analyzer import manifest_parser
from static_analyzer.manifest_parser import _get_component_info, _get_intent_filters

MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app">
  <application>
    <activity android:name="com.test.app.MainActivity">
      <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
      </intent-filter>
    </activity>

    <activity android:name="com.test.app.InternalActivity"/>

    <activity android:name="com.test.app.HiddenActivity" android:exported="false">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
      </intent-filter>
    </activity>

    <activity android:name="com.test.app.DeepLinkActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <data android:scheme="https" android:host="evil.example.com"/>
      </intent-filter>
    </activity>

    <service android:name="com.test.app.EmptyFilterService">
      <intent-filter/>
    </service>

    <receiver android:name="com.test.app.BootReceiver">
      <intent-filter>
        <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
        <category android:name="android.intent.category.DEFAULT"/>
      </intent-filter>
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED"/>
        <action android:name="android.provider.Telephony.SMS_RECEIVED"/>
      </intent-filter>
    </receiver>

    <provider android:name="com.test.app.FileProvider" android:exported="false"/>
  </application>
</manifest>
"""

PERMISSIONS = [
    "android.permission.INTERNET",
    "android.permission.READ_SMS",  # weight 9
    "android.permission.RECEIVE_SMS",  # weight 9
    "android.permission.REQUEST_INSTALL_PACKAGES",  # weight 5 -> dangerous 아님
    "android.permission.CAMERA",  # 미등록 -> weight 0
]


@pytest.fixture
def manifest_root():
    return etree.fromstring(MANIFEST_XML.encode("utf-8"))


@pytest.fixture
def parsed():
    """APK 클래스만 가짜로 바꿔서 parse_manifest() 전체를 돌린 결과."""

    class FakeAPK:
        def __init__(self, path):
            pass

        def get_android_manifest_xml(self):
            return etree.fromstring(MANIFEST_XML.encode("utf-8"))

        def get_permissions(self):
            return list(PERMISSIONS)

    with patch.object(manifest_parser, "APK", FakeAPK):
        return manifest_parser.parse_manifest("fake.apk")


def _find(components, name):
    return next(c for c in components if c["name"] == name)


# ------------------------------------------------------------ intent_filters 수집


def test_intent_filters_수집(manifest_root):
    activities = _get_component_info(manifest_root, "activity")
    assert _find(activities, "com.test.app.MainActivity")["intent_filters"] == [
        "android.intent.action.MAIN",
        "android.intent.category.LAUNCHER",
    ]


def test_intent_filter_없으면_빈_배열(manifest_root):
    activities = _get_component_info(manifest_root, "activity")
    assert _find(activities, "com.test.app.InternalActivity")["intent_filters"] == []


def test_intent_filter_여러개면_합치고_중복제거하며_순서유지(manifest_root):
    receivers = _get_component_info(manifest_root, "receiver")
    # SMS_RECEIVED가 두 intent-filter에 모두 있지만 한 번만, 처음 등장 순서로 남아야 한다
    assert _find(receivers, "com.test.app.BootReceiver")["intent_filters"] == [
        "android.provider.Telephony.SMS_RECEIVED",
        "android.intent.category.DEFAULT",
        "android.intent.action.BOOT_COMPLETED",
    ]


def test_data_태그는_수집하지_않음(manifest_root):
    """<data>(딥링크 scheme/host)는 스키마에 자리가 없어 수집 대상이 아니다."""
    activities = _get_component_info(manifest_root, "activity")
    filters = _find(activities, "com.test.app.DeepLinkActivity")["intent_filters"]
    assert filters == ["android.intent.action.VIEW"]
    assert not any("evil.example.com" in f or "https" == f for f in filters)


# ------------------------------------------------------------------- exported 판정


def test_intent_filter_있으면_exported_추론_True(manifest_root):
    activities = _get_component_info(manifest_root, "activity")
    assert _find(activities, "com.test.app.MainActivity")["exported"] is True


def test_exported_명시값이_intent_filter_추론보다_우선(manifest_root):
    """exported="false"인데 intent-filter가 있는 경우 -> 명시값(False)을 따른다."""
    activities = _get_component_info(manifest_root, "activity")
    assert _find(activities, "com.test.app.HiddenActivity")["exported"] is False


def test_빈_intent_filter는_exported_True지만_intent_filters는_빈_배열(manifest_root):
    """놓치기 쉬운 경계 케이스.

    exported 추론은 "intent-filter 태그가 있는가"로, intent_filters는 "그 안에
    action/category가 있는가"로 결정된다. 둘을 같은 조건으로 묶으면 exported 추론이 틀어진다.
    """
    services = _get_component_info(manifest_root, "service")
    svc = _find(services, "com.test.app.EmptyFilterService")
    assert svc["exported"] is True
    assert svc["intent_filters"] == []


def test_get_intent_filters_는_빈_intent_filter에서_빈_배열(manifest_root):
    svc_elem = manifest_root.find(".//service")
    assert svc_elem.find("intent-filter") is not None
    assert _get_intent_filters(svc_elem) == []


# ------------------------------------------------------- parse_manifest 전체 (components)


def test_components에_type이_붙는다(parsed):
    by_name = {c["name"]: c["type"] for c in parsed["components"]}
    assert by_name["com.test.app.MainActivity"] == "activity"
    assert by_name["com.test.app.EmptyFilterService"] == "service"
    assert by_name["com.test.app.BootReceiver"] == "receiver"
    assert by_name["com.test.app.FileProvider"] == "provider"


def test_components_type은_스키마_enum_범위(parsed):
    allowed = {"activity", "service", "receiver", "provider"}
    assert {c["type"] for c in parsed["components"]} <= allowed


def test_components는_기존_4개_리스트와_같은_집합(parsed):
    old = (
        parsed["activities"] + parsed["services"] + parsed["receivers"] + parsed["providers"]
    )
    assert sorted(c["name"] for c in parsed["components"]) == sorted(old)


def test_components에_이름이_None인_항목이_없다(parsed):
    assert all(c["name"] for c in parsed["components"])


# --------------------------------------------------------- 기존 필드 회귀 (깨지면 안 됨)


def test_기존_4개_리스트_유지(parsed):
    """risk_scorer 등 기존 코드가 참조 중이라 그대로 남아 있어야 한다."""
    assert parsed["activities"] == [
        "com.test.app.MainActivity",
        "com.test.app.InternalActivity",
        "com.test.app.HiddenActivity",
        "com.test.app.DeepLinkActivity",
    ]
    assert parsed["services"] == ["com.test.app.EmptyFilterService"]
    assert parsed["receivers"] == ["com.test.app.BootReceiver"]
    assert parsed["providers"] == ["com.test.app.FileProvider"]


def test_exported_components_내용과_순서_유지(parsed):
    """components 기반으로 다시 만들었지만 결과는 이전과 같아야 한다.

    risk_scorer가 이 리스트의 길이를 점수에 쓰기 때문에 내용이 바뀌면 점수가 바뀐다.
    """
    assert parsed["exported_components"] == [
        "com.test.app.MainActivity",
        "com.test.app.DeepLinkActivity",
        "com.test.app.EmptyFilterService",
        "com.test.app.BootReceiver",
    ]


def test_dangerous_permissions는_가중치_8이상만(parsed):
    assert parsed["dangerous_permissions"] == [
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
    ]


def test_permissions는_원본_그대로(parsed):
    assert parsed["permissions"] == PERMISSIONS
