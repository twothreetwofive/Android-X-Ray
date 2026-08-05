"""static_adapter 테스트. (B, 6주차)

어댑터는 순수 dict 변환이라 실제 APK도 jadx/apktool도 필요 없다.
변환 결과가 schemas/static_report.schema.json을 실제로 만족하는지까지 확인한다.
"""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from static_analyzer.manifest_parser import ABUSE_EXAMPLES
from static_analyzer.static_adapter import (
    RISK_SCORE_SCALE,
    permission_risk_level,
    to_static_report,
)

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "static_report.schema.json"


@pytest.fixture(scope="module")
def validator():
    with SCHEMA_PATH.open(encoding="utf-8") as f:
        return Draft7Validator(json.load(f))


def assert_valid(validator, report):
    errors = sorted(validator.iter_errors(report), key=lambda e: list(e.path))
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)


@pytest.fixture
def result():
    """analyze_static()이 정상 완료했을 때의 반환값 모양."""
    return {
        "meta": {
            "apk_name": "sample.apk",
            "analyzed_at": "2026-08-02T12:00:00+00:00",
            "package_name": "com.test.app",
            "version_name": "1.0",
            "version_code": 1,
            "min_sdk": 24,
            "target_sdk": 34,
            "file_hash": {"md5": "aa", "sha1": "bb", "sha256": "cc"},
            "file_size": 1234,
        },
        "manifest": {
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.READ_SMS",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.FOO_UNKNOWN",
            ],
            "dangerous_permissions": ["android.permission.READ_SMS"],
            "activities": ["com.test.app.Main"],
            "services": [],
            "receivers": ["com.test.app.BootReceiver"],
            "providers": [],
            "exported_components": ["com.test.app.Main", "com.test.app.BootReceiver"],
            "components": [
                {
                    "type": "activity",
                    "name": "com.test.app.Main",
                    "exported": True,
                    "intent_filters": ["android.intent.action.MAIN"],
                },
                {
                    "type": "receiver",
                    "name": "com.test.app.BootReceiver",
                    "exported": True,
                    "intent_filters": ["android.intent.action.BOOT_COMPLETED"],
                },
            ],
        },
        "certificate": {"issuer": "CN=Test", "is_self_signed": True},
        "code_analysis": {"obfuscation_detected": True},
        "strings": {"urls": ["http://evil.example.com"], "ip_addresses": [], "suspicious_strings": []},
        "third_party_sdks": ["Firebase"],
        "risk_score": 0.62,
        # D의 calculate_risk_with_breakdown()이 채워주는 모양. weight 합(62)이 raw와
        # 정확히 일치해야 한다는 것이 이 구조의 핵심 계약이다.
        "risk_breakdown": {
            "total": 0.62,
            "raw": 62,
            "breakdown": [
                {"factor": "android.permission.READ_SMS", "weight": 9},
                {"factor": "android.permission.REQUEST_INSTALL_PACKAGES", "weight": 5},
                {"factor": "exported_components×2 (2개)", "weight": 4},
                {"factor": "suspicious_api_calls×3 (3개)", "weight": 9},
                {"factor": "obfuscation_detected", "weight": 15},
                {"factor": "reflection_usage", "weight": 10},
                {"factor": "certificate.is_self_signed", "weight": 10},
            ],
        },
        "errors": [],
    }


# --------------------------------------------------------------------- 스키마 준수


def test_정상_결과가_스키마를_만족(validator, result):
    assert_valid(validator, to_static_report(result))


def test_manifest_실패해도_스키마를_만족(validator, result):
    result["manifest"] = None
    assert_valid(validator, to_static_report(result))


def test_빈_dict_입력도_스키마를_만족(validator):
    """모든 단계가 실패한 극단적인 경우에도 통합이 파싱 에러로 죽지 않아야 한다."""
    assert_valid(validator, to_static_report({}))


def test_include_extra_False면_스키마_필드와_errors만_남는다(validator, result):
    report = to_static_report(result, include_extra=False)
    assert_valid(validator, report)
    assert set(report) == {"meta", "permissions", "components", "risk_score", "errors"}


def test_include_extra_True면_통합스키마에_없는_필드도_실린다(result):
    report = to_static_report(result)
    assert report["certificate"] == {"issuer": "CN=Test", "is_self_signed": True}
    assert report["code_analysis"] == {"obfuscation_detected": True}
    assert report["strings"]["urls"] == ["http://evil.example.com"]
    assert report["third_party_sdks"] == ["Firebase"]


# ------------------------------------------------------------------------- meta


def test_meta_기본_매핑(result):
    meta = to_static_report(result)["meta"]
    assert meta["apk_name"] == "sample.apk"
    assert meta["package_name"] == "com.test.app"
    assert meta["analyzed_at"] == "2026-08-02T12:00:00+00:00"
    assert meta["sha256"] == "cc"  # file_hash.sha256 -> sha256 으로 평탄화
    assert meta["min_sdk"] == 24
    assert meta["target_sdk"] == 34


def test_apk_name이_없으면_apk_path_인자로_채운다(result):
    del result["meta"]["apk_name"]
    meta = to_static_report(result, apk_path="/tmp/some/dir/old_sample.apk")["meta"]
    assert meta["apk_name"] == "old_sample.apk"


def test_apk_name도_apk_path도_없으면_빈문자열과_경고(result):
    del result["meta"]["apk_name"]
    report = to_static_report(result)
    assert report["meta"]["apk_name"] == ""
    assert any("apk_name" in e for e in report["errors"])


def test_analyzed_at이_없으면_변환시각으로_대체하고_경고(result):
    del result["meta"]["analyzed_at"]
    report = to_static_report(result)
    assert report["meta"]["analyzed_at"]  # 뭔가 채워지긴 함
    assert any("analyzed_at" in e for e in report["errors"])


def test_sdk_값이_없으면_키_자체를_뺀다(validator, result):
    """스키마에서 min_sdk/target_sdk는 optional이지만 넣을 거면 integer여야 한다.

    None을 넣으면 'null is not of type integer'로 검증에 걸리므로 키를 빼야 한다.
    """
    del result["meta"]["min_sdk"]
    del result["meta"]["target_sdk"]
    report = to_static_report(result)
    assert "min_sdk" not in report["meta"]
    assert "target_sdk" not in report["meta"]
    assert_valid(validator, report)


# ------------------------------------------------------------------- permissions


@pytest.mark.parametrize(
    "permission, expected",
    [
        ("android.permission.BIND_ACCESSIBILITY_SERVICE", "high"),  # weight 10
        ("android.permission.READ_SMS", "high"),  # weight 9
        ("android.permission.SEND_SMS", "high"),  # weight 8 = high 하한 경계
        ("android.permission.REQUEST_INSTALL_PACKAGES", "medium"),  # weight 5
        # 아래 4개는 D가 6주차에 표를 확장하기 전까지 전부 low로 떨어지던 권한들이다.
        # D가 확인을 요청한 항목이라 회귀로 고정해 둔다.
        ("android.permission.CAMERA", "medium"),  # weight 7
        ("android.permission.RECORD_AUDIO", "medium"),  # weight 7
        ("android.permission.READ_CONTACTS", "medium"),  # weight 6
        ("android.permission.ACCESS_FINE_LOCATION", "medium"),  # weight 6
        # 표에 있어도 weight가 4 미만이면 low다 — "표에 있으니 medium 이상"이 아니다.
        ("android.permission.READ_EXTERNAL_STORAGE", "low"),  # weight 3
        ("android.permission.INTERNET", "low"),  # 미등록 -> 0
        ("android.permission.FOO_UNKNOWN", "low"),  # 미등록 -> 0
    ],
)
def test_risk_level_구간_매핑(permission, expected):
    assert permission_risk_level(permission) == expected


def test_permissions가_객체_배열로_변환된다(result):
    permissions = to_static_report(result)["permissions"]
    assert [p["name"] for p in permissions] == result["manifest"]["permissions"]
    assert all("risk_level" in p for p in permissions)


def test_abuse_example은_있는_권한에만_붙는다(result):
    by_name = {p["name"]: p for p in to_static_report(result)["permissions"]}
    assert by_name["android.permission.READ_SMS"]["abuse_example"]
    # 설명이 없는 권한은 빈 문자열이 아니라 키 자체가 없어야 한다
    assert "abuse_example" not in by_name["android.permission.FOO_UNKNOWN"]


def test_manifest가_None이면_permissions는_빈_배열(result):
    result["manifest"] = None
    assert to_static_report(result)["permissions"] == []


# -------------------------------------------------------------------- components


def test_components를_그대로_옮긴다(result):
    components = to_static_report(result)["components"]
    assert components == [
        {
            "type": "activity",
            "name": "com.test.app.Main",
            "exported": True,
            "intent_filters": ["android.intent.action.MAIN"],
        },
        {
            "type": "receiver",
            "name": "com.test.app.BootReceiver",
            "exported": True,
            "intent_filters": ["android.intent.action.BOOT_COMPLETED"],
        },
    ]


def test_components에_모르는_키가_붙어와도_스키마_필드만_남는다(result):
    result["manifest"]["components"][0]["처음보는필드"] = "무시돼야 함"
    component = to_static_report(result)["components"][0]
    assert set(component) == {"type", "name", "exported", "intent_filters"}


def test_components_필드가_없으면_4개_리스트로_복원한다(result):
    """구버전 parse_manifest 출력(components 추가 이전)을 읽었을 때의 폴백."""
    del result["manifest"]["components"]
    report = to_static_report(result)

    assert report["components"] == [
        {
            "type": "activity",
            "name": "com.test.app.Main",
            "exported": True,
            "intent_filters": [],  # 원본에서 버려져 복원 불가
        },
        {
            "type": "receiver",
            "name": "com.test.app.BootReceiver",
            "exported": True,
            "intent_filters": [],
        },
    ]
    assert any("components" in e for e in report["errors"])


def test_복원시_exported는_exported_components_대조로_정한다(result):
    del result["manifest"]["components"]
    result["manifest"]["activities"] = ["com.test.app.Main", "com.test.app.Hidden"]
    result["manifest"]["exported_components"] = ["com.test.app.Main"]

    by_name = {c["name"]: c for c in to_static_report(result)["components"]}
    assert by_name["com.test.app.Main"]["exported"] is True
    assert by_name["com.test.app.Hidden"]["exported"] is False


# -------------------------------------------------------------------- risk_score


def test_risk_score가_0에서_100_스케일_객체로_바뀐다(result):
    risk_score = to_static_report(result)["risk_score"]
    assert risk_score["total"] == 62.0
    assert risk_score["scale"] == RISK_SCORE_SCALE


def test_breakdown을_risk_breakdown에서_그대로_옮긴다(result):
    """어댑터는 근거를 직접 계산하지 않고 D의 계산 결과를 옮기기만 한다."""
    breakdown = to_static_report(result)["risk_score"]["breakdown"]

    assert breakdown == result["risk_breakdown"]["breakdown"]
    assert {"factor", "weight"} == set(breakdown[0])


def test_breakdown_weight_합이_raw와_일치한다(result):
    """근거의 합이 총점과 다르면 근거로서 의미가 없다 — 이게 breakdown의 존재 이유다.

    어댑터가 항목을 빠뜨리거나 중복시키면 여기서 잡힌다.
    """
    report = to_static_report(result)
    total_weight = sum(item["weight"] for item in report["risk_score"]["breakdown"])

    assert total_weight == result["risk_breakdown"]["raw"]
    # total(0~100 스케일)도 같은 값이어야 한다 — NORMALIZATION_CAP이 100.0이라
    # raw가 곧 100점 만점 점수다.
    assert report["risk_score"]["total"] == float(result["risk_breakdown"]["raw"])


def test_권한_factor는_ABUSE_EXAMPLES와_다시_대조할_수_있다(result):
    """factor에 권한 전체 이름이 그대로 들어있어야 대시보드에서 설명을 붙일 수 있다."""
    breakdown = to_static_report(result)["risk_score"]["breakdown"]
    factors = [item["factor"] for item in breakdown]

    assert "android.permission.READ_SMS" in factors
    assert ABUSE_EXAMPLES["android.permission.READ_SMS"]


def test_risk_breakdown이_없으면_breakdown_생략하고_경고(result):
    """risk_breakdown 필드가 없던 구버전 결과로도 변환은 계속 돼야 한다.

    다만 근거 없는 점수라는 사실은 리포트에 남겨야 한다.
    """
    del result["risk_breakdown"]
    report = to_static_report(result)

    assert "breakdown" not in report["risk_score"]
    assert report["risk_score"]["total"] == 62.0  # 점수 자체는 그대로 나온다
    assert any("risk_breakdown" in e for e in report["errors"])


@pytest.mark.parametrize("broken", [None, "문자열", 123, {"breakdown": "리스트가 아님"}])
def test_risk_breakdown이_깨져있어도_변환은_계속된다(validator, result, broken):
    result["risk_breakdown"] = broken
    report = to_static_report(result)

    assert "breakdown" not in report["risk_score"]
    assert_valid(validator, report)


def test_breakdown_항목에_모르는_키가_붙어와도_factor_weight만_남긴다(result):
    """D가 나중에 항목에 필드를 더해도 통합 리포트 모양이 흔들리지 않도록."""
    result["risk_breakdown"]["breakdown"] = [
        {"factor": "android.permission.CAMERA", "weight": 7, "설명": "나중에 추가된 키"}
    ]
    breakdown = to_static_report(result)["risk_score"]["breakdown"]

    assert breakdown == [{"factor": "android.permission.CAMERA", "weight": 7}]


def test_risk_score가_None이면_breakdown도_안_붙는다(result):
    """점수가 실패했는데 근거만 남아있으면 total=0.0의 근거처럼 읽혀 더 혼란스럽다."""
    result["risk_score"] = None
    report = to_static_report(result)

    assert report["risk_score"] == {"total": 0.0, "scale": RISK_SCORE_SCALE}


def test_risk_score가_None이면_0으로_채우되_반드시_경고를_남긴다(result):
    """total=0.0을 '안전한 앱'으로 오해하면 안 되므로 경고가 필수다.

    스키마상 total은 required + number라 null을 넣을 수 없어서 0.0으로 채울 수밖에 없다.
    """
    result["risk_score"] = None
    report = to_static_report(result)
    assert report["risk_score"]["total"] == 0.0
    assert any("risk_score" in e and "안전" in e for e in report["errors"])


def test_risk_score가_bool이면_점수로_취급하지_않는다(result):
    """파이썬에서 True는 int의 하위 타입이라 isinstance(True, int)가 참이다.

    방어하지 않으면 True가 total=100.0(최고 위험)으로 둔갑한다.
    """
    result["risk_score"] = True
    report = to_static_report(result)
    assert report["risk_score"]["total"] == 0.0
    assert any("risk_score" in e for e in report["errors"])


# ------------------------------------------------------------------------ errors


def test_원본_errors를_보존하고_어댑터_경고를_뒤에_붙인다(result):
    result["errors"] = ["코드 스캔 실패: jadx 없음"]
    result["risk_score"] = None
    report = to_static_report(result)

    assert report["errors"][0] == "코드 스캔 실패: jadx 없음"
    assert len(report["errors"]) > 1


def test_변환이_원본_result를_건드리지_않는다(result):
    """오케스트레이터가 원본 결과를 다른 곳에서도 쓸 수 있으므로 부작용이 없어야 한다."""
    before = deepcopy(result)
    to_static_report(result)
    assert result == before
