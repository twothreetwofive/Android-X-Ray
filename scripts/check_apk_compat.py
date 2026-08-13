#!/usr/bin/env python3
"""scripts/check_apk_compat.py — 받은 APK가 우리 팀 AVD에서 실제로 실행 가능한지 미리 거른다.

사용:
    python3 scripts/check_apk_compat.py ~/samples/*.apk

왜 필요한가:
    팀 공용 AVD(Pixel_4 / API 29 / google_apis)는 `ro.product.cpu.abilist=x86` 단독이다.
    ARM 변환(libhoudini)이 없으므로 네이티브 라이브러리가 arm64-v8a / armeabi-v7a /
    x86_64 뿐인 APK는 `adb install`이 INSTALL_FAILED_NO_MATCHING_ABIS로 실패한다.
    MalwareBazaar에서 샘플을 여러 개 받아놓고 이 스크립트로 한 번에 거른 뒤,
    통과한 것만 동적·네트워크 분석에 쓰면 된다.

    정적 분석은 ABI/API와 무관하게 항상 가능하므로, 여기서 탈락해도
    "정적 전용 샘플"로는 쓸 수 있다.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

# 팀 공용 AVD 기준값 (adb shell getprop ro.product.cpu.abilist / ro.build.version.sdk)
#
# 실측(2026-08-13, emulator-5554):
#   ro.product.cpu.abilist = x86_64,x86,arm64-v8a,armeabi-v7a,armeabi
#   ro.build.version.sdk   = 30
# arm64-v8a/armeabi-v7a가 목록에 있는 것은 이 이미지가 **ARM 변환을 내장**하기
# 때문이다. 즉 ARM 전용 APK도 설치·실행된다 — 안드로이드 악성코드 상당수가
# ARM 전용이라 샘플 고를 때 제약이 사실상 없어진다.
DEVICE_ABIS = {"x86_64", "x86", "arm64-v8a", "armeabi-v7a", "armeabi"}
DEVICE_API = 30


def _detect_device() -> None:
    """에뮬레이터가 붙어 있으면 실제 값으로 갱신한다.

    위 기본값은 이 팀 AVD 기준이라, 다른 사람이 다른 AVD로 돌리면 틀린 판정을
    내놓는다. adb가 잡히면 기기에서 직접 읽어오는 편이 정확하다.
    """
    global DEVICE_ABIS, DEVICE_API
    import shutil
    import subprocess

    if not shutil.which("adb"):
        return
    try:
        abilist = subprocess.run(
            ["adb", "shell", "getprop", "ro.product.cpu.abilist"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        sdk = subprocess.run(
            ["adb", "shell", "getprop", "ro.build.version.sdk"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return

    if abilist:
        DEVICE_ABIS = {a.strip() for a in abilist.split(",") if a.strip()}
    if sdk.isdigit():
        DEVICE_API = int(sdk)
    if abilist or sdk:
        print(f"[기기 감지] ABI={sorted(DEVICE_ABIS)} API={DEVICE_API}")

# 동적/네트워크 분석에서 볼거리가 나오는 권한들 (있을수록 좋은 샘플)
INTERESTING_PERMS = {
    "android.permission.INTERNET",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
}

# 흔한 상용 패커 (네이티브 .so 기반이라 대부분 ARM 전용 -> x86 AVD에서 설치 불가)
PACKER_HINTS = {
    "libjiagu": "360 Jiagu",
    "libshell": "Bangcle/SecShell",
    "libDexHelper": "DexProtector",
    "libtup": "Tencent Legu",
    "libnesec": "NetEase",
    "libapp-armeabi": "일반 패커",
}


def _abis(apk_path: Path) -> set[str]:
    with zipfile.ZipFile(apk_path) as z:
        return {
            n.split("/")[1]
            for n in z.namelist()
            if n.startswith("lib/") and n.count("/") >= 2
        }


def _packers(apk_path: Path) -> list[str]:
    with zipfile.ZipFile(apk_path) as z:
        names = z.namelist()
    found = []
    for key, label in PACKER_HINTS.items():
        if any(key.lower() in n.lower() for n in names):
            found.append(label)
    return found


def check(apk_path: Path) -> bool:
    from androguard.core.apk import APK

    print(f"\n=== {apk_path.name} ===")
    try:
        apk = APK(str(apk_path))
    except Exception as e:  # noqa: BLE001 — 깨진 샘플도 흔하므로 죽지 않게
        print(f"  [실패] APK 파싱 불가: {type(e).__name__}: {e}")
        print("  판정: 사용 불가")
        return False

    try:
        min_sdk = int(apk.get_min_sdk_version() or 0)
    except (TypeError, ValueError):
        min_sdk = 0

    abis = _abis(apk_path)
    perms = set(apk.get_permissions())
    packers = _packers(apk_path)

    print(f"  패키지     : {apk.get_package()}")
    print(f"  앱 이름    : {apk.get_app_name()}")
    print(f"  minSdk     : {min_sdk or '미지정'}  (기기 API {DEVICE_API})")
    print(f"  네이티브ABI: {sorted(abis) if abis else '없음 (DEX 전용)'}")
    print(f"  권한       : {len(perms)}개")
    if packers:
        print(f"  패커 흔적  : {', '.join(packers)}")

    hit = sorted(p.rsplit('.', 1)[-1] for p in (perms & INTERESTING_PERMS))
    if hit:
        print(f"  주목 권한  : {', '.join(hit)}")

    # 표준 권한 수를 따로 센다. 전체 권한이 수십 개여도 대부분이 앱 자체 정의
    # 권한(com.xxx.permission.*)이면 실제 능력은 그만큼이 아니다. 반대로 표준
    # 권한이 1~2개뿐인데 그게 REQUEST_INSTALL_PACKAGES면 드로퍼 신호다.
    std_perms = {p for p in perms if p.startswith("android.permission.")}
    if len(perms) != len(std_perms):
        print(f"  권한 내역  : 표준 {len(std_perms)}개 / 앱 자체 정의 {len(perms) - len(std_perms)}개")

    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
        print("  ⚠ 드로퍼 신호: REQUEST_INSTALL_PACKAGES (실행 후 2차 APK를 내려받아 설치하는 유형)")

    # 이름에 제로폭 문자를 섞어 탐지·검색을 피하는 수법이 흔하다.
    name = apk.get_app_name() or ""
    zero_width = [c for c in name if c in "​‌‍⁠﻿"]
    if zero_width:
        print(f"  ⚠ 앱 이름에 제로폭 문자 {len(zero_width)}개 — 이름 위장/탐지 회피 수법")

    n_components = len(apk.get_activities()) + len(apk.get_services()) + len(apk.get_receivers())
    print(f"  컴포넌트   : {n_components}개 "
          f"(액티비티 {len(apk.get_activities())} / 서비스 {len(apk.get_services())} / 리시버 {len(apk.get_receivers())})")

    # ── 설치 가능 여부 판정 ──
    reasons = []
    if abis and not (abis & DEVICE_ABIS):
        reasons.append(f"ABI 불일치 (APK={sorted(abis)}, 기기={sorted(DEVICE_ABIS)})")
    if min_sdk > DEVICE_API:
        reasons.append(f"minSdk {min_sdk} > 기기 API {DEVICE_API}")

    if reasons:
        print("  판정: [정적 전용]  " + " / ".join(reasons))
        print("        -> 동적·네트워크 분석 불가. 정적 분석 대상으로만 사용")
        return False

    # 관찰거리 등급 — 주목 권한 수만 세면 드로퍼처럼 "권한은 적지만 실행 시
    # 행동이 큰" 유형을 과소평가한다. 드로퍼 신호와 컴포넌트 규모를 함께 본다.
    score = len(perms & INTERESTING_PERMS)
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
        score += 3
    if n_components >= 50:
        score += 1

    grade = "좋음" if score >= 5 else ("보통" if score >= 2 else "빈약")
    print(f"  판정: [설치 가능]  동적 분석 볼거리: {grade}")
    return True


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 1

    paths = [Path(a) for a in argv[1:]]
    paths = [p for p in paths if p.is_file()]
    if not paths:
        print("검사할 APK 파일이 없음")
        return 1

    _detect_device()   # 기기가 붙어 있으면 실제 사양으로 판정

    installable = [p for p in paths if check(p)]

    print(f"\n{'=' * 50}")
    print(f"총 {len(paths)}개 중 설치 가능 {len(installable)}개")
    for p in installable:
        print(f"  - {p.name}")
    if not installable:
        print("  (없음 — 다른 샘플을 받아서 다시 확인할 것)")
    return 0


if __name__ == "__main__":
    # androguard의 DEBUG 로그 억제
    try:
        from loguru import logger

        logger.remove()
    except ImportError:
        pass
    sys.exit(main(sys.argv))
