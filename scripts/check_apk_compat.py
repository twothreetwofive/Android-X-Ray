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
DEVICE_ABIS = {"x86"}
DEVICE_API = 29

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

    score = len(perms & INTERESTING_PERMS)
    grade = "좋음" if score >= 5 else ("보통" if score >= 2 else "빈약")
    print(f"  판정: [설치 가능]  동적 분석 볼거리: {grade} (주목 권한 {score}개)")
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
