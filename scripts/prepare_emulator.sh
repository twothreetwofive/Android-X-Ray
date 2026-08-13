#!/usr/bin/env bash
# scripts/prepare_emulator.sh — 파이프라인 실행 전 에뮬레이터 사전 준비
#
# 사용:  bash scripts/prepare_emulator.sh [분석할.apk]
#
# 하는 일 (전부 adb 명령이고, 에뮬레이터를 켜 둔 상태에서 1회만 하면 된다):
#   1. adb 연결 / 부팅 완료 확인
#   2. adb root  (google_apis 이미지여야 성공. Play Store 이미지는 root 불가)
#   3. tcpdump 를 /data/local/tmp/tcpdump 에 준비
#      -> network_analyzer/capture.py 가 이 경로를 하드코딩해서 확인하고,
#         없으면 TcpdumpCaptureError로 동적·네트워크가 통째로 실패한다
#         (7주차에 C가 "tcpdump 에러에서 중단"된 지점이 바로 여기)
#   4. 기기 ABI에 맞는 frida-server 를 push 하고 백그라운드로 실행
#   5. (인자로 apk를 주면) 그 apk 설치까지
#
# 사전 조건: `source scripts/wsl_env.sh` 로 adb가 PATH에 있어야 함.

set -u
APK="${1:-}"
TOOLS="$HOME/tools"
FRIDA_VER="17.16.2"

ok()   { echo "  [OK]   $*"; }
fail() { echo "  [실패] $*"; }
step() { echo; echo "== $* =="; }

# ── 1. 기기 확인 ──
step "1. 기기 연결 확인"
if ! command -v adb >/dev/null; then
  fail "adb가 PATH에 없음. 먼저 'source scripts/wsl_env.sh' 실행"
  exit 1
fi
if ! adb devices | grep -qE "device$"; then
  fail "연결된 기기 없음. Windows에서 에뮬레이터를 켜고 adb-bridge가 떠 있는지 확인"
  adb devices
  exit 1
fi
SERIAL=$(adb devices | awk '/device$/{print $1; exit}')
ok "기기: $SERIAL"

BOOTED=$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
[ "$BOOTED" = "1" ] && ok "부팅 완료" || { fail "아직 부팅 중 (잠시 후 재실행)"; exit 1; }

ABI=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
SDK_VER=$(adb shell getprop ro.build.version.sdk | tr -d '\r')
ok "ABI=$ABI, API=$SDK_VER"

# ── 2. root ──
step "2. adb root"
adb root >/dev/null 2>&1
sleep 2
adb wait-for-device
WHO=$(adb shell whoami 2>/dev/null | tr -d '\r')
if [ "$WHO" = "root" ]; then
  ok "root 획득"
else
  fail "root 실패 (현재 사용자: $WHO). Play Store 포함 이미지는 root 불가 -> google_apis 이미지 AVD로 다시 만들 것"
  fail "root 없이는 tcpdump 캡처가 안 되므로 네트워크 모듈은 실패한다"
fi

# ── 3. tcpdump ──
step "3. tcpdump 준비 (/data/local/tmp/tcpdump)"
if adb shell "[ -f /data/local/tmp/tcpdump ] && echo EXISTS" | grep -q EXISTS; then
  ok "이미 존재"
elif adb shell "[ -f /system/bin/tcpdump ] && echo EXISTS" | grep -q EXISTS; then
  adb shell "cp /system/bin/tcpdump /data/local/tmp/tcpdump && chmod 755 /data/local/tmp/tcpdump"
  ok "시스템 이미지의 tcpdump를 복사함"
elif adb shell "[ -f /system/xbin/tcpdump ] && echo EXISTS" | grep -q EXISTS; then
  adb shell "cp /system/xbin/tcpdump /data/local/tmp/tcpdump && chmod 755 /data/local/tmp/tcpdump"
  ok "시스템 이미지(xbin)의 tcpdump를 복사함"
elif [ -f "$TOOLS/tcpdump-android" ]; then
  adb push "$TOOLS/tcpdump-android" /data/local/tmp/tcpdump >/dev/null
  adb shell chmod 755 /data/local/tmp/tcpdump
  ok "로컬 static 바이너리를 push함"
else
  fail "기기에 tcpdump가 없고 로컬 static 바이너리도 없음"
  fail "-> static 빌드된 android용 tcpdump를 구해 ~/tools/tcpdump-android 로 두고 다시 실행"
  fail "-> 대안: 에뮬레이터를 'emulator -avd <이름> -tcpdump C:\\경로\\capture.pcap' 로 띄워 호스트에서 직접 캡처"
fi
adb shell "/data/local/tmp/tcpdump --version" 2>&1 | head -2

# ── 4. frida-server ──
step "4. frida-server $FRIDA_VER 준비"
case "$ABI" in
  x86_64)      FS="$TOOLS/frida-server-${FRIDA_VER}-android-x86_64" ;;
  x86)         FS="$TOOLS/frida-server-${FRIDA_VER}-android-x86" ;;
  arm64-v8a)   FS="$TOOLS/frida-server-${FRIDA_VER}-android-arm64" ;;
  armeabi-v7a) FS="$TOOLS/frida-server-${FRIDA_VER}-android-arm" ;;
  *)           FS="" ;;
esac

if [ -z "$FS" ] || [ ! -f "$FS" ]; then
  fail "ABI($ABI)에 맞는 frida-server 바이너리가 없음: $FS"
  fail "-> https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-<ABI>.xz 를 받아 ~/tools 에 둘 것"
else
  adb push "$FS" /data/local/tmp/frida-server >/dev/null && ok "push 완료 ($(basename "$FS"))"
  adb shell chmod 755 /data/local/tmp/frida-server
  adb shell "pkill -f frida-server" 2>/dev/null
  adb shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &" &
  sleep 3
  if adb shell pidof frida-server | tr -d '\r' | grep -q .; then
    ok "frida-server 실행 중 (pid $(adb shell pidof frida-server | tr -d '\r'))"
  else
    fail "frida-server가 뜨지 않음. 'adb shell /data/local/tmp/frida-server' 를 직접 실행해 에러 확인"
  fi
fi

echo
echo "-- 호스트에서 frida 연결 확인 --"
python3 -c "
import frida
try:
    d = frida.get_usb_device(timeout=5)
    print('  [OK]   frida 연결:', d.name)
    print('  실행 중인 앱 수:', len(d.enumerate_processes()))
except Exception as e:
    print('  [실패] frida 연결:', type(e).__name__, e)
"

# ── 5. APK 설치 ──
if [ -n "$APK" ]; then
  step "5. APK 설치: $APK"
  if [ ! -f "$APK" ]; then
    fail "파일 없음: $APK"
  else
    OUT=$(adb install -r -g "$APK" 2>&1)
    echo "$OUT" | tail -3
    if echo "$OUT" | grep -q "Success"; then
      ok "설치 성공"
    elif echo "$OUT" | grep -q "NO_MATCHING_ABIS"; then
      fail "APK의 네이티브 라이브러리가 기기 ABI($ABI)와 안 맞음"
      fail "-> 같은 ABI의 AVD를 새로 만들거나, 이 APK는 정적 분석 전용으로 쓸 것"
    fi
  fi
fi

step "준비 완료"
echo "다음: python3 src/main.py <apk경로> --output output/report_<이름>.json"
