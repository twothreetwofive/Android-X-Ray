#!/usr/bin/env bash
# scripts/connect_emulator.sh — WSL에서 Windows 에뮬레이터에 붙는 과정을 한 번에.
#
# 사용:  bash scripts/connect_emulator.sh
#        (에뮬레이터는 Windows에서 미리 켜 둘 것)
#
# 왜 스크립트인가:
#   adb kill-server / adb-bridge & / adb devices 를 손으로 순서대로 치는 방식은
#   실패하기 쉽다. 특히 **bridge가 이미 떠 있는 상태에서 `adb kill-server`를 치면
#   그 명령이 중계를 타고 넘어가 Windows 쪽 adb 서버를 죽인다.** 그러면 WSL도
#   Windows도 연결이 끊긴 채 "Address already in use"와 "Connection reset by peer"가
#   동시에 나온다. 이 스크립트는 각 단계의 상태를 먼저 확인하고 필요한 것만 한다
#   (몇 번을 실행해도 같은 결과 — idempotent).

set -u

# Windows 쪽 adb.exe 경로. **Android Studio가 실제로 쓰는 SDK**를 가리켜야 한다.
# 이 PC에는 SDK가 두 벌 있고(C:\Android_AVD, %LOCALAPPDATA%\Android\Sdk),
# 에뮬레이터는 C:\Android_AVD 쪽에서 돈다. 다른 쪽 adb.exe로 서버를 띄우면
# 버전이 같아도 Android Studio가 관리하는 서버와 따로 놀아 기기가 안 보인다.
ADB_WIN="${ADB_WIN:-/mnt/c/Android_AVD/platform-tools/adb.exe}"
if [ ! -x "$ADB_WIN" ]; then
    # 대체 경로: 사용자 홈의 기본 SDK 위치에서 찾아본다.
    ADB_WIN=$(ls /mnt/c/Users/*/AppData/Local/Android/Sdk/platform-tools/adb.exe 2>/dev/null | head -1)
fi

# WSL adb와 Windows adb는 **버전이 같아야 한다.** 다르면 WSL 클라이언트가
# "서버 버전이 다르다"며 원격 서버를 죽이고 자기 로컬 서버를 띄운다
# (Windows 로그에 "adb server killed by remote request"로 남는다). 그러면
# 에뮬레이터가 붙어 있는 서버는 사라지고 WSL에서는 기기가 안 보인다.
# 실제로 8주차에 WSL 37.0.1 / Windows 37.0.0 조합에서 이 현상이 났다.

WINIP=$(ip route show default | awk '{print $3}')
PORT=5037

ok()   { echo "  [OK]   $*"; }
warn() { echo "  [..]   $*"; }
fail() { echo "  [실패] $*"; }
step() { echo; echo "== $* =="; }

# ── 0. 준비 확인 ──
if ! command -v adb >/dev/null; then
    fail "adb가 PATH에 없음 — 먼저 'source scripts/wsl_env.sh'"
    exit 1
fi
if [ -z "$ADB_WIN" ] || [ ! -x "$ADB_WIN" ]; then
    fail "Windows adb.exe를 찾을 수 없음: ${ADB_WIN:-(없음)}"
    fail "경로가 다르면 ADB_WIN=/mnt/c/.../adb.exe bash scripts/connect_emulator.sh 로 지정"
    exit 1
fi

# ── 0-1. adb 버전 일치 확인 ──
VER_WSL=$(adb version | sed -n 2p | awk '{print $2}')
VER_WIN=$("$ADB_WIN" version | sed -n 2p | tr -d '\r' | awk '{print $2}')
if [ "$VER_WSL" != "$VER_WIN" ]; then
    fail "adb 버전 불일치 — WSL($VER_WSL) vs Windows($VER_WIN)"
    fail "이 상태로는 WSL 클라이언트가 Windows adb 서버를 죽여버려서 기기가 보이지 않는다."
    fail "해결: 같은 버전의 platform-tools를 WSL에 설치할 것"
    fail "  curl -o /tmp/pt.zip https://dl.google.com/android/repository/platform-tools_r\${VER_WIN%%-*}-linux.zip"
    exit 1
fi

# ── 1. Windows adb 서버가 WSL에서 닿는지 확인 ──
step "1. Windows adb 서버 (${WINIP}:${PORT})"

reachable() {
    python3 - "$WINIP" "$PORT" <<'PY'
import socket, sys
try:
    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3).close()
except OSError:
    sys.exit(1)
PY
}

if reachable; then
    ok "이미 열려 있음"
else
    warn "닿지 않음 — 모든 인터페이스에 바인드해서 다시 띄운다"
    # Android Studio가 띄운 서버는 127.0.0.1에만 바인드돼 WSL에서 안 보인다.
    # 죽이고 -a 옵션으로 다시 올린다(에뮬레이터 자체는 죽지 않는다).
    "$ADB_WIN" kill-server >/dev/null 2>&1
    sleep 1
    nohup "$ADB_WIN" -a -P "$PORT" nodaemon server >/tmp/winadb.log 2>&1 &
    sleep 3
    if reachable; then
        ok "재기동 완료"
    else
        fail "여전히 닿지 않음. Windows 방화벽이 WSL 서브넷을 막고 있을 수 있음"
        fail "PowerShell에서 직접 실행해 볼 것:  adb -a -P 5037 nodaemon server"
        exit 1
    fi
fi

# ── 2. WSL 쪽 중계(adb-bridge) ──
step "2. WSL 중계 (127.0.0.1:${PORT})"

# 프로세스 이름(pgrep)으로 판별하지 않는다 — 명령줄에 "adb-bridge" 문자열이
# 들어간 다른 셸까지 잡혀서 "이미 떠 있다"고 오판한 적이 있다.
# 대신 **실제로 동작하는지**를 본다: 5037에 붙어서 Windows 쪽 기기 목록이
# 돌아오면 살아있는 중계다.
bridge_works() {
    # 중계가 살아 있으면 이 요청이 Windows 서버까지 가서 응답이 온다.
    timeout 5 adb host-features >/dev/null 2>&1
}

port_free() {
    python3 - "$PORT" <<'PY'
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
}

if ! port_free && bridge_works; then
    ok "중계가 이미 살아 있음 — 그대로 쓴다"
else
    if ! port_free; then
        # 포트는 잡혀 있는데 동작은 안 한다 = 죽은 중계 또는 WSL 로컬 adb 서버.
        # 어느 쪽이든 정리해야 한다. adb 로컬 서버부터 정리하고,
        # 그래도 안 비면 우리 중계 프로세스를 직접 종료한다.
        warn "5037이 잡혀 있으나 응답이 없음 — 정리한다"
        env -u ADB_SERVER_SOCKET adb kill-server >/dev/null 2>&1
        sleep 1
        if ! port_free; then
            pkill -f "python3 .*bin/adb-bridge" 2>/dev/null
            sleep 1
        fi
    fi

    if ! port_free; then
        fail "5037을 비울 수 없음. 아래로 점유 프로세스를 확인할 것:"
        fail "  ss -ltnp | grep 5037"
        exit 1
    fi

    nohup adb-bridge >/tmp/adb-bridge.log 2>&1 &
    sleep 2
    if bridge_works; then
        ok "중계 시작 (로그: /tmp/adb-bridge.log)"
    else
        fail "중계가 떴지만 Windows 서버와 통신되지 않음 — /tmp/adb-bridge.log 확인"
        cat /tmp/adb-bridge.log 2>/dev/null
        exit 1
    fi
fi

# ── 3. 기기 확인 ──
step "3. 기기 확인"
OUT=$(adb devices 2>&1)
echo "$OUT" | sed 's/^/  /'

if echo "$OUT" | grep -qE "device$"; then
    SERIAL=$(echo "$OUT" | awk '/device$/{print $1; exit}')
    ok "연결됨: $SERIAL"
    echo "  ABI=$(adb shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')" \
         "API=$(adb shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r')"
    echo
    echo "다음: bash scripts/prepare_emulator.sh ~/samples/<파일명>.apk"
elif echo "$OUT" | grep -q "offline"; then
    fail "기기가 offline 상태 — 에뮬레이터 부팅이 끝날 때까지 기다린 뒤 재실행"
    exit 1
else
    fail "연결된 기기 없음"
    fail "Windows에서 에뮬레이터가 켜져 있는지 확인 (작업 관리자에 qemu-system-x86_64)"
    exit 1
fi
