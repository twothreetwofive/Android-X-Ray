// C의 schema.py(HookEvent) 포맷에 맞춰 send() 한다.
// 필드를 바꿔야 하면 C와 먼저 맞추고 schema.py부터 고칠 것.
//
// Python/frida_controller.py 없이 테스트 가능:
//   frida -U -f <패키지명> -l hooks.js
import Java from 'frida-java-bridge';

// ── 전송 전 노이즈 사전 필터 ──
// 여기서 거르는 건 "명백히 의미 없는 값"뿐이고, 최종 분류/세션 단위 통계는 C의 message_parser.py 몫.
var MIN_STRING_BUILDER_LEN = 3;   // 이하는 프레임워크 내부 append 노이즈로 보고 스킵
var MIN_BASE64_DECODED_LEN = 5;   // 디코딩 결과가 이하 바이트면 의미 없는 플래그값으로 보고 스킵
var MAX_CIPHER_PAYLOAD_LEN = 51200; // 50KB 넘으면 이미지/파일 캐싱 등으로 보고 스킵

var lastValueByHookType = {};

function isDuplicate(hookType, rawValue) {
    if (lastValueByHookType[hookType] === rawValue) {
        return true;
    }
    lastValueByHookType[hookType] = rawValue;
    return false;
}

// ── caller(호출자) 정보 ──
// C와 합의 후 추가. schema.py의 extra 계약 변경 (extra에 caller_class/caller_method 공통 추가).
// hookedClassName(예: "java.lang.StringBuilder") 자신의 프레임은 건너뛰고,
// 스택트레이스에서 처음으로 나오는 "바깥" 프레임을 실제 호출자로 본다.
//
// StringBuilder.append()는 JDK 내부적으로 AbstractStringBuilder.append()에 위임하기 때문에,
// hookedClassName만 건너뛰면 실제 호출자가 아니라 이 내부 위임 프레임이 caller로 잡힌다
// (calendar 앱 실측: string_builder 이벤트 117개 중 111개가 이 프레임으로 오염됨).
// 그래서 이런 JDK 내부 위임 클래스도 같이 건너뛴다.
var INTERNAL_DELEGATE_CLASSES = ["java.lang.AbstractStringBuilder"];

function getCallerInfo(hookedClassName) {
    try {
        var Exception = Java.use("java.lang.Exception");
        var stackTrace = Exception.$new().getStackTrace();
        for (var i = 0; i < stackTrace.length; i++) {
            var frameClass = stackTrace[i].getClassName();
            if (frameClass === "java.lang.Exception" ||
                frameClass === hookedClassName ||
                INTERNAL_DELEGATE_CLASSES.indexOf(frameClass) !== -1) {
                continue;
            }
            return {
                caller_class: frameClass,
                caller_method: stackTrace[i].getMethodName()
            };
        }
    } catch (e) {
        console.log("[hooks.js] caller 정보 추출 실패: " + e);
    }
    return { caller_class: "unknown", caller_method: "unknown" };
}

function sendEvent(hookType, className, methodName, rawValue, extra) {
    var callerInfo = getCallerInfo(className);
    send({
        hook_type: hookType,
        timestamp: new Date().toISOString(),
        class_name: className,
        method_name: methodName,
        raw_value: rawValue,
        extra: Object.assign({}, extra, callerInfo),
        thread_id: Process.getCurrentThreadId()
    });
}

function bytesToBase64(bytes) {
    return Java.use("android.util.Base64").encodeToString(bytes, 0 /* NO_WRAP */);
}

function hookStringBuilder() {
    var StringBuilder = Java.use("java.lang.StringBuilder");
    var append = StringBuilder.append.overload("java.lang.String");

    append.implementation = function (str) {
        var result = append.call(this, str);
        try {
            if (str.length > MIN_STRING_BUILDER_LEN && !isDuplicate("string_builder", str)) {
                sendEvent("string_builder", "java.lang.StringBuilder", "append", str, {});
            }
        } catch (e) {
            console.log("[hooks.js] string_builder send 실패: " + e);
        }
        return result;
    };
}

function hookBase64() {
    var Base64 = Java.use("android.util.Base64");

    var decode = Base64.decode.overload("java.lang.String", "int");
    decode.implementation = function (input, flags) {
        var result = decode.call(this, input, flags);
        try {
            if (result.length > MIN_BASE64_DECODED_LEN) {
                var decoded = bytesToBase64(result);
                if (!isDuplicate("base64_decode", decoded)) {
                    sendEvent("base64", "android.util.Base64", "decode", decoded, { direction: "decode" });
                }
            }
        } catch (e) {
            console.log("[hooks.js] base64 decode send 실패: " + e);
        }
        return result;
    };

    var encodeToString = Base64.encodeToString.overload("[B", "int");
    encodeToString.implementation = function (input, flags) {
        var result = encodeToString.call(this, input, flags);
        try {
            if (result.length > MIN_BASE64_DECODED_LEN && !isDuplicate("base64_encode", result)) {
                sendEvent("base64", "android.util.Base64", "encodeToString", result, { direction: "encode" });
            }
        } catch (e) {
            console.log("[hooks.js] base64 encode send 실패: " + e);
        }
        return result;
    };
}

function hookCipher() {
    var Cipher = Java.use("javax.crypto.Cipher");
    var ENCRYPT_MODE = 1; // javax.crypto.Cipher.ENCRYPT_MODE
    var doFinal = Cipher.doFinal.overload("[B");

    doFinal.implementation = function (input) {
        var result = doFinal.call(this, input);
        try {
            if (result.length <= MAX_CIPHER_PAYLOAD_LEN) {
                var algorithm = this.getAlgorithm();
                var mode = this.getOpmode() === ENCRYPT_MODE ? "encrypt" : "decrypt";
                var decoded = bytesToBase64(result);
                if (!isDuplicate("cipher", decoded)) {
                    sendEvent("cipher", "javax.crypto.Cipher", "doFinal", decoded, {
                        algorithm: algorithm,
                        mode: mode
                    });
                }
            }
        } catch (e) {
            console.log("[hooks.js] cipher send 실패: " + e);
        }
        return result;
    };
}

// ── 정보탈취 행위 후킹 (source / sink) ──
//
// 배경(8주차 실샘플): 게임으로 위장한 정보탈취 앱은 연락처·기기ID를 읽어 밖으로
// 보낸다. 그런데 위의 세 후킹(string_builder/base64/cipher)은 "데이터를 변형·은닉하는"
// 지점만 잡아서, 훔친 값을 그대로 소켓으로 보내면 이벤트가 0건이 된다 — 동적 모듈이
// "관측 없음"으로 통째로 빠지고, 파이프라인이 정적 전용으로 퇴화한다.
// 그래서 "무엇을 읽었나(source)"와 "어디로 보냈나(sink)"를 직접 건다.
//
// sink는 목적지 문자열을 그대로 남기므로, 학습용 샘플이 루프백(127.0.0.1)으로
// 보내는 경우도 network_send 이벤트로 잡힌다(공인망 C&C도 동일하게 잡힘).
//
// 주의: 이 API들은 안드로이드 버전/제조사에 따라 시그니처가 갈린다. 각 후킹을
// try/catch로 감싸, 한 API가 없어도(overload 불일치 등) 나머지 후킹은 계속
// 등록되게 한다(기존 세 후킹까지 같이 죽는 것을 막는다).

// 민감정보 종류 라벨. 실제 값(IMEI·전화번호 등 PII)은 로깅하지 않는다 — "무엇을"
// 읽었는지만 남겨 조합(정보탈취 패턴) 판단의 근거로 쓴다.
function hookSensitiveRead() {
    var jobs = [
        { cls: "android.telephony.TelephonyManager", methods: {
            getDeviceId: "device_id", getImei: "imei", getSubscriberId: "subscriber_id",
            getSimSerialNumber: "sim_serial", getLine1Number: "phone_number" } },
        { cls: "android.location.LocationManager", methods: {
            getLastKnownLocation: "location" } }
    ];
    jobs.forEach(function (job) {
        var Clazz;
        try { Clazz = Java.use(job.cls); } catch (e) { return; }  // 이 기기에 클래스 없음
        Object.keys(job.methods).forEach(function (m) {
            var dataType = job.methods[m];
            try {
                Clazz[m].overloads.forEach(function (ov) {
                    ov.implementation = function () {
                        var result = ov.apply(this, arguments);
                        try {
                            if (!isDuplicate("sensitive_read", dataType)) {
                                sendEvent("sensitive_read", job.cls, m, dataType, { data_type: dataType });
                            }
                        } catch (e) { console.log("[hooks.js] sensitive_read send 실패: " + e); }
                        return result;
                    };
                });
            } catch (e) { /* 이 메서드는 이 기기에 없음 — 조용히 건너뛴다 */ }
        });
    });
}

// 연락처/SMS/통화기록은 ContentResolver.query의 Uri로 구분한다. 그 외 content
// 조회(설정·미디어 등)는 정상 앱도 끝없이 호출하므로 노이즈로 보고 무시한다.
function classifyContentUri(uri) {
    if (!uri) return null;
    if (uri.indexOf("contacts") !== -1) return "contacts";
    if (uri.indexOf("sms") !== -1 || uri.indexOf("mms") !== -1) return "sms";
    if (uri.indexOf("call_log") !== -1) return "call_log";
    return null;
}

function hookContentResolver() {
    var CR;
    try { CR = Java.use("android.content.ContentResolver"); } catch (e) { return; }
    try {
        CR.query.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var result = ov.apply(this, arguments);
                try {
                    var uri = (arguments.length > 0 && arguments[0]) ? arguments[0].toString() : "";
                    var dataType = classifyContentUri(uri);
                    if (dataType && !isDuplicate("sensitive_read", dataType)) {
                        sendEvent("sensitive_read", "android.content.ContentResolver", "query",
                                  dataType, { data_type: dataType, uri: uri });
                    }
                } catch (e) { console.log("[hooks.js] contentresolver send 실패: " + e); }
                return result;
            };
        });
    } catch (e) { /* query overload 불일치 — 건너뜀 */ }
}

// 목적지 host를 루프백/사설/공인으로 분류. 루프백은 학습용 샘플의 표식이고,
// 공인망 목적지는 실제 C&C 후보다(화면·스코어링에서 구분해 쓸 수 있게 남긴다).
function destType(host) {
    if (!host) return "unknown";
    if (host === "localhost" || host === "::1" || host.indexOf("127.") === 0) return "loopback";
    if (host.indexOf("10.") === 0 || host.indexOf("192.168.") === 0) return "private";
    var m = /^172\.(\d+)\./.exec(host);
    if (m && (+m[1]) >= 16 && (+m[1]) <= 31) return "private";
    return "public";
}

function hostOf(urlStr) {
    try {
        var m = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/([^\/:?#]+)/.exec(urlStr);
        return m ? m[1] : "";
    } catch (e) { return ""; }
}

function emitNetworkSend(cls, method, dest, host) {
    if (isDuplicate("network_send", dest)) return;
    sendEvent("network_send", cls, method, dest, { destination: dest, host: host, dest_type: destType(host) });
}

function hookNetworkSend() {
    // 1) java.net.URL.openConnection() — HttpURLConnection 경로. URL 전체가 목적지.
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.overloads.forEach(function (ov) {
            ov.implementation = function () {
                var result = ov.apply(this, arguments);
                try {
                    var url = this.toString();
                    emitNetworkSend("java.net.URL", "openConnection", url, hostOf(url));
                } catch (e) { console.log("[hooks.js] url send 실패: " + e); }
                return result;
            };
        });
    } catch (e) { /* URL 후킹 실패 — 건너뜀 */ }

    // 2) java.net.Socket(String host, int port) — 원시 소켓. 루프백 직결도 여기서 잡힘.
    try {
        var Socket = Java.use("java.net.Socket");
        var ctor = Socket.$init.overload("java.lang.String", "int");
        ctor.implementation = function (host, port) {
            try {
                emitNetworkSend("java.net.Socket", "<init>", host + ":" + port, host);
            } catch (e) { console.log("[hooks.js] socket send 실패: " + e); }
            return ctor.call(this, host, port);
        };
    } catch (e) { /* Socket(String,int) overload 없음 — 건너뜀 */ }
}

// custom_xor 후킹은 4일차 몫 (표준 API로 안 잡히는 패턴이라 대상 앱 리버싱 후 추가 예정)
Java.perform(function () {
        hookStringBuilder();
        hookBase64();
        hookCipher();
        hookSensitiveRead();
        hookContentResolver();
        hookNetworkSend();
        console.log("[hooks.js] string_builder / base64 / cipher / sensitive_read / network_send 후킹 등록 완료");
    });