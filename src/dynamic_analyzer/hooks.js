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

// custom_xor 후킹은 4일차 몫 (표준 API로 안 잡히는 패턴이라 대상 앱 리버싱 후 추가 예정)
Java.perform(function () {
        hookStringBuilder();
        hookBase64();
        hookCipher();
        console.log("[hooks.js] string_builder / base64 / cipher 후킹 등록 완료");
    });