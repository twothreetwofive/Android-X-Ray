// dynamic_analyzer/hooks.js
// B(소정) 작성, 4주차 과제. C의 schema.py(HookEvent) 포맷에 맞춰 send() 한다.
// 필드를 바꿔야 하면 C(은아)와 먼저 맞추고 schema.py부터 고칠 것.
//
// 단독 테스트 (2일차, Python/frida_controller.py 없이 가능):
//   frida -U -f <패키지명> -l hooks.js

function sendEvent(hookType, className, methodName, rawValue, extra) {
    send({
        hook_type: hookType,
        timestamp: new Date().toISOString(),
        class_name: className,
        method_name: methodName,
        raw_value: rawValue,
        extra: extra || {},
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
            sendEvent("string_builder", "java.lang.StringBuilder", "append", str, {});
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
            sendEvent("base64", "android.util.Base64", "decode", bytesToBase64(result), { direction: "decode" });
        } catch (e) {
            console.log("[hooks.js] base64 decode send 실패: " + e);
        }
        return result;
    };

    var encodeToString = Base64.encodeToString.overload("[B", "int");
    encodeToString.implementation = function (input, flags) {
        var result = encodeToString.call(this, input, flags);
        try {
            sendEvent("base64", "android.util.Base64", "encodeToString", result, { direction: "encode" });
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
            var algorithm = this.getAlgorithm();
            var mode = this.getOpmode() === ENCRYPT_MODE ? "encrypt" : "decrypt";
            sendEvent("cipher", "javax.crypto.Cipher", "doFinal", bytesToBase64(result), {
                algorithm: algorithm,
                mode: mode
            });
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
