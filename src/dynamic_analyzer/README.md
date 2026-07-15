hooks.js에서 이 형식으로 send() 해보시고 이상하면 말씀해주세요 - 은아: 

    send({
        hook_type: "cipher",  // "string_builder" | "base64" | "cipher" | "custom_xor"
        timestamp: new Date().toISOString(),
        class_name: "javax.crypto.Cipher",
        method_name: "doFinal",
        raw_value: "...",  // 바이트면 Base64 인코딩해서 문자열로
        extra: { algorithm: "AES/CBC/PKCS5Padding", mode: "decrypt" },
        thread_id: Process.getCurrentThreadId()
    });

주의: frida가 한 번 더 감싸서 Python에서는 message["payload"]로 받게 됨 (C가 처리함)

+) 이거 JS임!! Python 아니에요 hook.js에서 사용하는 함수임 