// src/utils/crypto.js
// 描述：包含所有加密、解密、哈希、签名相关的函数。

// --- 动态令牌签名与验证 (HMAC-SHA256) ---
const TOKEN_ALGORITHM = { name: 'HMAC', hash: 'SHA-256' };
const DEFAULT_TOKEN_TTL_SECONDS = 30; // 动态令牌默认有效期

/**
 * 为动态令牌生成签名。
 * payload -> JSON.stringify -> UTF8 Encode -> Base64URL Encode (payloadB64Url)
 * signatureInput = payloadB64Url (或者更标准的 headerB64Url + "." + payloadB64Url)
 * signature = HMAC(secret, signatureInput) -> Base64URL Encode (signatureB64Url)
 * token = payloadB64Url + "." + signatureB64Url
 * @param {object} payload - 要签名的令牌负载 (e.g., { username, exp, iat }).
 * @param {string} secretString - 用于签名的密钥字符串 (来自 env.DYNAMIC_TOKEN_SECRET).
 * @returns {Promise<string|null>} "payloadB64Url.signatureB64Url" 格式的令牌，或 null 如果失败.
 */
export async function signDynamicToken(payload, secretString) {
    if (!payload || !secretString) {
        console.error("signDynamicToken: Payload or secret missing.");
        return null;
    }
    try {
        const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(secretString),
            TOKEN_ALGORITHM,
            false,
            ['sign']
        );
        
        // 准备 payload，确保有 iat 和 exp
        const issuedAt = payload.iat || Math.floor(Date.now() / 1000);
        const expiresAt = payload.exp || (issuedAt + (payload.ttl_seconds || DEFAULT_TOKEN_TTL_SECONDS));
        const finalPayload = { ...payload, iat: issuedAt, exp: expiresAt };
        delete finalPayload.ttl_seconds; // 移除临时的 ttl

        const payloadString = JSON.stringify(finalPayload);
        const payloadB64Url = arrayBufferToBase64Url(new TextEncoder().encode(payloadString));

        // 签名部分：通常 JWT 会签名 headerB64Url + "." + payloadB64Url
        // 为简化，我们这里可以只签名 payloadB64Url，或者签名原始的 payloadString 都可以
        // 重要的是验证时使用相同的数据源。
        // 我们选择签名原始的 payloadString，然后将原始 payloadString 进行 Base64URL 编码作为令牌的第一部分。
        const dataToSign = new TextEncoder().encode(payloadString); 
        const signatureBuffer = await crypto.subtle.sign(TOKEN_ALGORITHM.name, key, dataToSign);
        const signatureB64Url = arrayBufferToBase64Url(signatureBuffer);

        return `${payloadB64Url}.${signatureB64Url}`;
    } catch (e) {
        console.error("Error signing token:", e.message, e.stack);
        return null;
    }
}

/**
 * 验证动态令牌的签名和内容。
 * 期望 tokenString 是 "payloadB64Url.signatureB64Url" 格式.
 * @param {string} tokenString - "payloadB64Url.signatureB64Url".
 * @param {string} secretString - 用于验证的密钥字符串.
 * @returns {Promise<{valid: boolean, payload?: object, error?: string}>} 验证结果.
 */
export async function verifyAndDecodeDynamicToken(tokenString, secretString) {
    if (!tokenString || !secretString) return { valid: false, error: "Token or secret missing" };
    
    const parts = tokenString.split('.');
    if (parts.length !== 2) return { valid: false, error: "Invalid token format (expected payload.signature)" };

    const [payloadB64Url, signatureB64Url] = parts;

    try {
        const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(secretString),
            TOKEN_ALGORITHM,
            false,
            ['verify']
        );
        
        const payloadString = base64UrlDecodeToString(payloadB64Url); // 解码得到原始 JSON 字符串
        if (!payloadString) return { valid: false, error: "Invalid payload encoding" };

        const payloadObject = JSON.parse(payloadString);
        
        // 用于验证签名的原始数据 (与签名时使用的数据一致)
        const dataThatWasSigned = new TextEncoder().encode(payloadString); 
        const signatureBuffer = base64UrlToArrayBuffer(signatureB64Url);
        
        const isValidSignature = await crypto.subtle.verify(TOKEN_ALGORITHM.name, key, signatureBuffer, dataThatWasSigned);

        if (!isValidSignature) return { valid: false, error: "Invalid signature" };

        // 检查有效期 (exp) 和签发时间 (iat)
        const currentTime = Math.floor(Date.now() / 1000);
        if (payloadObject.exp && payloadObject.exp < currentTime) {
            return { valid: false, error: "Token expired", payload: payloadObject };
        }
        // 允许iat最多比当前时间晚一点点，以处理极小的时钟不同步
        if (payloadObject.iat && payloadObject.iat > currentTime + 5) { 
            return { valid: false, error: "Token not yet valid (iat in future)", payload: payloadObject };
        }

        return { valid: true, payload: payloadObject };

    } catch (e) {
        console.error("Error verifying token:", e.message, e.stack);
        // JSON.parse 可能会失败
        return { valid: false, error: `Token verification/parsing error: ${e.message}` };
    }
}

// Base64 URL safe encoding/decoding (确保这些辅助函数存在且正确)
function arrayBufferToBase64Url(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function base64UrlToArrayBuffer(base64url) {
    base64url = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64url.length % 4) {
        base64url += '=';
    }
    return base64ToArrayBuffer(base64url); // 调用你已有的 base64ToArrayBuffer
}

// 这个函数用于将 Base64URL 安全字符串解码为原始字符串
function base64UrlDecodeToString(base64url) {
    try {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        // atob -> decode URI component for UTF-8
        return decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    } catch(e) {
        console.error("base64UrlDecodeToString failed:", e.message);
        return null;
    }
}

// --- 哈希 ---
/**
 * 计算 ArrayBuffer 内容的 SHA-256 哈希值。
 * @param {ArrayBuffer} arrayBuffer - 文件的 ArrayBuffer 内容。
 * @returns {Promise<string>} SHA-256 哈希值的十六进制字符串。
 */
export async function calculateSha256(arrayBuffer) {
    if (!arrayBuffer || arrayBuffer.byteLength === 0) {
        throw new Error("Cannot hash empty or null ArrayBuffer.");
    }
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}


/**
 * 为动态令牌生成签名。
 * @param {object} payload - 要签名的令牌负载 (e.g., { username, exp, iat }).
 * @param {string} secretString - 用于签名的密钥字符串 (来自 env.DYNAMIC_TOKEN_SECRET).
 * @returns {Promise<string|null>} Base64 URL 编码的签名，或 null 如果失败.
 */
export async function signDynamicToken(payload, secretString) {
    if (!payload || !secretString) return null;
    try {
        const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(secretString),
            TOKEN_ALGORITHM,
            false,
            ['sign']
        );
        const dataToSign = new TextEncoder().encode(JSON.stringify(payload));
        const signatureBuffer = await crypto.subtle.sign(TOKEN_ALGORITHM.name, key, dataToSign);
        return arrayBufferToBase64Url(signatureBuffer);
    } catch (e) {
        console.error("Error signing token:", e.message);
        return null;
    }
}

/**
 * 验证动态令牌的签名和内容。
 * @param {string} signedTokenString - 格式 "payloadB64Url.signatureB64Url".
 * @param {string} secretString - 用于验证的密钥字符串.
 * @returns {Promise<{valid: boolean, payload?: object, error?: string}>} 验证结果.
 */
export async function verifyAndDecodeDynamicToken(signedTokenString, secretString) {
    if (!signedTokenString || !secretString) return { valid: false, error: "Token or secret missing" };
    
    const parts = signedTokenString.split('.');
    if (parts.length !== 2) return { valid: false, error: "Invalid token format" };

    const [payloadB64Url, signatureB64Url] = parts;

    try {
        const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(secretString),
            TOKEN_ALGORITHM,
            false,
            ['verify']
        );
        const dataToVerify = new TextEncoder().encode(base64UrlDecode(payloadB64Url)); // 实际签名的是原始 payload 字符串，这里为了方便，我们直接对解码后的 payload 字符串进行编码再验证。理想情况是签名原始的 payload 字符串。
                                                                                      // 但更常见的是直接签名原始的 payloadB64Url 字符串。
                                                                                      // 为了简单，我们这里假设签名的是 JSON 字符串化的 payload。
        // 重要的修正：实际签名的是原始的 payloadB64Url 字符串，或者一个包含它的结构。
        // 假设签名的是 payloadB64Url 本身，或者说是令牌的第一部分
        const dataThatWasSigned = new TextEncoder().encode(payloadB64Url); // 或者如 JWT，是 header.payload 拼接

        const signatureBuffer = base64UrlToArrayBuffer(signatureB64Url);
        
        // 让我们调整为签名整个 token 的第一部分 (payloadB64Url)
        // 在 signDynamicToken 中，我们应该返回 `payloadB64Url + '.' + signatureB64Url`
        // 而不是对 JSON.stringify(payload) 签名。
        // 为了当前结构兼容，我们先假设签名的是 JSON.stringify(payload)
        // **更正签名和验证逻辑以匹配常见 JWT 结构（头部。载荷。签名）会更标准**
        // **以下是基于对 JSON.stringify(payload) 签名的验证：**
        const payloadString = base64UrlDecode(payloadB64Url); // 解码得到原始 JSON 字符串
        const payloadObject = JSON.parse(payloadString);
        const dataToVerifyAgain = new TextEncoder().encode(payloadString); // 用于验证签名的原始数据

        const isValid = await crypto.subtle.verify(TOKEN_ALGORITHM.name, key, signatureBuffer, dataToVerifyAgain);

        if (!isValid) return { valid: false, error: "Invalid signature" };

        // 检查有效期 (exp) 和签发时间 (iat)
        const currentTime = Math.floor(Date.now() / 1000);
        if (payloadObject.exp && payloadObject.exp < currentTime) {
            return { valid: false, error: "Token expired", payload: payloadObject };
        }
        if (payloadObject.iat && payloadObject.iat > currentTime + 60) { // 允许一定的时钟漂移 (e.g., 60s into the future)
            return { valid: false, error: "Token not yet valid (iat in future)", payload: payloadObject };
        }

        return { valid: true, payload: payloadObject };

    } catch (e) {
        console.error("Error verifying token:", e.message);
        return { valid: false, error: `Verification error: ${e.message}` };
    }
}


// --- 文件内容对称加密/解密 (AES-GCM) ---
const AES_GCM_ALGORITHM = { name: 'AES-GCM', length: 256 }; // 256-bit key
const AES_GCM_IV_LENGTH_BYTES = 12; // 96 bits is recommended for GCM

/**
 * 生成一个随机的 AES 密钥 (ArrayBuffer).
 * @returns {Promise<CryptoKey>}
 */
export async function generateAesGcmKey() {
    return crypto.subtle.generateKey(AES_GCM_ALGORITHM, true, ['encrypt', 'decrypt']);
}
/**
 * 将 CryptoKey 导出为原始 ArrayBuffer.
 * @param {CryptoKey} cryptoKey
 * @returns {Promise<ArrayBuffer>}
 */
export async function exportCryptoKeyToRaw(cryptoKey) {
    return crypto.subtle.exportKey('raw', cryptoKey);
}
/**
 * 从原始 ArrayBuffer 导入 CryptoKey.
 * @param {ArrayBuffer} rawKeyBuffer
 * @param {Array<string>} usages - e.g., ['encrypt', 'decrypt']
 * @returns {Promise<CryptoKey>}
 */
export async function importRawToCryptoKey(rawKeyBuffer, usages = ['encrypt', 'decrypt']) {
    return crypto.subtle.importKey('raw', rawKeyBuffer, AES_GCM_ALGORITHM, true, usages);
}


/**
 * 加密数据 (ArrayBuffer) 使用 AES-GCM.
 * @param {ArrayBuffer} plainDataBuffer - 要加密的明文数据.
 * @param {CryptoKey} cryptoKey - AES-GCM 密钥 (CryptoKey object).
 * @returns {Promise<{ciphertext: ArrayBuffer, iv: Uint8Array}>} - 加密后的数据和 IV.
 */
export async function encryptDataAesGcm(plainDataBuffer, cryptoKey) {
    const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH_BYTES));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        cryptoKey,
        plainDataBuffer
    );
    return { ciphertext, iv };
}

/**
 * 解密数据 (ArrayBuffer) 使用 AES-GCM.
 * @param {ArrayBuffer} ciphertextBuffer - 密文数据.
 * @param {Uint8Array} iv - 初始化向量.
 * @param {CryptoKey} cryptoKey - AES-GCM 密钥 (CryptoKey object).
 * @returns {Promise<ArrayBuffer|null>} - 解密后的明文数据，或 null 如果解密失败.
 */
export async function decryptDataAesGcm(ciphertextBuffer, iv, cryptoKey) {
    try {
        return await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            ciphertextBuffer
        );
    } catch (e) {
        console.error("AES-GCM Decryption failed:", e.message);
        return null; // 解密失败
    }
}

// --- 主加密密钥 (MEK) 相关操作 ---
/**
 * 使用 MEK (作为 CryptoKey) 加密用户密钥 (ArrayBuffer).
 * MEK 本身应该从 env secret 中获取并导入为 CryptoKey.
 * @param {ArrayBuffer} userKeyBuffer - 用户密钥的 ArrayBuffer.
 * @param {CryptoKey} mekCryptoKey - 主加密密钥 (AES-GCM CryptoKey).
 * @returns {Promise<{encryptedUserKey: ArrayBuffer, iv: Uint8Array}|null>}
 */
export async function encryptUserKeyWithMEK(userKeyBuffer, mekCryptoKey) {
    try {
        return await encryptDataAesGcm(userKeyBuffer, mekCryptoKey);
    } catch(e) {
        console.error("Failed to encrypt user key with MEK:", e.message);
        return null;
    }
}

/**
 * 使用 MEK (作为 CryptoKey) 解密用户密钥.
 * @param {ArrayBuffer} encryptedUserKeyBuffer - 已加密的用户密钥.
 * @param {Uint8Array} iv - 加密时使用的 IV.
 * @param {CryptoKey} mekCryptoKey - 主加密密钥 (AES-GCM CryptoKey).
 * @returns {Promise<ArrayBuffer|null>} 解密后的用户密钥 ArrayBuffer.
 */
export async function decryptUserKeyWithMEK(encryptedUserKeyBuffer, iv, mekCryptoKey) {
     try {
        return await decryptDataAesGcm(encryptedUserKeyBuffer, iv, mekCryptoKey);
    } catch(e) {
        console.error("Failed to decrypt user key with MEK:", e.message);
        return null;
    }
}


// --- Base64 辅助函数 ---
export function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

export function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Base64 URL safe encoding/decoding
function arrayBufferToBase64Url(buffer) {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function base64UrlToArrayBuffer(base64url) {
    base64url = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64url.length % 4) {
        base64url += '=';
    }
    return base64ToArrayBuffer(base64url);
}

function base64UrlDecode(base64url) { // Decodes to string
    try {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        return decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    } catch(e) {
        console.error("base64UrlDecode failed:", e.message);
        return ""; // Return empty string or throw, depending on desired error handling
    }
}