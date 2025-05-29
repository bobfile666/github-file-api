// src/utils/crypto.js
// 描述：包含所有加密、解密、哈希、签名相关的函数。

// --- 哈希 ---
/**
 * 计算 ArrayBuffer 内容的 SHA-256 哈希值。
 * @param {ArrayBuffer} arrayBuffer - 文件的 ArrayBuffer 内容。
 * @returns {Promise<string>} SHA-256 哈希值的十六进制字符串。
 * @throws {Error} 如果 arrayBuffer 为空或 null。
 */
export async function calculateSha256(arrayBuffer) {
    if (!arrayBuffer || arrayBuffer.byteLength === 0) {
        throw new Error("Cannot hash empty or null ArrayBuffer.");
    }
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- 动态令牌签名与验证 (HMAC-SHA256) ---
const TOKEN_ALGORITHM = { name: 'HMAC', hash: 'SHA-256' };
const DEFAULT_TOKEN_TTL_SECONDS = 30; // 动态令牌默认有效期 (秒)

/**
 * 为动态令牌生成签名字符串。
 * 令牌格式："payloadB64Url.signatureB64Url"
 * 签名的是序列化后的 payload (JSON string)。
 * @param {object} payloadInput - 要签名的令牌负载 (e.g., { username }).
 * @param {string} secretString - 用于签名的密钥字符串 (来自 env.DYNAMIC_TOKEN_SECRET).
 * @returns {Promise<string|null>} "payloadB64Url.signatureB64Url" 格式的令牌，或 null 如果失败.
 */
export async function signDynamicToken(payloadInput, secretString) {
    if (!payloadInput || typeof payloadInput !== 'object' || !secretString) {
        console.error("signDynamicToken: Invalid payload or secret missing.");
        return null;
    }
    try {
        const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(secretString),
            TOKEN_ALGORITHM,
            false, // not extractable
            ['sign']
        );
        
        const issuedAt = payloadInput.iat || Math.floor(Date.now() / 1000);
        const expiresAt = payloadInput.exp || (issuedAt + (payloadInput.ttl_seconds || DEFAULT_TOKEN_TTL_SECONDS));
        
        // 确保最终的 payload 包含 iat 和 exp，并移除临时的 ttl_seconds
        const finalPayloadToSerialize = { ...payloadInput, iat: issuedAt, exp: expiresAt };
        delete finalPayloadToSerialize.ttl_seconds;

        const payloadString = JSON.stringify(finalPayloadToSerialize);
        const payloadB64Url = arrayBufferToBase64Url(new TextEncoder().encode(payloadString));

        // 签名的是原始的 payloadString (UTF-8 encoded)
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
    if (!tokenString || typeof tokenString !== 'string' || !secretString) {
        return { valid: false, error: "Token or secret missing or invalid type" };
    }
    
    const parts = tokenString.split('.');
    if (parts.length !== 2) {
        return { valid: false, error: "Invalid token format (expected payload.signature)" };
    }

    const [payloadB64Url, signatureB64Url] = parts;

    try {
        const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(secretString),
            TOKEN_ALGORITHM,
            false, // not extractable
            ['verify']
        );
        
        const payloadString = base64UrlDecodeToString(payloadB64Url);
        if (payloadString === null) { // base64UrlDecodeToString 返回 null 表示解码失败
            return { valid: false, error: "Invalid payload encoding in token" };
        }

        const payloadObject = JSON.parse(payloadString); // 可能抛出 SyntaxError
        
        // 用于验证签名的原始数据 (与签名时使用的数据一致：即原始的 payloadString)
        const dataThatWasSigned = new TextEncoder().encode(payloadString); 
        const signatureBuffer = base64UrlToArrayBuffer(signatureB64Url);
        
        const isValidSignature = await crypto.subtle.verify(TOKEN_ALGORITHM.name, key, signatureBuffer, dataThatWasSigned);

        if (!isValidSignature) {
            return { valid: false, error: "Invalid signature" };
        }

        // 检查有效期 (exp) 和签发时间 (iat)
        const currentTime = Math.floor(Date.now() / 1000);
        if (typeof payloadObject.exp !== 'number' || payloadObject.exp < currentTime) {
            return { valid: false, error: "Token expired", payload: payloadObject };
        }
        // 允许iat最多比当前时间晚一点点 (例如5秒)，以处理极小的时钟不同步
        if (typeof payloadObject.iat !== 'number' || payloadObject.iat > currentTime + 5) { 
            return { valid: false, error: "Token not yet valid (iat in future or invalid)", payload: payloadObject };
        }

        return { valid: true, payload: payloadObject };

    } catch (e) { // 捕获 JSON.parse 错误或其他意外错误
        console.error("Error verifying token:", e.message, e.stack);
        return { valid: false, error: `Token verification/parsing error: ${e.message}` };
    }
}


// --- 文件内容对称加密/解密 (AES-GCM) ---
const AES_GCM_ALGORITHM_NAME = 'AES-GCM';
const AES_GCM_KEY_LENGTH_BITS = 256; // 256-bit key
export const AES_GCM_IV_LENGTH_BYTES = 12; // 96 bits (12 bytes) is recommended for GCM

/**
 * 生成一个随机的 AES-GCM 密钥 (CryptoKey object).
 * @returns {Promise<CryptoKey>}
 */
export async function generateAesGcmKey() {
    return crypto.subtle.generateKey(
        { name: AES_GCM_ALGORITHM_NAME, length: AES_GCM_KEY_LENGTH_BITS },
        true, // extractable
        ['encrypt', 'decrypt']
    );
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
 * 从原始 ArrayBuffer 导入 AES-GCM CryptoKey.
 * @param {ArrayBuffer} rawKeyBuffer - 原始密钥数据 (应为 32 字节 for AES-256).
 * @param {Array<KeyUsage>} [usages=['encrypt', 'decrypt']] - 密钥用途.
 * @returns {Promise<CryptoKey>}
 */
export async function importRawToAesGcmCryptoKey(rawKeyBuffer, usages = ['encrypt', 'decrypt']) {
    // 功能：将原始密钥字节数组导入为可用于 AES-GCM 操作的 CryptoKey 对象。
    // 参数：rawKeyBuffer (ArrayBuffer), usages (Array<string>)
    // 返回：Promise<CryptoKey>
    if (!rawKeyBuffer || rawKeyBuffer.byteLength !== AES_GCM_KEY_LENGTH_BITS / 8) { // AES_GCM_KEY_LENGTH_BITS 应定义为 256
        throw new Error(`Invalid key length for AES-GCM ${AES_GCM_KEY_LENGTH_BITS}-bit. Expected ${AES_GCM_KEY_LENGTH_BITS / 8} bytes, got ${rawKeyBuffer ? rawKeyBuffer.byteLength : 'null'}.`);
    }
    return crypto.subtle.importKey(
        'raw', 
        rawKeyBuffer, 
        { name: AES_GCM_ALGORITHM_NAME, length: AES_GCM_KEY_LENGTH_BITS }, 
        true, 
        usages
    );
}


/**
 * 加密数据 (ArrayBuffer) 使用 AES-GCM.
 * @param {ArrayBuffer} plainDataBuffer - 要加密的明文数据.
 * @param {CryptoKey} cryptoKey - AES-GCM 密钥 (CryptoKey object).
 * @returns {Promise<{ciphertext: ArrayBuffer, iv: Uint8Array}>} - 加密后的数据和 IV.
 * @throws {Error} 如果加密失败。
 */
export async function encryptDataAesGcm(plainDataBuffer, cryptoKey) {
    const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_LENGTH_BYTES));
    const ciphertext = await crypto.subtle.encrypt(
        { name: AES_GCM_ALGORITHM_NAME, iv: iv },
        cryptoKey,
        plainDataBuffer
    );
    return { ciphertext, iv };
}

/**
 * 解密数据 (ArrayBuffer) 使用 AES-GCM.
 * @param {ArrayBuffer} ciphertextBuffer - 密文数据.
 * @param {Uint8Array} iv - 初始化向量 (应为 12 字节).
 * @param {CryptoKey} cryptoKey - AES-GCM 密钥 (CryptoKey object).
 * @returns {Promise<ArrayBuffer|null>} - 解密后的明文数据，或 null 如果解密失败.
 */
export async function decryptDataAesGcm(ciphertextBuffer, iv, cryptoKey) {
    if (iv.byteLength !== AES_GCM_IV_LENGTH_BYTES) {
        console.error("decryptDataAesGcm: Invalid IV length.");
        return null;
    }
    try {
        return await crypto.subtle.decrypt(
            { name: AES_GCM_ALGORITHM_NAME, iv: iv },
            cryptoKey,
            ciphertextBuffer
        );
    } catch (e) {
        // 解密失败通常意味着密钥错误、IV 错误或数据被篡改
        console.error("AES-GCM Decryption failed (likely key/IV mismatch or data corruption):", e.message);
        return null;
    }
}

// --- 主加密密钥 (MEK) 相关操作 (使用 AES-GCM 加密用户密钥) ---
/**
 * 使用 MEK (作为 CryptoKey) 加密用户密钥 (ArrayBuffer).
 * MEK 本身应该从 env secret 中获取并导入为 CryptoKey.
 * @param {ArrayBuffer} userKeyBuffer - 用户密钥的 ArrayBuffer.
 * @param {CryptoKey} mekCryptoKey - 主加密密钥 (AES-GCM CryptoKey).
 * @returns {Promise<{encryptedUserKey: ArrayBuffer, iv: Uint8Array}|null>} 加密后的用户密钥和用于此次加密的 IV。
 */
export async function encryptUserKeyWithMEK(userKeyBuffer, mekCryptoKey) {
    try {
        // 使用 encryptDataAesGcm 函数，因为它就是做 AES-GCM 加密的
        const result = await encryptDataAesGcm(userKeyBuffer, mekCryptoKey);
        return { encryptedUserKey: result.ciphertext, iv: result.iv };
    } catch(e) {
        console.error("Failed to encrypt user key with MEK:", e.message, e.stack);
        return null;
    }
}

/**
 * 使用 MEK (作为 CryptoKey) 解密用户密钥.
 * @param {ArrayBuffer} encryptedUserKeyBuffer - 已加密的用户密钥的密文部分.
 * @param {Uint8Array} ivForUserKeyEncryption - 加密该用户密钥时使用的 IV.
 * @param {CryptoKey} mekCryptoKey - 主加密密钥 (AES-GCM CryptoKey).
 * @returns {Promise<ArrayBuffer|null>} 解密后的用户密钥 ArrayBuffer.
 */
export async function decryptUserKeyWithMEK(encryptedUserKeyBuffer, ivForUserKeyEncryption, mekCryptoKey) {
     try {
        // 使用 decryptDataAesGcm 函数
        return await decryptDataAesGcm(encryptedUserKeyBuffer, ivForUserKeyEncryption, mekCryptoKey);
    } catch(e) { // decryptDataAesGcm 内部会捕获并返回 null，这里再包一层以防万一
        console.error("Failed to decrypt user key with MEK (outer catch):", e.message, e.stack);
        return null;
    }
}


// --- Base64 和 Base64URL 辅助函数 ---
/**
 * 将 ArrayBuffer 转换为 Base64 编码的字符串.
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export function arrayBufferToBase64(buffer) {
    // 功能：将 ArrayBuffer 转换为 Base64 编码的字符串。
    // (代码和之前一样)
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * 将 Base64 编码的字符串转换为 ArrayBuffer.
 * @param {string} base64
 * @returns {ArrayBuffer}
 */
export function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * 将 ArrayBuffer 转换为 Base64URL 安全编码的字符串.
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export function arrayBufferToBase64Url(buffer) {
    // 标准的 btoa 输出的 Base64 已经是大部分 URL 安全的了，除了 '+' 和 '/'
    // 并且可能包含 '=' padding.
    return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
        .replace(/\+/g, '-')  // Convert '+' to '-'
        .replace(/\//g, '_')  // Convert '/' to '_'
        .replace(/=+$/, '');  // Remove padding '='
}

/**
 * 将 Base64URL 安全编码的字符串转换为 ArrayBuffer.
 * @param {string} base64url
 * @returns {ArrayBuffer}
 */
export function base64UrlToArrayBuffer(base64url) {
    // Convert Base64URL back to Base64
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if necessary
    while (base64.length % 4) {
        base64 += '=';
    }
    return base64ToArrayBuffer(base64); // Use the existing base64ToArrayBuffer
}

/**
 * 将 Base64URL 安全编码的字符串解码为 UTF-8 字符串.
 * @param {string} base64url
 * @returns {string|null} 解码后的字符串，或 null 如果解码失败.
 */
export function base64UrlDecodeToString(base64url) {
    try {
        let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        // Padding is not strictly necessary for atob in modern browsers if input is valid multiple of 4 after conversion
        // However, atob expects a Base64 string, not Base64URL.
        // The decodeURIComponent handles UTF-8 characters correctly.
        return decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
    } catch (e) {
        console.error("base64UrlDecodeToString failed:", e.message);
        return null; 
    }
}