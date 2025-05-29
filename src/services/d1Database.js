// src/services/d1Database.js
// 描述：封装所有与 D1 数据库的交互逻辑。
import { 
    importRawToAesGcmCryptoKey, // <-- 修改导入的函数名
    decryptUserKeyWithMEK, 
    base64ToArrayBuffer, 
    arrayBufferToBase64,
    encryptUserKeyWithMEK // 确保这个也被导入，如果 storeEncryptedUserKey 函数需要它
} from '../utils/crypto.js';

// --- 用户密钥管理 ---
export const DUMMY_USER_KEY_RAW_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
export const DUMMY_USER_KEY_IV_BASE64 = "AAAAAAAAAAAAAAA="; 

export async function getUserSymmetricKey(env, username) {
    // 功能：获取并解密指定用户的对称加密密钥 (CryptoKey object for AES-GCM).
    // 参数：env, username
    // 返回：用户的 CryptoKey 或 null 如果失败。
    if (!env.DB) {
        if (env.LOGGING_ENABLED === "true") console.warn("D1_NOT_CONFIGURED: Using DUMMY_USER_KEY_RAW_BASE64 for testing getUserSymmetricKey.");
        try {
            const rawKeyBuffer = base64ToArrayBuffer(DUMMY_USER_KEY_RAW_BASE64);
            // 使用修正后的导入函数名
            return await importRawToAesGcmCryptoKey(rawKeyBuffer, ['encrypt', 'decrypt']);
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") console.error("Error importing dummy key:", e);
            return null;
        }
    }
    if (!env.MASTER_ENCRYPTION_KEY) {
        if (env.LOGGING_ENABLED === "true") console.error("MASTER_ENCRYPTION_KEY secret is not configured.");
        return null;
    }

    try {
        const stmt = env.DB.prepare("SELECT encryption_key_encrypted FROM Users WHERE user_id = ? AND status = 'active'");
        const result = await stmt.bind(username).first();

        if (!result || !result.encryption_key_encrypted) {
            if (env.LOGGING_ENABLED === "true") console.log(`No active user or encryption key found in D1 for user '${username}'.`);
            return null;
        }

        const parts = result.encryption_key_encrypted.split('.');
        if (parts.length !== 2) {
            if (env.LOGGING_ENABLED === "true") console.error(`Invalid stored encrypted key format for user '${username}'. Expected 'iv.key'.`);
            return null;
        }
        const userKeyIvBase64 = parts[0];
        const encryptedUserKeyBase64 = parts[1];

        const encryptedUserKeyBuffer = base64ToArrayBuffer(encryptedUserKeyBase64);
        const userKeyIv = new Uint8Array(base64ToArrayBuffer(userKeyIvBase64));

        const mekRawBuffer = base64ToArrayBuffer(env.MASTER_ENCRYPTION_KEY);
        // 使用修正后的导入函数名
        const mekCryptoKey = await importRawToAesGcmCryptoKey(mekRawBuffer, ['decrypt']); 

        const decryptedUserKeyBuffer = await decryptUserKeyWithMEK(encryptedUserKeyBuffer, userKeyIv, mekCryptoKey);
        if (!decryptedUserKeyBuffer) {
            if (env.LOGGING_ENABLED === "true") console.error(`Failed to decrypt user key for '${username}' with MEK.`);
            return null;
        }
        // 使用修正后的导入函数名
        return await importRawToAesGcmCryptoKey(decryptedUserKeyBuffer, ['encrypt', 'decrypt']);

    } catch (e) {
        if (env.LOGGING_ENABLED === "true") console.error(`Error getting/decrypting user symmetric key for '${username}':`, e.message, e.stack);
        return null;
    }
}

export async function storeEncryptedUserKey(env, username, rawUserKeyBuffer) {
    // 功能：(辅助/管理功能) 为用户创建记录并存储加密后的密钥。
    // 参数：env, username, rawUserKeyBuffer
    // 返回：true 如果成功，false 如果失败。
    if (!env.DB || !env.MASTER_ENCRYPTION_KEY) {
        if (env.LOGGING_ENABLED === "true") console.error("D1 or MASTER_ENCRYPTION_KEY not configured for storing user key.");
        return false;
    }
    try {
        const mekRawBuffer = base64ToArrayBuffer(env.MASTER_ENCRYPTION_KEY);
        // 使用修正后的导入函数名
        const mekCryptoKey = await importRawToAesGcmCryptoKey(mekRawBuffer, ['encrypt']);

        const encryptionResult = await encryptUserKeyWithMEK(rawUserKeyBuffer, mekCryptoKey);
        if (!encryptionResult) {
            if (env.LOGGING_ENABLED === "true") console.error(`Failed to encrypt user key for ${username} with MEK during storage.`);
            return false;
        }

        const userKeyIvBase64 = arrayBufferToBase64(encryptionResult.iv);
        const encryptedUserKeyBase64 = arrayBufferToBase64(encryptionResult.encryptedUserKey);
        const storedValue = `${userKeyIvBase64}.${encryptedUserKeyBase64}`;

        const stmt = env.DB.prepare(
            "INSERT INTO Users (user_id, encryption_key_encrypted, status) VALUES (?, ?, 'active') ON CONFLICT(user_id) DO UPDATE SET encryption_key_encrypted=excluded.encryption_key_encrypted, status='active'"
        );
        await stmt.bind(username, storedValue).run();
        if (env.LOGGING_ENABLED === "true") console.log(`Stored encrypted key for user ${username}.`);
        return true;

    } catch (e) {
        if (env.LOGGING_ENABLED === "true") console.error(`Error storing encrypted user key for ${username}:`, e.message, e.stack);
        return false;
    }
}

// --- 日志记录 ---
/**
 * 重命名：logUploadActivity -> logFileActivity
 * 记录文件操作活动。
 * @param {object} env - Worker 环境变量.
 * @param {object} logData - 日志数据对象.
 * @property {string} user_id
 * @property {string} action_type - 'upload', 'download', 'delete', 'list'
 * @property {string} original_file_path
 * @property {string} [file_hash]
 * @property {number} [file_size_bytes]
 * @property {string} status - 'success' or 'failure'
 * @property {string} [error_message]
 * @property {string} [source_ip]
 * @property {string} [user_agent]
 * @returns {Promise<void>}
 */
export async function logFileActivity(env, logData) { // <-- 重命名函数
    // 功能：向 D1 数据库记录文件操作日志。
    // 参数：env, logData (包含日志详情的对象)
    // 返回：无 (Promise<void>)
    if (!env.DB) {
        if (env.LOGGING_ENABLED === "true") console.warn("D1_NOT_CONFIGURED: Activity log not saved.", logData);
        return;
    }
    try {
        const {
            user_id,
            action_type = 'unknown', // 添加默认值
            original_file_path,
            file_hash = null, 
            file_size_bytes = null,
            status,
            error_message = null,
            source_ip = null,
            user_agent = null
        } = logData;
        const logged_at = new Date().toISOString();

        // 假设你已将表 UploadLogs 重命名为 FileActivityLogs 并添加了 action_type 列
        const stmt = env.DB.prepare(
            "INSERT INTO FileActivityLogs (user_id, action_type, original_file_path, file_hash, file_size_bytes, logged_at, status, error_message, source_ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ); 
        
        await stmt.bind(
            user_id, 
            action_type,
            original_file_path, 
            file_hash, 
            file_size_bytes, 
            logged_at, 
            status, 
            error_message, 
            source_ip, 
            user_agent
        ).run();
        
        if (env.LOGGING_ENABLED === "true") console.log(`Activity logged: User='${user_id}', Action='${action_type}', Path='${original_file_path}', Status='${status}'`);

    } catch (e) {
        if (env.LOGGING_ENABLED === "true") {
            console.error("Failed to log file activity:", e.message, e.stack, "Log data attempted:", logData);
        }
    }
}