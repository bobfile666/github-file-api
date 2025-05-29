// src/services/d1Database.js
// 描述：封装所有与 D1 数据库的交互逻辑。
import { 
    importRawToCryptoKey, 
    decryptUserKeyWithMEK, 
    base64ToArrayBuffer, 
    arrayBufferToBase64 
} from '../utils/crypto.js';

// --- 用户密钥管理 ---

// 这是一个临时的硬编码原始用户密钥 (base64)，用于测试，直到 D1 和 MEK 流程完全建立。
// 生产中绝不能这样用！密钥应从 D1 读取并用 MEK 解密。
// 生成一个 256 位 (32 字节) 的密钥：crypto.getRandomValues(new Uint8Array(32))
// 然后 arrayBufferToBase64(keyBuffer)
export const DUMMY_USER_KEY_RAW_BASE64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; // 32 个'A'的 Base64
export const DUMMY_USER_KEY_IV_BASE64 = "AAAAAAAAAAAAAAA="; // 12 个'A'的 Base64 (用于 MEK 加密用户密钥时的 IV)


/**
 * 获取并解密指定用户的对称加密密钥 (CryptoKey object for AES-GCM).
 * @param {object} env - Worker 环境变量 (包含 DB 和 MASTER_ENCRYPTION_KEY).
 * @param {string} username - 用户名.
 * @returns {Promise<CryptoKey|null>} 用户的 CryptoKey 或 null 如果失败.
 */
export async function getUserSymmetricKey(env, username) {
    if (!env.DB) {
        console.error("D1 Database (env.DB) is not configured.");
        // 对于本地或无 D1 的测试，返回一个硬编码的密钥
        if (env.LOGGING_ENABLED === "true") console.warn("D1_NOT_CONFIGURED: Using DUMMY_USER_KEY_RAW_BASE64 for testing.");
        try {
            const rawKeyBuffer = base64ToArrayBuffer(DUMMY_USER_KEY_RAW_BASE64);
            return await importRawToCryptoKey(rawKeyBuffer, ['encrypt', 'decrypt']);
        } catch (e) {
            console.error("Error importing dummy key:", e);
            return null;
        }
    }
    if (!env.MASTER_ENCRYPTION_KEY) {
        console.error("MASTER_ENCRYPTION_KEY secret is not configured.");
        return null;
    }

    try {
        // 1. 从 D1 获取加密的用户密钥 (base64 string) 和 IV (base64 string)
        const stmt = env.DB.prepare("SELECT encryption_key_encrypted FROM Users WHERE user_id = ? AND status = 'active'");
        const result = await stmt.bind(username).first();

        if (!result || !result.encryption_key_encrypted) {
            if (env.LOGGING_ENABLED === "true") console.log(`No active user or encryption key found in D1 for user '${username}'.`);
            return null;
        }

        // encryption_key_encrypted 应该存储为 "iv_base64.encrypted_key_base64"
        const parts = result.encryption_key_encrypted.split('.');
        if (parts.length !== 2) {
            console.error(`Invalid stored encrypted key format for user '${username}'. Expected 'iv.key'.`);
            return null;
        }
        const userKeyIvBase64 = parts[0];
        const encryptedUserKeyBase64 = parts[1];

        const encryptedUserKeyBuffer = base64ToArrayBuffer(encryptedUserKeyBase64);
        const userKeyIv = new Uint8Array(base64ToArrayBuffer(userKeyIvBase64));


        // 2. 准备 MEK (主加密密钥)
        // MEK 本身也应该是 Base64 编码的原始密钥字符串，存储在 Secret 中
        const mekRawBuffer = base64ToArrayBuffer(env.MASTER_ENCRYPTION_KEY);
        const mekCryptoKey = await importRawToCryptoKey(mekRawBuffer, ['decrypt']); // MEK 只需要解密权限

        // 3. 使用 MEK 解密用户密钥
        const decryptedUserKeyBuffer = await decryptUserKeyWithMEK(encryptedUserKeyBuffer, userKeyIv, mekCryptoKey);
        if (!decryptedUserKeyBuffer) {
            console.error(`Failed to decrypt user key for '${username}' with MEK.`);
            return null;
        }

        // 4. 将解密后的原始用户密钥导入为 CryptoKey (用于文件加解密)
        return await importRawToCryptoKey(decryptedUserKeyBuffer, ['encrypt', 'decrypt']);

    } catch (e) {
        console.error(`Error getting/decrypting user symmetric key for '${username}':`, e.message, e.stack);
        return null;
    }
}

/**
 * (辅助/管理功能，实际可能由管理员脚本调用)
 * 为用户创建记录并存储加密后的密钥。
 * @param {object} env - Worker 环境变量.
 * @param {string} username - 用户名.
 * @param {ArrayBuffer} rawUserKeyBuffer - 用户原始对称密钥 (e.g., 32 bytes for AES-256).
 * @returns {Promise<boolean>} - 是否成功.
 */
export async function storeEncryptedUserKey(env, username, rawUserKeyBuffer) {
    if (!env.DB || !env.MASTER_ENCRYPTION_KEY) {
        console.error("D1 or MASTER_ENCRYPTION_KEY not configured for storing user key.");
        return false;
    }
    try {
        const mekRawBuffer = base64ToArrayBuffer(env.MASTER_ENCRYPTION_KEY);
        const mekCryptoKey = await importRawToCryptoKey(mekRawBuffer, ['encrypt']);

        const encryptionResult = await encryptUserKeyWithMEK(rawUserKeyBuffer, mekCryptoKey); // crypto.js 的函数
        if (!encryptionResult) {
            console.error(`Failed to encrypt user key for ${username} with MEK during storage.`);
            return false;
        }

        const userKeyIvBase64 = arrayBufferToBase64(encryptionResult.iv);
        const encryptedUserKeyBase64 = arrayBufferToBase64(encryptionResult.encryptedUserKey);
        const storedValue = `${userKeyIvBase64}.${encryptedUserKeyBase64}`;

        // 假设 Users 表已存在
        const stmt = env.DB.prepare(
            "INSERT INTO Users (user_id, encryption_key_encrypted, status) VALUES (?, ?, 'active') ON CONFLICT(user_id) DO UPDATE SET encryption_key_encrypted=excluded.encryption_key_encrypted, status='active'"
        );
        await stmt.bind(username, storedValue).run();
        if (env.LOGGING_ENABLED === "true") console.log(`Stored encrypted key for user ${username}.`);
        return true;

    } catch (e) {
        console.error(`Error storing encrypted user key for ${username}:`, e.message, e.stack);
        return false;
    }
}


/**
 * 记录文件上传活动 (或其他文件操作，如果表结构通用)。
 * @param {object} env - Worker 环境变量.
 * @param {object} logData - 日志数据对象.
 * @property {string} user_id
 * @property {string} original_file_path
 * @property {string} [file_hash] - 对于上传是必须的
 * @property {number} [file_size_bytes] - 对于上传
 * @property {string} status - 'success' or 'failure'
 * @property {string} [action_type='upload'] - 可以扩展为 'download', 'delete', 'list'
 * @property {string} [error_message]
 * @property {string} [source_ip]
 * @property {string} [user_agent]
 * @returns {Promise<void>}
 */
export async function logUploadActivity(env, logData) {
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
            original_file_path,
            file_hash = null, // 设为可选，因为删除或列表操作可能没有
            file_size_bytes = null, // 设为可选
            status,
            action_type = 'upload', // 默认是上传，可以扩展
            error_message = null,
            source_ip = null,
            user_agent = null
        } = logData;
        const logged_at = new Date().toISOString(); // 使用 logged_at 更通用

        // 根据 action_type 可能需要调整 SQL 或表结构，但 UploadLogs 表目前主要针对上传
        // 如果要记录所有操作，可以考虑一个更通用的 'FileActivityLogs' 表
        const stmt = env.DB.prepare(
            "INSERT INTO UploadLogs (user_id, original_file_path, file_hash, file_size_bytes, uploaded_at, status, error_message, source_ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ); // uploaded_at 列名可能需要改为 logged_at 如果表更通用
        
        await stmt.bind(
            user_id, 
            original_file_path, 
            file_hash, 
            file_size_bytes, 
            logged_at, // 使用新的 logged_at
            status, 
            error_message, 
            source_ip, 
            user_agent
        ).run();
        
        if (env.LOGGING_ENABLED === "true") console.log(`Activity logged: User='${user_id}', Action='${action_type}', Path='${original_file_path}', Status='${status}'`);

    } catch (e) {
        if (env.LOGGING_ENABLED === "true") {
            console.error("Failed to log activity:", e.message, e.stack, "Log data attempted:", logData);
        }
        // 告警或备用日志系统可以在这里考虑
    }
}