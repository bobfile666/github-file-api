// src/services/kvStore.js
// 描述：封装所有与 Cloudflare KV Store 的交互逻辑。

const UPLOAD_TIMESTAMP_KV_PREFIX = 'upload_ts_'; // KV key 前缀

/**
 * 获取用户上次成功上传的时间戳。
 * @param {object} env - Worker 环境变量 (包含 USER_UPLOAD_TIMESTAMPS_KV).
 * @param {string} username - 用户名.
 * @returns {Promise<number|null>} - 时间戳 (毫秒) 或 null 如果未找到.
 */
export async function getLastUploadTimestamp(env, username) {
    if (!env.USER_UPLOAD_TIMESTAMPS_KV) {
        if (env.LOGGING_ENABLED === "true") console.warn("KV_NAMESPACE_NOT_CONFIGURED: USER_UPLOAD_TIMESTAMPS_KV is not bound. Rate limiting will be bypassed.");
        return null; // 如果 KV 未配置，则不进行速率限制或返回允许
    }
    const kvKey = `${UPLOAD_TIMESTAMP_KV_PREFIX}${username}`;
    const timestampStr = await env.USER_UPLOAD_TIMESTAMPS_KV.get(kvKey);
    return timestampStr ? parseInt(timestampStr, 10) : null;
}

/**
 * 更新用户上次成功上传的时间戳。
 * @param {object} env - Worker 环境变量.
 * @param {string} username - 用户名.
 * @param {number} timestampMs - 当前时间戳 (毫秒).
 * @param {number} [ttlSeconds] - (可选) KV 条目的 TTL（秒），例如 1 天后自动过期。
 * @returns {Promise<void>}
 */
export async function updateLastUploadTimestamp(env, username, timestampMs, ttlSeconds) {
    if (!env.USER_UPLOAD_TIMESTAMPS_KV) {
        if (env.LOGGING_ENABLED === "true") console.warn("KV_NAMESPACE_NOT_CONFIGURED: Cannot update last upload timestamp for rate limiting.");
        return;
    }
    const kvKey = `${UPLOAD_TIMESTAMP_KV_PREFIX}${username}`;
    const options = {};
    if (ttlSeconds) {
        options.expirationTtl = ttlSeconds;
    }
    try {
        await env.USER_UPLOAD_TIMESTAMPS_KV.put(kvKey, timestampMs.toString(), options);
        if (env.LOGGING_ENABLED === "true") console.log(`Updated last upload timestamp for ${username} in KV.`);
    } catch (e) {
        console.error(`Failed to update last upload timestamp in KV for ${username}:`, e.message);
    }
}