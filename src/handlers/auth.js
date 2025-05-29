// src/handlers/auth.js
// 描述：处理用户身份验证相关的请求，主要是动态令牌的生成。
import { signDynamicToken } from '../utils/crypto.js';
import { jsonResponse, errorResponse } from '../utils/response.js';
// 假设有一个函数验证调用平台的 API Key (这部分需要根据你的平台对接方式实现)
// async function verifyPlatformIntegrity(request, env) {
//     const platformKey = request.headers.get('X-Platform-API-Key');
//     // 在这里查询 D1 或固定列表验证 platformKey 是否有效，并返回平台信息或是否有效
//     if (platformKey === env.SOME_PRESHARED_KEY_FOR_PLATFORM_A) return { valid: true, platformId: "PlatformA" };
//     return { valid: false, message: "Invalid platform API Key" };
// }


/**
 * 处理动态令牌请求。
 * @param {Request} request - 进来的请求.
 * @param {object} env - Worker 环境变量.
 * @param {object} ctx - Worker 执行上下文.
 * @returns {Promise<Response>}
 */
export async function handleRequestDynamicToken(request, env, ctx) {
    if (request.method !== 'POST') {
        return errorResponse(env, "Method not allowed. Use POST to request a token.", 405);
    }

    // 1. (可选但推荐) 验证请求来源平台的身份
    // const platformAuth = await verifyPlatformIntegrity(request, env);
    // if (!platformAuth.valid) {
    //     return errorResponse(env, platformAuth.message || "Platform authentication failed", 401);
    // }
    // 如果没有平台级认证，任何能访问此端点的人都可以为任意用户请求令牌，依赖后续 API 的用户名匹配。

    let requestBody;
    try {
        requestBody = await request.json();
    } catch (e) {
        return errorResponse(env, "Invalid JSON request body.", 400);
    }

    const { username, ttl_seconds } = requestBody; // ttl_seconds 是可选的，会覆盖默认 TTL
    if (!username) {
        return errorResponse(env, "Username is required in the request body.", 400);
    }
    if (typeof username !== 'string' || username.trim() === '') {
        return errorResponse(env, "Username must be a non-empty string.", 400);
    }
    if (ttl_seconds && (typeof ttl_seconds !== 'number' || ttl_seconds <= 0 || ttl_seconds > 300)) { // 例如，最大 TTL 5 分钟
        return errorResponse(env, "ttl_seconds must be a positive number, not exceeding 300.", 400);
    }


    // TODO: 实际应用中，这里应该检查 D1 中是否存在该用户 (username)
    // 如果用户不存在，可能不应该签发令牌，或者签发的令牌后续无法通过文件操作的授权。
    // const userExists = await d1Service.checkUserExists(env, username); // 假设有此函数
    // if (!userExists) {
    //     return errorResponse(env, `User '${username}' not found. Cannot issue token.`, 404);
    // }

    if (!env.DYNAMIC_TOKEN_SECRET) {
        console.error("DYNAMIC_TOKEN_SECRET is not configured in worker environment.");
        return errorResponse(env, "Token signing service is misconfigured.", 500);
    }
    
    const tokenPayload = { 
        username: username,
        // iat 和 exp 会在 signDynamicToken 内部处理
        // 如果有特定的操作意图，也可以在这里加入，e.g., scope: "upload"
    };
    if (ttl_seconds) {
        tokenPayload.ttl_seconds = ttl_seconds; // 传递自定义 TTL
    }

    const signedToken = await signDynamicToken(tokenPayload, env.DYNAMIC_TOKEN_SECRET);

    if (!signedToken) {
        return errorResponse(env, "Failed to generate dynamic token.", 500);
    }

    return jsonResponse({ 
        dynamic_token: signedToken,
        username: username,
        expires_in: ttl_seconds || DEFAULT_TOKEN_TTL_SECONDS // 使用 crypto.js 中的默认值
    });
}