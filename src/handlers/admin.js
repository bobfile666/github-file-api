// src/handlers/admin.js
// 描述：处理管理员相关的 API 请求，例如创建用户。

import { jsonResponse, errorResponse } from '../utils/response.js';
import { generateAesGcmKey, exportCryptoKeyToRaw } from '../utils/crypto.js';
import { storeEncryptedUserKey, getUserSymmetricKey } from '../services/d1Database.js'; // getUserSymmetricKey 用于检查用户是否已存在

/**
 * 验证请求是否来自合法的管理员。
 * @param {Request} request - 进来的请求对象.
 * @param {object} env - Worker 环境变量 (包含 ADMIN_API_KEY).
 * @returns {boolean} - 是否是管理员.
 */
function isAdminRequest(request, env) {
    const adminKeyFromHeader = request.headers.get('X-Admin-API-Key');
    if (!env.ADMIN_API_KEY) {
        if (env.LOGGING_ENABLED === "true") console.error("[isAdminRequest] ADMIN_API_KEY secret is not configured in worker environment.");
        return false; // 如果 ADMIN_API_KEY 未配置，则所有管理员请求都失败
    }
    if (!adminKeyFromHeader || adminKeyFromHeader !== env.ADMIN_API_KEY) {
        if (env.LOGGING_ENABLED === "true") console.warn("[isAdminRequest] Admin API Key mismatch or not provided.");
        return false;
    }
    return true;
}


/**
 * 处理管理员创建新用户的请求。
 * 端点：POST /admin/users/create  (或 /v1/admin/users)
 * 请求体 (JSON): { "username": "newuser123" }
 * Header: X-Admin-API-Key: <your_admin_api_key>
 * @param {Request} request
 * @param {object} env
 * @param {object} ctx
 * @returns {Promise<Response>}
 */
export async function handleAdminCreateUser(request, env, ctx) {
    // 功能：管理员创建新用户，包括生成和存储其加密密钥。
    // 参数：request, env, ctx
    // 返回：Response 对象
    
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleAdminCreateUser] Received request to create user.`);
    }

    // 1. 验证是否是管理员请求
    if (!isAdminRequest(request, env)) {
        return errorResponse(env, "Unauthorized: Admin access required.", 403);
    }

    if (request.method !== 'POST') {
        return errorResponse(env, "Method Not Allowed. Use POST to create a user.", 405);
    }

    let requestBody;
    try {
        requestBody = await request.json();
    } catch (e) {
        if (env.LOGGING_ENABLED === "true") console.warn(`[handleAdminCreateUser] Invalid JSON body:`, e.message);
        return errorResponse(env, "Invalid JSON request body.", 400);
    }

    const { username } = requestBody;

    if (!username || typeof username !== 'string' || username.trim() === '' || username.includes('/') || username.includes('..')) {
        // 对用户名进行一些基本验证，防止路径操纵或无效字符
        if (env.LOGGING_ENABLED === "true") console.warn(`[handleAdminCreateUser] Invalid username provided: '${username}'`);
        return errorResponse(env, "Invalid username provided. Username must be a non-empty string and should not contain path-like characters ('/', '..').", 400);
    }
    
    // 检查 D1 数据库是否配置
    if (!env.DB) {
        if (env.LOGGING_ENABLED === "true") console.error("[handleAdminCreateUser] D1 Database (env.DB) is not configured.");
        return errorResponse(env, "Database service is not configured.", 500);
    }
    if (!env.MASTER_ENCRYPTION_KEY) {
        if (env.LOGGING_ENABLED === "true") console.error("[handleAdminCreateUser] MASTER_ENCRYPTION_KEY secret is not configured.");
        return errorResponse(env, "Master encryption key is not configured.", 500);
    }


    try {
        // 2. 检查用户是否已存在 (通过尝试获取其密钥)
        // 注意：getUserSymmetricKey 内部会处理用户不存在或密钥不存在的情况并返回 null
        // 我们也可以直接查询 Users 表。为简单起见，复用 getUserSymmetricKey 的检查。
        // 或者更直接：
        const checkUserStmt = env.DB.prepare("SELECT user_id FROM Users WHERE user_id = ?");
        const existingUser = await checkUserStmt.bind(username).first();

        if (existingUser) {
            if (env.LOGGING_ENABLED === "true") console.warn(`[handleAdminCreateUser] Attempt to create existing user: '${username}'`);
            return errorResponse(env, `User '${username}' already exists.`, 409); // 409 Conflict
        }

        // 3. 为新用户生成对称加密密钥 (CryptoKey object)
        const userCryptoKey = await generateAesGcmKey(); // from utils/crypto.js
        if (!userCryptoKey) {
             if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminCreateUser] Failed to generate user symmetric key for '${username}'`);
            return errorResponse(env, "Failed to generate user encryption key.", 500);
        }
        
        // 4. 将 CryptoKey 导出为原始 ArrayBuffer 以便用 MEK 加密
        const userRawKeyBuffer = await exportCryptoKeyToRaw(userCryptoKey);
        if (!userRawKeyBuffer) {
            if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminCreateUser] Failed to export user symmetric key to raw format for '${username}'`);
            return errorResponse(env, "Failed to process user encryption key.", 500);
        }

        // 5. 使用 MEK 加密用户密钥并存储到 D1
        // storeEncryptedUserKey 函数 (from services/d1Database.js) 内部会处理 MEK 加密和 D1 存储
        const storedSuccessfully = await storeEncryptedUserKey(env, username, userRawKeyBuffer);

        if (!storedSuccessfully) {
            if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminCreateUser] Failed to store encrypted key for user '${username}' in D1.`);
            return errorResponse(env, `Failed to create user '${username}' due to a storage error.`, 500);
        }

        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleAdminCreateUser] User '${username}' created successfully by admin.`);
        }
        return jsonResponse({
            message: `User '${username}' created successfully.`,
            username: username
        }, 201); // 201 Created

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") {
            console.error(`[handleAdminCreateUser] Unexpected error while creating user '${username}':`, error.message, error.stack);
        }
        return errorResponse(env, `An unexpected server error occurred: ${error.message}`, 500);
    }
}