// src/handlers/admin.js
// 描述：处理管理员相关的 API 请求，例如创建用户。

import { jsonResponse, errorResponse } from '../utils/response.js';
import { 
    generateAesGcmKey, 
    exportCryptoKeyToRaw, 
    arrayBufferToBase64 // <--- 确保此导入存在
} from '../utils/crypto.js'; 
import { storeEncryptedUserKey } from '../services/d1Database.js';
import { ensureFileExists } from '../services/github.js';


/**
 * 验证请求是否来自合法的管理员。
 * @param {Request} request
 * @param {object} env
 * @returns {boolean}
 */
function isAdminRequest(request, env) {
    // 功能：验证管理员 API 密钥。
    const adminKeyFromHeader = request.headers.get('X-Admin-API-Key');
    if (!env.ADMIN_API_KEY) {
        if (env.LOGGING_ENABLED === "true") console.error("[isAdminRequest] ADMIN_API_KEY secret is not configured.");
        return false;
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
    // 功能：管理员创建新用户，包括生成和存储其加密密钥，并初始化 GitHub 上的用户目录和 index.json。
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleAdminCreateUser] Received request to create user.`);
    }
    if (!isAdminRequest(request, env)) {
        return errorResponse(env, "Unauthorized: Admin access required.", 403);
    }
    if (request.method !== 'POST') {
        return errorResponse(env, "Method Not Allowed. Use POST to create a user.", 405);
    }
    let requestBody;
    try { requestBody = await request.json(); } catch (e) { return errorResponse(env, "Invalid JSON request body.", 400); }
    const { username } = requestBody;
    if (!username || typeof username !== 'string' || username.trim() === '' || username.includes('/') || username.includes('..')) {
        return errorResponse(env, "Invalid username provided.", 400);
    }
    if (!env.DB || !env.MASTER_ENCRYPTION_KEY) {
        return errorResponse(env, "Server configuration error (DB or MEK).", 500);
    }

    try {
        const checkUserStmt = env.DB.prepare("SELECT user_id FROM Users WHERE user_id = ?");
        const existingUser = await checkUserStmt.bind(username).first();
        if (existingUser) {
            return errorResponse(env, `User '${username}' already exists.`, 409);
        }
        const userCryptoKey = await generateAesGcmKey();
        const userRawKeyBuffer = await exportCryptoKeyToRaw(userCryptoKey);
        if (!userRawKeyBuffer) {
            return errorResponse(env, "Failed to process user encryption key.", 500);
        }
        const storedInD1Successfully = await storeEncryptedUserKey(env, username, userRawKeyBuffer);
        if (!storedInD1Successfully) {
            return errorResponse(env, `Failed to create user '${username}' due to a D1 storage error.`, 500);
        }

        const owner = env.GITHUB_REPO_OWNER;
        const repo = env.GITHUB_REPO_NAME;
        const targetBranch = env.TARGET_BRANCH || "main";
        const userIndexPath = `${username}/index.json`;
        const emptyIndexContent = JSON.stringify({ files: {} }, null, 2);
        const emptyIndexBase64 = arrayBufferToBase64(new TextEncoder().encode(emptyIndexContent));
        const initCommitMessage = `Chore: Initialize index.json for new user ${username}`;
        const githubInitResult = await ensureFileExists(env, owner, repo, userIndexPath, targetBranch, emptyIndexBase64, initCommitMessage);

        if (githubInitResult.error && githubInitResult.status !== 200) {
            return jsonResponse({
                message: `User '${username}' created in D1, but GitHub initialization might have failed: ${githubInitResult.message}. Please verify GitHub structure.`,
                username: username,
                d1_status: "created",
                github_status: "initialization_failed",
                github_error: githubInitResult
            }, 207);
        }
        return jsonResponse({
            message: `User '${username}' created successfully. GitHub structure initialized.`,
            username: username
        }, 201);
    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminCreateUser] Unexpected error for '${username}':`, error.message, error.stack);
        return errorResponse(env, `An unexpected server error occurred: ${error.message}`, 500);
    }
}

/**
 * 新添加的函数：处理管理员获取用户列表的请求。
 * 端点：GET /admin/users (或 /v1/admin/users)
 * Header: X-Admin-API-Key: <your_admin_api_key>
 * @param {Request} request
 * @param {object} env
 * @param {object} ctx
 * @returns {Promise<Response>}
 */
export async function handleAdminListUsers(request, env, ctx) {
    // 功能：管理员获取系统中的用户列表。
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleAdminListUsers] Received request to list users.`);
    }
    if (!isAdminRequest(request, env)) {
        return errorResponse(env, "Unauthorized: Admin access required.", 403);
    }
    if (request.method !== 'GET') {
        return errorResponse(env, "Method Not Allowed. Use GET to list users.", 405);
    }
    if (!env.DB) {
        return errorResponse(env, "Database service is not configured.", 500);
    }
    try {
        const stmt = env.DB.prepare("SELECT user_id, created_at, status FROM Users ORDER BY created_at DESC");
        const { results } = await stmt.all();
        const users = results || [];
        if (env.LOGGING_ENABLED === "true") console.log(`[handleAdminListUsers] Found ${users.length} users.`);
        return jsonResponse({ users: users, count: users.length });
    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminListUsers] Error listing users:`, error.message, error.stack);
        return errorResponse(env, `Error listing users: ${error.message}`, 500);
    }
}

/**
 * 新添加的函数：处理管理员获取特定用户信息的请求。
 * 端点：GET /admin/users/{username}
 * @param {Request} request
 * @param {object} env
 * @param {object} ctx
 * @param {string} username - 从路径中提取的用户名
 * @returns {Promise<Response>}
 */
export async function handleAdminGetUserInfo(request, env, ctx, username) {
    // 功能：管理员获取特定用户的非敏感信息。
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleAdminGetUserInfo] Request for user: ${username}`);
    }
    if (!isAdminRequest(request, env)) {
        return errorResponse(env, "Unauthorized: Admin access required.", 403);
    }
    if (!env.DB) {
        return errorResponse(env, "Database service not configured.", 500);
    }
    if (!username) {
        return errorResponse(env, "Username parameter is required.", 400);
    }

    try {
        const stmt = env.DB.prepare("SELECT user_id, created_at, status FROM Users WHERE user_id = ?");
        const user = await stmt.bind(username).first();

        if (!user) {
            return errorResponse(env, `User '${username}' not found.`, 404);
        }
        return jsonResponse(user);
    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminGetUserInfo] Error fetching user ${username}:`, error.message, error.stack);
        return errorResponse(env, `Error fetching user info: ${error.message}`, 500);
    }
}

/**
 * 新添加的函数：辅助函数，用于更新用户状态 (禁用/启用)。
 * @param {object} env
 * @param {string} username
 * @param {'active' | 'disabled'} newStatus
 * @returns {Promise<Response>}
 */
async function updateUserStatus(env, username, newStatus) {
    // 功能：更新 D1 中指定用户的状态。
    if (!env.DB) {
        return errorResponse(env, "Database service not configured.", 500);
    }
    try {
        const stmt = env.DB.prepare("UPDATE Users SET status = ? WHERE user_id = ?");
        const info = await stmt.bind(newStatus, username).run();

        if (info.success && info.changes > 0) {
            if (env.LOGGING_ENABLED === "true") console.log(`[updateUserStatus] User '${username}' status updated to '${newStatus}'.`);
            return jsonResponse({ message: `User '${username}' status updated to '${newStatus}'.` });
        } else if (info.changes === 0) {
            return errorResponse(env, `User '${username}' not found or status already '${newStatus}'.`, 404);
        } else {
            if (env.LOGGING_ENABLED === "true") console.error(`[updateUserStatus] Failed to update status for user '${username}'. D1 info:`, info);
            return errorResponse(env, `Failed to update status for user '${username}'.`, 500);
        }
    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[updateUserStatus] Error updating status for ${username}:`, error.message, error.stack);
        return errorResponse(env, `Error updating user status: ${error.message}`, 500);
    }
}

/**
 * 新添加的函数：处理管理员禁用用户的请求。
 * 端点：PUT /admin/users/{username}/disable
 * @param {Request} request
 * @param {object} env
 * @param {object} ctx
 * @param {string} username
 * @returns {Promise<Response>}
 */
export async function handleAdminDisableUser(request, env, ctx, username) {
    // 功能：管理员禁用一个用户。
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleAdminDisableUser] Request to disable user: ${username}`);
    }
    if (!isAdminRequest(request, env)) {
        return errorResponse(env, "Unauthorized: Admin access required.", 403);
    }
    if (!username) {
        return errorResponse(env, "Username parameter is required.", 400);
    }
    return updateUserStatus(env, username, 'disabled');
}

/**
 * 新添加的函数：处理管理员启用用户的请求。
 * 端点：PUT /admin/users/{username}/enable
 * @param {Request} request
 * @param {object} env
 * @param {object} ctx
 * @param {string} username
 * @returns {Promise<Response>}
 */
export async function handleAdminEnableUser(request, env, ctx, username) {
    // 功能：管理员启用一个用户。
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleAdminEnableUser] Request to enable user: ${username}`);
    }
    if (!isAdminRequest(request, env)) {
        return errorResponse(env, "Unauthorized: Admin access required.", 403);
    }
    if (!username) {
        return errorResponse(env, "Username parameter is required.", 400);
    }
    return updateUserStatus(env, username, 'active');
}


/**
 * 新添加的函数：处理管理员删除用户的请求（仅从 D1 Users 表删除）。
 * 端点：DELETE /admin/users/{username}
 * @param {Request} request
 * @param {object} env
 * @param {object} ctx
 * @param {string} username
 * @returns {Promise<Response>}
 */
export async function handleAdminDeleteUser(request, env, ctx, username) {
    // 功能：管理员从 D1 删除用户记录 (活动日志保留)。
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleAdminDeleteUser] Request to delete user: ${username}`);
    }
    if (!isAdminRequest(request, env)) {
        return errorResponse(env, "Unauthorized: Admin access required.", 403);
    }
    if (!env.DB) {
        return errorResponse(env, "Database service not configured.", 500);
    }
    if (!username) {
        return errorResponse(env, "Username parameter is required.", 400);
    }

    try {
        // 警告：此操作不可逆，且仅删除 D1 中的用户记录。
        // GitHub 上的文件和文件夹不会被自动清理。
        // FileActivityLogs 中的记录会因为外键已移除而保留。
        const stmt = env.DB.prepare("DELETE FROM Users WHERE user_id = ?");
        const info = await stmt.bind(username).run();

        if (info.success && info.changes > 0) {
            if (env.LOGGING_ENABLED === "true") console.log(`[handleAdminDeleteUser] User '${username}' deleted from D1 Users table. GitHub files NOT automatically cleaned.`);
            return jsonResponse({ message: `User '${username}' deleted successfully from user database. Associated files on GitHub and activity logs are NOT automatically removed.` });
        } else if (info.changes === 0) {
            return errorResponse(env, `User '${username}' not found in user database.`, 404);
        } else {
            if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminDeleteUser] Failed to delete user '${username}' from D1. D1 info:`, info);
            return errorResponse(env, `Failed to delete user '${username}'.`, 500);
        }
    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminDeleteUser] Error deleting user ${username}:`, error.message, error.stack);
        return errorResponse(env, `Error deleting user: ${error.message}`, 500);
    }
}

