// src/handlers/admin.js
// 描述：处理管理员相关的 API 请求，例如创建用户。

import { jsonResponse, errorResponse } from '../utils/response.js';
import { generateAesGcmKey, exportCryptoKeyToRaw } from '../utils/crypto.js';
import { storeEncryptedUserKey, getUserSymmetricKey } from '../services/d1Database.js'; // getUserSymmetricKey 用于检查用户是否已存在
import { ensureFileExists } from '../services/github.js'; // 新增导入


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
            if (env.LOGGING_ENABLED === "true") console.warn(`[handleAdminCreateUser] Attempt to create existing user: '${username}'`);
            return errorResponse(env, `User '${username}' already exists.`, 409);
        }

        const userCryptoKey = await generateAesGcmKey();
        if (!userCryptoKey) {
             if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminCreateUser] Failed to generate user symmetric key for '${username}'`);
            return errorResponse(env, "Failed to generate user encryption key.", 500);
        }
        
        const userRawKeyBuffer = await exportCryptoKeyToRaw(userCryptoKey);
        if (!userRawKeyBuffer) {
            if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminCreateUser] Failed to export user symmetric key to raw format for '${username}'`);
            return errorResponse(env, "Failed to process user encryption key.", 500);
        }

        const storedInD1Successfully = await storeEncryptedUserKey(env, username, userRawKeyBuffer);

        if (!storedInD1Successfully) {
            if (env.LOGGING_ENABLED === "true") console.error(`[handleAdminCreateUser] Failed to store encrypted key for user '${username}' in D1.`);
            return errorResponse(env, `Failed to create user '${username}' due to a D1 storage error.`, 500);
        }

        // --- 新增：初始化 GitHub 用户目录和空的 index.json ---
        const owner = env.GITHUB_REPO_OWNER;
        const repo = env.GITHUB_REPO_NAME;
        const targetBranch = env.TARGET_BRANCH || "main";
        const userIndexPath = `${username}/index.json`;
        const emptyIndexContent = JSON.stringify({ files: {} }, null, 2);
        const emptyIndexBase64 = arrayBufferToBase64(new TextEncoder().encode(emptyIndexContent)); // 使用 crypto.js 中的辅助函数
        const initCommitMessage = `Chore: Initialize index.json for new user ${username}`;

        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleAdminCreateUser] Initializing GitHub structure for user '${username}' at path '${userIndexPath}'`);
        }

        const githubInitResult = await ensureFileExists(env, owner, repo, userIndexPath, targetBranch, emptyIndexBase64, initCommitMessage);

        if (githubInitResult.error && githubInitResult.status !== 200) { // 200 表示可能已存在
            // 如果创建失败 (非 "已存在" 的情况)
            if (env.LOGGING_ENABLED === "true") {
                console.error(`[handleAdminCreateUser] Failed to initialize GitHub index.json for user '${username}'. Error: ${githubInitResult.message}. D1 record was created but GitHub init failed.`);
            }
            // 这是一个半成功状态：D1 用户已创建，但 GitHub 结构初始化失败。
            // 可以选择返回一个警告性的成功，或者一个特定的错误码。
            // 为了简单，我们这里还是返回成功，但附加警告信息，或者让管理员知道需要检查。
            // 更好的做法是尝试回滚 D1 的创建，但这会增加复杂性。
            return jsonResponse({
                message: `User '${username}' created in D1, but GitHub initialization might have failed: ${githubInitResult.message}. Please verify GitHub structure.`,
                username: username,
                d1_status: "created",
                github_status: "initialization_failed",
                github_error: githubInitResult
            }, 207); // 207 Multi-Status
        }
        // ----------------------------------------------------

        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleAdminCreateUser] User '${username}' created successfully in D1 and GitHub structure initialized.`);
        }
        return jsonResponse({
            message: `User '${username}' created successfully. GitHub structure initialized.`,
            username: username
        }, 201);

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") {
            console.error(`[handleAdminCreateUser] Unexpected error while creating user '${username}':`, error.message, error.stack);
        }
        return errorResponse(env, `An unexpected server error occurred: ${error.message}`, 500);
    }
}