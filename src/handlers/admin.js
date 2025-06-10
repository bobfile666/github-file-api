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

/**
 * 验证请求是否来自合法的管理员 (使用 X-Admin-API-Key Header)。
 * @param {Request} request
 * @param {object} env
 * @returns {boolean}
 */
function isAdminApiRequest(request, env) {
    // 功能：用于 JSON API 的管理员 API 密钥验证。
    const adminKeyFromHeader = request.headers.get('X-Admin-API-Key');
    if (!env.ADMIN_API_KEY) {
        if (env.LOGGING_ENABLED === "true") console.error("[isAdminApiRequest] ADMIN_API_KEY secret is not configured.");
        return false;
    }
    if (!adminKeyFromHeader || adminKeyFromHeader !== env.ADMIN_API_KEY) {
        if (env.LOGGING_ENABLED === "true") console.warn("[isAdminApiRequest] Admin API Key mismatch or not provided in header.");
        return false;
    }
    return true;
}

/**
 * 验证管理员页面密码 (通常来自 URL 参数或 POST 表单)。
 * @param {string|null} submittedPassword
 * @param {object} env
 * @returns {boolean}
 */
function verifyAdminPagePassword(submittedPassword, env) {
    // 功能：用于 HTML 管理页面的密码验证。
    if (!env.ADMIN_PAGE_PASSWORD) {
        if (env.LOGGING_ENABLED === "true") console.error("[verifyAdminPagePassword] ADMIN_PAGE_PASSWORD secret is not configured.");
        return false;
    }
    return submittedPassword === env.ADMIN_PAGE_PASSWORD;
}

/**
 * 生成并返回管理员操作页面 HTML。
 * @param {Request} request
 * @param {object} env
 * @param {object} ctx
 * @param {string} apiVersionPrefix - API 版本前缀，例如 "/v1"
 * @returns {Promise<Response>}
 */
export async function handleAdminDashboard(request, env, ctx, apiVersionPrefix) {
    // 功能：显示 HTML 管理面板，包含触发其他管理员操作的表单。
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[AdminDashboard] Page requested. Method: ${request.method}`);
    }

    const url = new URL(request.url);
    // 密码可以来自 GET 参数 (初次访问) 或 POST 表单的隐藏字段
    let submittedPassword = url.searchParams.get("password");
    if (request.method === 'POST') {
        const formData = await request.formData();
        submittedPassword = formData.get("password") || submittedPassword; // POST 优先
    }
    const adminPageMessage = url.searchParams.get("message") || "";

    if (!env.ADMIN_PAGE_PASSWORD) {
        return new Response("Admin dashboard is misconfigured (password not set).", { status: 500, headers: { 'Content-Type': 'text/plain' } });
    }

    // 如果是 POST 请求，它实际上已经被 index.js 中的特定 action 路由处理了
    // 这个函数主要负责 GET 请求显示页面，或处理 POST 失败后的 GET 重定向。
    // 如果将来有直接 POST 到 /admin 的通用操作，可以在这里处理。
    // 当前模型下，POST 到 /admin/actions/*

    let htmlContent = `
        <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Dashboard</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 20px; background-color: #f0f2f5; color: #1c1e21; font-size: 14px; }
            .container { background-color: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1), 0 8px 16px rgba(0,0,0,0.1); max-width: 700px; margin: auto; }
            h1, h2 { color: #1877f2; } h1 {font-size: 24px;} h2 {font-size: 20px; margin-top:30px; border-bottom: 1px solid #ddd; padding-bottom: 5px;}
            label { display: block; margin-top: 12px; font-weight: 600; }
            input[type="text"], input[type="password"], button[type="submit"] {
                padding: 10px 12px; margin-top: 6px; border-radius: 6px; border: 1px solid #ccd0d5; width: calc(100% - 26px); box-sizing: border-box; font-size:14px;
            }
            button[type="submit"] { background-color: #1877f2; color: white; cursor: pointer; border: none; font-weight: 600; }
            button[type="submit"]:hover { background-color: #166fe5; }
            .action-group { margin-bottom: 25px; padding: 15px; background-color:#f7f8fa; border: 1px solid #ddd; border-radius: 6px;}
            .message { padding: 12px; border-radius: 6px; margin-bottom:15px; font-weight: 500;}
            .success-message { background-color: #e9f5e9; color: #4b844b; border: 1px solid #c8e6c9;}
            .error-message { background-color: #fdecea; color: #c92a2a; border: 1px solid #f5c6cb;}
            a { color: #1877f2; text-decoration: none; } a:hover { text-decoration: underline; }
            hr {border: 0; height: 1px; background-color: #ddd; margin: 20px 0;}
        </style></head><body><div class="container"><h1>Admin Dashboard</h1>
    `;

    if (adminPageMessage) {
        // 根据消息内容简单判断是成功还是错误来应用不同样式 (可以改进)
        const messageClass = adminPageMessage.toLowerCase().includes("fail") || adminPageMessage.toLowerCase().includes("error") ? "error-message" : "success-message";
        htmlContent += `<p class="message ${messageClass}">${escapeHtml(adminPageMessage)}</p>`;
    }

    if (!verifyAdminPagePassword(submittedPassword, env)) {
        htmlContent += `
            <form method="GET" action="${escapeHtml(url.pathname)}">
                <h2>Admin Login</h2>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
                <button type="submit" style="margin-top:15px; width:auto; padding:10px 20px;">Login</button>
            </form>
        `;
    } else {
        // 已登录，显示操作按钮
        const authenticatedAdminPath = `${escapeHtml(url.pathname)}?password=${escapeHtml(submittedPassword)}`;
        htmlContent += `
            <h2>Authenticated Actions</h2>
            <p style="color: green; font-weight: bold;">Authenticated</p>

            <div class="action-group">
                <h3>System Reports & Maintenance</h3>
                <form method="POST" action="${escapeHtml(new URL(apiVersionPrefix + '/admin/actions/trigger-status-report', url.origin).pathname)}">
                    <input type="hidden" name="password" value="${escapeHtml(submittedPassword)}">
                    <button type="submit">Generate & Push Status Report Now</button>
                </form>
                <br>
                <form method="POST" action="${escapeHtml(new URL(apiVersionPrefix + '/admin/actions/trigger-maintenance-check', url.origin).pathname)}">
                    <input type="hidden" name="password" value="${escapeHtml(submittedPassword)}">
                    <button type="submit">Run Maintenance Checks & Report Now</button>
                </form>
            </div>

            <div class="action-group">
                <h3>User Management (via Admin Dashboard)</h3>
                <form method="POST" action="${escapeHtml(new URL(apiVersionPrefix + '/admin/users', url.origin).pathname)}">
                    <p><small>This form uses the <code>X-Admin-API-Key</code> internally for the create user API.</small></p>
                    <input type="hidden" name="password_page" value="${escapeHtml(submittedPassword)}"> <!-- Differentiator if needed, or just for re-auth concept -->
                    <label for="new_username">New Username:</label>
                    <input type="text" id="new_username" name="new_username_dashboard" required placeholder="e.g., newuser_gamma">
                    <button type="submit">Create User via Dashboard</button>
                </form>
                <p style="margin-top:15px;">
                  <a href="${escapeHtml(new URL(apiVersionPrefix + '/admin/users', url.origin).toString())}" 
                     onclick="this.href+='?password='+document.getElementById('page_password_field_for_links')?.value || prompt('Enter Admin Page Password:'); return !!(document.getElementById('page_password_field_for_links')?.value || true);" 
                     target="_blank">View User List (API - JSON, requires password or X-Admin-API-Key)</a>
                </p>
                 <!-- Hidden field to grab password for links if needed, or prompt -->
                <input type="hidden" id="page_password_field_for_links" value="${escapeHtml(submittedPassword)}">

            </div>
            <hr>
            <p><a href="${escapeHtml(url.pathname)}">Logout (Clear Password from URL & Reload)</a></p>
        `;
    }

    htmlContent += `</div></body></html>`;
    return new Response(htmlContent, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}


function escapeHtml(unsafe) {
    // 功能：简单的 HTML 转义函数，防止 XSS。
    if (typeof unsafe !== 'string') return '';
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

/**
 * 主路由函数，处理所有 /admin/* 下的请求。
 * 由 src/index.js 调用。
 * @param {string} subPath - /admin 之后的部分路径 (e.g., "/users", "/users/testuser", "/dashboard")
 * @param {Request} request
 * @param {object} env
 * @param {object} ctx
 * @param {string} apiVersionPrefix - e.g., "/v1"
 * @returns {Promise<Response>}
 */
export async function routeAdminRequests(subPath, request, env, ctx, apiVersionPrefix) {
    // 功能：根据 /admin/ 后的子路径和方法，分发到相应的管理员处理函数。
    // 参数：subPath, request, env, ctx, apiVersionPrefix
    // 返回：Promise<Response>

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[routeAdminRequests] Routing admin request for subPath: '${subPath}', Method: ${request.method}`);
    }

    // HTML Admin Dashboard
    if ((subPath === '' || subPath === '/' || subPath === '/dashboard') && request.method === 'GET') {
        return handleAdminDashboard(request, env, ctx, apiVersionPrefix);
    }

    // Actions triggered by Admin Dashboard (via POST to specific action paths)
    // These paths are now defined in index.js's routeRequest, so this section might be redundant
    // if all actions are routed directly from index.js.
    // However, if admin.js handles its own sub-routing for actions:
    if (subPath.startsWith('/actions/')) {
        // Example: /actions/trigger-status-report
        // These are now better handled directly in index.js's router to simplify password verification logic.
        // If kept here, they would need isAdminPagePassword or similar check.
        return errorResponse(env, `Admin action endpoints should be routed from main index.`, 501); // Not Implemented here
    }


    // JSON API for User Management (/users/*)
    if (subPath.startsWith('/users')) {
        const userAdminPathRemainder = subPath.substring('/users'.length); // e.g., "", "/username", "/username/disable"
        const userAdminPathSegments = userAdminPathRemainder.split('/').filter(Boolean);

        // All these JSON APIs should use X-Admin-API-Key
        if (!isAdminApiRequest(request, env)) {
            return errorResponse(env, "Unauthorized: Admin API Key required for this operation.", 403);
        }

        if (userAdminPathSegments.length === 0) { //  /admin/users
            if (request.method === 'POST') return await handleAdminCreateUser(request, env, ctx);
            if (request.method === 'GET') return await handleAdminListUsers(request, env, ctx);
        } else if (userAdminPathSegments.length === 1) { // /admin/users/{username}
            const usernameParam = userAdminPathSegments[0];
            if (request.method === 'GET') return await handleAdminGetUserInfo(request, env, ctx, usernameParam);
            if (request.method === 'DELETE') return await handleAdminDeleteUser(request, env, ctx, usernameParam);
        } else if (userAdminPathSegments.length === 2) { // /admin/users/{username}/action
            const usernameParam = userAdminPathSegments[0];
            const action = userAdminPathSegments[1];
            if (request.method === 'PUT') { // Or POST depending on preference for actions
                if (action === 'disable') return await handleAdminDisableUser(request, env, ctx, usernameParam);
                if (action === 'enable') return await handleAdminEnableUser(request, env, ctx, usernameParam);
            }
        }
    }
    
    if (env.LOGGING_ENABLED === "true") {
        console.warn(`[routeAdminRequests] Admin subPath '${subPath}' not handled for method ${request.method}.`);
    }
    return errorResponse(env, `Admin endpoint for '${subPath}' not found or method not supported.`, 404);
}

