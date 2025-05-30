// src/index.js
// 描述：Worker 的主入口文件，处理所有路由和请求分发。

import { jsonResponse, errorResponse } from './utils/response.js';
import { verifyAndDecodeDynamicToken } from './utils/crypto.js'; // 用于请求认证
import { handleRequestDynamicToken } from './handlers/auth.js';
import { 
    handleFileUpload, 
    handleFileDownload, 
    handleFileDelete, 
    handleFileList 
} from './handlers/files.js';
import { 
    handleAdminCreateUser, 
    handleAdminListUsers,
    handleAdminGetUserInfo,
    handleAdminDisableUser,
    handleAdminEnableUser,
    handleAdminDeleteUser
} from './handlers/admin.js';

/**
 * 认证中间件/函数：验证请求中的动态令牌。
 * @param {Request} request
 * @param {object} env
 * @param {string} expectedUsername - 从 URL 路径中解析出的用户名，用于与令牌中的用户名比对。
 * @returns {Promise<{valid: boolean, username?: string, payload?: object, message?: string, status?: number}>}
 */
async function authenticateRequestWithDynamicToken(request, env, expectedUsername) {
    // 功能：验证请求头中的 Bearer 动态令牌。
    // (代码和之前一样)
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return { valid: false, message: "Authorization header missing or not Bearer type.", status: 401 };
    }
    const token = authHeader.substring(7); 
    if (!token) {
        return { valid: false, message: "Token missing in Authorization header.", status: 401 };
    }
    if (!env.DYNAMIC_TOKEN_SECRET) {
        if (env.LOGGING_ENABLED === "true") console.error("[authenticateRequestWithDynamicToken] DYNAMIC_TOKEN_SECRET is not configured.");
        return { valid: false, message: "Authentication service misconfigured (secret missing).", status: 500 };
    }
    const verificationResult = await verifyAndDecodeDynamicToken(token, env.DYNAMIC_TOKEN_SECRET);
    if (!verificationResult.valid) {
        return { valid: false, message: verificationResult.error || "Invalid token.", status: 401 };
    }
    if (verificationResult.payload.username !== expectedUsername) {
        if (env.LOGGING_ENABLED === "true") console.warn(`[authenticateRequestWithDynamicToken] Token username mismatch: Token for '${verificationResult.payload.username}', Path for '${expectedUsername}'`);
        return { valid: false, message: "Token not valid for this user resource.", status: 403 };
    }
    return { 
        valid: true, 
        username: verificationResult.payload.username, 
        payload: verificationResult.payload 
    };
}

/**
 * 处理 CORS 预检请求
 * @param {Request} request
 * @returns {Response}
 */
function handleOptions(request) {
    // 功能：响应浏览器的 OPTIONS 请求，用于 CORS。
    // (代码和之前一样)
    const headers = request.headers;
    if (
        headers.get('Origin') !== null &&
        headers.get('Access-Control-Request-Method') !== null &&
        headers.get('Access-Control-Request-Headers') !== null
    ) {
        return new Response(null, {
            headers: {
                'Access-Control-Allow-Origin': '*', // 生产应配置具体源
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Commit-Message, X-API-Key, X-Admin-API-Key',
                'Access-Control-Max-Age': '86400', 
            },
        });
    } else {
        return new Response(null, { headers: { Allow: 'GET, POST, PUT, DELETE, OPTIONS' } });
    }
}


export default {
    async fetch(request, env, ctx) {
        // 功能：Worker 的主 fetch 处理函数，根据请求路由到不同处理器。
        // 参数：request, env, ctx
        // 返回：Promise<Response>

        if (env && env.LOGGING_ENABLED === "true") {
            const { search, महिलाएं , ...rest } = request; // 示例：移除敏感参数或简化日志
            console.log(`[IndexFetch] Request Received: ${request.method} ${request.url} `/*, JSON.stringify(rest)*/);
            const safeEnv = { ...env };
            delete safeEnv.GITHUB_PAT; delete safeEnv.DYNAMIC_TOKEN_SECRET; delete safeEnv.MASTER_ENCRYPTION_KEY; delete safeEnv.ADMIN_API_KEY;
            console.log("[IndexFetch] Current Safe ENV:", JSON.stringify(safeEnv));
        } else if (!env) {
            console.warn("[IndexFetch] env object is undefined. Critical configurations might be missing.");
        }
        
        if (request.method === 'OPTIONS') {
            return handleOptions(request);
        }

        const url = new URL(request.url);
        let pathname = url.pathname;
        const apiVersionPrefix = `/${env.API_VERSION || 'v1'}`; // e.g. /v1

        // 移除路径末尾的斜杠，除非它是根路径 "/"
        if (pathname !== '/' && pathname.endsWith('/')) {
            pathname = pathname.slice(0, -1);
        }

        try {
            // --- 根路径 ---
            if (pathname === '/') {
                return jsonResponse({
                    message: "GitHub File API Worker",
                    version: env.API_VERSION || "v1",
                    status: "operational",
                    documentation: "Please refer to API documentation for endpoint usage." 
                });
            }

            // --- 管理员端点 (/v1/admin/...) ---
            if (pathname.startsWith(`${apiVersionPrefix}/admin/users`)) {
                const adminPathSegments = pathname.substring(`${apiVersionPrefix}/admin/users`.length).split('/').filter(Boolean);
                
                if (adminPathSegments.length === 0) { // /admin/users
                    if (request.method === 'POST') return await handleAdminCreateUser(request, env, ctx);
                    if (request.method === 'GET') return await handleAdminListUsers(request, env, ctx);
                } else if (adminPathSegments.length === 1) { // /admin/users/{username}
                    const usernameParam = adminPathSegments[0];
                    if (request.method === 'GET') return await handleAdminGetUserInfo(request, env, ctx, usernameParam);
                    if (request.method === 'DELETE') return await handleAdminDeleteUser(request, env, ctx, usernameParam);
                } else if (adminPathSegments.length === 2) { // /admin/users/{username}/action
                    const usernameParam = adminPathSegments[0];
                    const action = adminPathSegments[1];
                    if (request.method === 'PUT') {
                        if (action === 'disable') return await handleAdminDisableUser(request, env, ctx, usernameParam);
                        if (action === 'enable') return await handleAdminEnableUser(request, env, ctx, usernameParam);
                    }
                }
                return errorResponse(env, `Admin endpoint ${pathname} with method ${request.method} not found or not supported.`, 404);
            }

            // --- 认证端点 (/v1/auth/...) ---
            if (pathname === `${apiVersionPrefix}/auth/request-token` && request.method === 'POST') {
                return await handleRequestDynamicToken(request, env, ctx); 
            }

            // --- 文件操作端点 (/v1/files/...) ---
            if (pathname.startsWith(`${apiVersionPrefix}/files/`)) {
                const fileOpPathSegments = pathname.substring(`${apiVersionPrefix}/files/`.length).split('/');
                const usernameFromPath = fileOpPathSegments.shift(); 

                if (!usernameFromPath) {
                    return errorResponse(env, "Username is missing in the path for files endpoint.", 400);
                }
                
                const authResult = await authenticateRequestWithDynamicToken(request, env, usernameFromPath);
                if (!authResult.valid) {
                   return errorResponse(env, authResult.message, authResult.status);
                }
                const authenticatedUsername = authResult.username;
                
                const originalFilePath = fileOpPathSegments.join('/'); // Может быть пустым для листинга корневой папки пользователя

                if (request.method === 'PUT' || request.method === 'POST') {
                    if (originalFilePath === '' || originalFilePath.endsWith('/')) return errorResponse(env, "File path must be specified and cannot be a directory for upload.", 400);
                    return await handleFileUpload(request, env, ctx, authenticatedUsername, originalFilePath);
                } else if (request.method === 'GET') {
                    // 如果 originalFilePath 为空 (e.g. /v1/files/user) 或以 / 结尾 (e.g. /v1/files/user/docs/), 视为列表
                    if (originalFilePath === '' || pathname.endsWith('/')) { // pathname 用于捕捉原始 URL 是否以/结尾
                        // 对于 /v1/files/user/ (originalFilePath 为空), dirPath 也为空
                        // 对于 /v1/files/user/docs/ (originalFilePath 为 docs), dirPath 也为 docs
                        const dirPathToList = (originalFilePath.endsWith('/') && originalFilePath.length > 1) ? originalFilePath.slice(0,-1) : originalFilePath;
                        return await handleFileList(request, env, ctx, authenticatedUsername, dirPathToList);
                    } else { // 下载文件
                        return await handleFileDownload(request, env, ctx, authenticatedUsername, originalFilePath);
                    }
                } else if (request.method === 'DELETE') {
                     if (originalFilePath === '' || originalFilePath.endsWith('/')) {
                        return errorResponse(env, "Specific file path (not a directory) is required for deletion.", 400);
                    }
                    return await handleFileDelete(request, env, ctx, authenticatedUsername, originalFilePath);
                } else {
                    return errorResponse(env, `Method ${request.method} not supported for files endpoint ${pathname}.`, 405);
                }
            }

            // --- 未匹配任何路由 ---
            if (env.LOGGING_ENABLED === "true") console.warn(`[IndexFetch] Endpoint not found for: ${request.method} ${pathname}`);
            return errorResponse(env, `The requested endpoint ${pathname} was not found.`, 404);

        } catch (err) {
            // 捕获所有未处理的顶层错误
            if (env.LOGGING_ENABLED === "true") console.error(`[IndexFetch] CRITICAL UNHANDLED ERROR for ${request.url}:`, err.message, err.stack, err);
            return errorResponse(env, `Internal Server Error: An unexpected issue occurred. Ray ID: ${request.headers.get('cf-ray') || 'N/A'}`, 500);
        }
    }
};