// src/index.js
// 描述：Worker 的主入口文件。
import { jsonResponse, errorResponse } from './utils/response.js';
import { getFileContentAndSha, createFileOrUpdateFile, deleteGitHubFile, getFileShaFromPath } from './services/github.js'; // 将会被创建

import { 
    handleFileUpload, 
    handleFileDownload, 
    handleFileDelete, 
    handleFileList 
} from './handlers/files.js'; // 引入新的处理函数

export default {
    async fetch(request, env, ctx) {
        // 全局日志，确保 env 对象存在且 LOGGING_ENABLED 被正确设置
        if (env && env.LOGGING_ENABLED === "true") {
            console.log(`Request Received: ${request.method} ${request.url}`);
            const safeEnv = { ...env };
            // 从日志中移除敏感信息
            delete safeEnv.GITHUB_PAT;
            delete safeEnv.DYNAMIC_TOKEN_SECRET;
            delete safeEnv.MASTER_ENCRYPTION_KEY;
            console.log("Current Safe ENV:", JSON.stringify(safeEnv));
        } else if (!env) {
            console.warn("env object is undefined in fetch handler. Logging and configuration might be affected.");
        }
        
        // 预检请求 (CORS)
        if (request.method === 'OPTIONS') {
            return handleOptions(request);
        }

        const url = new URL(request.url);
        const pathname = url.pathname;
        const apiVersionPrefix = `/${env.API_VERSION || 'v1'}`; // e.g. /v1

        try {
            if (pathname.startsWith(`${apiVersionPrefix}/files/`)) {
                // 路径格式：/v1/files/{username}/{originalFilePath...}
                // 或 /v1/files/{username}/ (用于列出用户根目录)
                const pathSegments = pathname.substring(`${apiVersionPrefix}/files/`.length).split('/');
                const username = pathSegments.shift(); // 第一个段是 username

                if (!username) {
                    return errorResponse(env, "Username is missing in the path.", 400);
                }
                
                // originalFilePath 可以包含子目录，或为空
                const originalFilePath = pathSegments.join('/');

                // TODO: 在这里集成动态令牌认证逻辑
                // const authResult = await authenticateRequestWithDynamicToken(request, env, username);
                // if (!authResult.valid) {
                //    return errorResponse(env, authResult.message, authResult.status);
                // }
                // For now, we proceed without authentication for this simplified version.
                const authenticatedUsername = username; // 假设认证成功且用户就是路径中的 username


                if (request.method === 'PUT' || request.method === 'POST') { // 上传
                    if (!originalFilePath) return errorResponse(env, "File path is required for upload.", 400);
                    return await handleFileUpload(request, env, ctx, authenticatedUsername, originalFilePath);
                } else if (request.method === 'GET') { // 下载或列表
                    if (pathname.endsWith('/') || !originalFilePath) { // 列出目录 (e.g., /v1/files/user/docs/ or /v1/files/user/)
                        const dirPath = originalFilePath.endsWith('/') ? originalFilePath.slice(0,-1) : originalFilePath;
                        return await handleFileList(request, env, ctx, authenticatedUsername, dirPath);
                    } else { // 下载文件
                        return await handleFileDownload(request, env, ctx, authenticatedUsername, originalFilePath);
                    }
                } else if (request.method === 'DELETE') { // 删除
                     if (!originalFilePath || originalFilePath.endsWith('/')) {
                        return errorResponse(env, "Specific file path (not a directory) is required for deletion.", 400);
                    }
                    return await handleFileDelete(request, env, ctx, authenticatedUsername, originalFilePath);
                } else {
                    return errorResponse(env, `Method ${request.method} not supported for /files endpoint.`, 405);
                }

            } else if (pathname === '/') { // 根路径
                return jsonResponse({
                    message: "GitHub File API Worker - Simplified Core Logic",
                    endpoints: [
                        "PUT /v1/files/{username}/{filepath} (Upload)",
                        "GET /v1/files/{username}/{filepath} (Download)",
                        "GET /v1/files/{username}/{directorypath/} (List directory)",
                        "GET /v1/files/{username}/ (List user root)",
                        "DELETE /v1/files/{username}/{filepath} (Delete)"
                    ]
                });
            }

            return errorResponse(env, "Endpoint not found.", 404);

        } catch (err) {
            console.error(`Unhandled error in fetch for ${request.url}:`, err.message, err.stack);
            return errorResponse(env, `Internal Server Error: ${err.message}`, 500);
        }
    }
};

/**
 * 处理 CORS 预检请求
 * @param {Request} request
 * @returns {Response}
 */
function handleOptions(request) {
    const headers = request.headers;
    if (
        headers.get('Origin') !== null &&
        headers.get('Access-Control-Request-Method') !== null &&
        headers.get('Access-Control-Request-Headers') !== null
    ) {
        // Handle CORS preflight requests.
        return new Response(null, {
            headers: {
                'Access-Control-Allow-Origin': '*', // 生产环境应配置为特定源
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Commit-Message, X-API-Key', // 确保包含你客户端会发送的所有头部
                'Access-Control-Max-Age': '86400', // 24 hours
            },
        });
    } else {
        // Handle standard OPTIONS request.
        return new Response(null, {
            headers: {
                Allow: 'GET, POST, PUT, DELETE, OPTIONS',
            },
        });
    }
}

// 辅助函数 (暂时放在这里，后续可以移到 utils/crypto.js 或 utils/converters.js)
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary_string = atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}