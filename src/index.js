// src/index.js
// 描述：Worker 的主入口文件。
import { jsonResponse, errorResponse } from './utils/response.js';
import { getFileContentAndSha, createFileOrUpdateFile, deleteGitHubFile, getFileShaFromPath } from './services/github.js'; // 将会被创建

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

        // 基本的 API 版本和路径结构：/v1/files/{username}/{filePath...}
        // 或者 /v1/auth/request-token
        // 我们暂时不实现完整的路由和认证，先让 GitHub 服务能被测试

        try {
            // 测试 GitHub 服务 (临时端点，后续会集成到 files.js 和 auth.js)
            if (pathname.startsWith('/test-github/get/')) {
                // e.g., /test-github/get/your-username/path/to/file.txt
                const parts = pathname.substring('/test-github/get/'.length).split('/');
                const usernameTest = parts.shift(); // 这里的 username 暂时不用，因为我们直接操作仓库路径
                const filePathTest = parts.join('/');
                if (!filePathTest) return errorResponse(env, "File path is required for test-github/get", 400);
                
                const owner = env.GITHUB_REPO_OWNER;
                const repo = env.GITHUB_REPO_NAME;
                const branch = env.TARGET_BRANCH || "main";
                
                const fileData = await getFileContentAndSha(env, owner, repo, filePathTest, branch);
                if (fileData) {
                    // 如果是文本文件，可以尝试解码显示
                    let contentPreview = "Binary or too large to preview";
                    if (fileData.content && !fileData.encoding && fileData.size < 1024 * 5) { // 假设是 UTF-8 且小于 5KB
                         try {
                            contentPreview = new TextDecoder().decode(base64ToArrayBuffer(fileData.content_base64));
                         } catch (e) { /* ignore */ }
                    }
                    return jsonResponse({ ...fileData, content_preview: contentPreview });
                }
                return errorResponse(env, `File not found or error fetching: ${filePathTest}`, 404);

            } else if (pathname.startsWith('/test-github/put/')) {
                 // e.g., POST to /test-github/put/your-username/path/to/new-file.txt with text body
                if (request.method !== 'POST' && request.method !== 'PUT') return errorResponse(env, "Method not allowed for test-github/put, use POST or PUT", 405);

                const parts = pathname.substring('/test-github/put/'.length).split('/');
                const usernameTest = parts.shift();
                const filePathTest = parts.join('/');
                if (!filePathTest) return errorResponse(env, "File path is required for test-github/put", 400);

                const owner = env.GITHUB_REPO_OWNER;
                const repo = env.GITHUB_REPO_NAME;
                const branch = env.TARGET_BRANCH || "main";
                const fileContentText = await request.text();
                if (!fileContentText) return errorResponse(env, "Request body is empty", 400);

                const contentBase64 = arrayBufferToBase64(new TextEncoder().encode(fileContentText));
                const commitMessage = `Test PUT: ${filePathTest}`;
                
                // 检查文件是否存在以获取 SHA (用于更新)
                const existingFile = await getFileShaFromPath(env, owner, repo, filePathTest, branch);
                const existingSha = existingFile ? existingFile.sha : null;

                const result = await createFileOrUpdateFile(env, owner, repo, filePathTest, branch, contentBase64, commitMessage, existingSha);
                return jsonResponse(result, result.content ? (existingSha ? 200 : 201) : 500);
            
            } else if (pathname.startsWith('/test-github/delete/')) {
                // e.g., DELETE to /test-github/delete/your-username/path/to/file.txt
                if (request.method !== 'DELETE') return errorResponse(env, "Method not allowed for test-github/delete, use DELETE", 405);

                const parts = pathname.substring('/test-github/delete/'.length).split('/');
                const usernameTest = parts.shift();
                const filePathTest = parts.join('/');
                if (!filePathTest) return errorResponse(env, "File path is required for test-github/delete", 400);

                const owner = env.GITHUB_REPO_OWNER;
                const repo = env.GITHUB_REPO_NAME;
                const branch = env.TARGET_BRANCH || "main";
                const commitMessage = `Test DELETE: ${filePathTest}`;

                // 需要文件的 SHA 来删除
                const fileToDelete = await getFileShaFromPath(env, owner, repo, filePathTest, branch);
                if (!fileToDelete || !fileToDelete.sha) {
                    return errorResponse(env, `File not found or SHA missing, cannot delete: ${filePathTest}`, 404);
                }

                const result = await deleteGitHubFile(env, owner, repo, filePathTest, branch, fileToDelete.sha, commitMessage);
                if (result && result.commit) { // GitHub delete API returns commit info and content=null on success
                     return jsonResponse({ message: `File ${filePathTest} deleted successfully.`, commit: result.commit });
                }
                return errorResponse(env, `Failed to delete ${filePathTest}: ${result.message || 'Unknown error'}`, result.status || 500);
            }

            // 默认根路径响应
            if (pathname === '/') {
                return jsonResponse({
                    message: "Welcome to GitHub File API Worker!",
                    repository: `https://github.com/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}`,
                    targetBranch: env.TARGET_BRANCH || "main",
                    testEndpoints: [
                        "/test-github/get/{username}/{filepath}",
                        "POST /test-github/put/{username}/{filepath} (with text body)",
                        "DELETE /test-github/delete/{username}/{filepath}"
                    ]
                });
            }

            return errorResponse(env, "Endpoint not found.", 404);

        } catch (err) {
            console.error("Unhandled error in fetch:", err.message, err.stack);
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