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
import { 
    arrayBufferToBase64, // 确保从 crypto.js 导入
    calculateSha256      // 确保从 crypto.js 导入
} from './utils/crypto.js';
import * as githubService from './services/github.js'


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
    },

    /**
     * 新添加的函数：处理 Cron Trigger 调度的事件
     * @param {ScheduledEvent} event - https://developers.cloudflare.com/workers/runtime-apis/scheduled-event/
     * @param {object} env - Worker 环境变量
     * @param {object} ctx - 执行上下文，包含 waitUntil
     * @returns {Promise<void>}
     */
    async scheduled(event, env, ctx) {
        // 功能：由 Cron Trigger 定时触发，执行维护任务和报告生成。
        // 参数：event (包含 cron 和 scheduledTime), env, ctx
        // 返回：Promise<void>
        
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[ScheduledTask] Triggered by cron: ${event.cron} at ${new Date(event.scheduledTime).toISOString()}`);
        }

        // 使用 ctx.waitUntil 确保任务在响应返回后仍能完成
        ctx.waitUntil(
            (async () => {
                try {
                    // --- 1. 整理和分析任务 (简化版) ---
                    if (env.LOGGING_ENABLED === "true") console.log("[ScheduledTask] Starting data analysis and report generation...");
                    
                    let reportContent = `# System Report - ${new Date(event.scheduledTime).toISOString()}\n\n`;

                    // --- 示例：获取用户总数 ---
                    let userCount = 0;
                    if (env.DB) {
                        const countStmt = env.DB.prepare("SELECT COUNT(*) as total_users FROM Users");
                        const countResult = await countStmt.first();
                        userCount = countResult ? countResult.total_users : 0;
                        reportContent += `## User Statistics\n`;
                        reportContent += `- Total Registered Users: ${userCount}\n\n`;
                    } else {
                        reportContent += `- User statistics unavailable (D1 DB not configured).\n\n`;
                    }

                    // --- 示例：获取最近上传活动 (例如过去 24 小时) ---
                    if (env.DB) {
                        reportContent += `## Recent Activity (Last 24 Hours)\n`;
                        const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
                        // 假设 FileActivityLogs 表和列名已按之前建议修改
                        const activityStmt = env.DB.prepare(
                            "SELECT user_id, action_type, original_file_path, status, COUNT(*) as count " +
                            "FROM FileActivityLogs " +
                            "WHERE logged_at >= ? " +
                            "GROUP BY user_id, action_type, original_file_path, status " +
                            "ORDER BY logged_at DESC LIMIT 20"
                        );
                        const { results: recentActivities } = await activityStmt.bind(twentyFourHoursAgo).all();
                        if (recentActivities && recentActivities.length > 0) {
                            reportContent += `| User ID | Action | Path | Status | Count |\n`;
                            reportContent += `|---------|--------|------|--------|-------|\n`;
                            for (const activity of recentActivities) {
                                reportContent += `| ${activity.user_id} | ${activity.action_type} | ${activity.original_file_path.substring(0,50)} | ${activity.status} | ${activity.count} |\n`;
                            }
                        } else {
                            reportContent += `- No significant activity in the last 24 hours.\n`;
                        }
                        reportContent += `\n`;
                    } else {
                         reportContent += `- Recent activity unavailable (D1 DB not configured).\n\n`;
                    }

                    // --- 示例：查找最大文件 (这是一个复杂操作，简化版) ---
                    // 真实实现需要遍历所有用户的 index.json，然后对每个文件调用 GitHub API 获取大小
                    // 这里仅作概念演示，可能只报告索引中的文件数量
                    reportContent += `## Storage Insights (Conceptual)\n`;
                    if (userCount > 0 && env.DB) { // 假设我们需要遍历用户
                        // const allUsersStmt = env.DB.prepare("SELECT user_id FROM Users");
                        // const { results: allUsers } = await allUsersStmt.all();
                        // let totalIndexedFiles = 0;
                        // for (const user of allUsers) {
                        //      const { indexData } = await getUserIndexForScheduledTask(env, user.user_id); // 需要一个不依赖 request 的 getUserIndex 版本
                        //      if (indexData && indexData.files) {
                        //          totalIndexedFiles += Object.keys(indexData.files).length;
                        //      }
                        // }
                        // reportContent += `- Approximate total indexed files: ${totalIndexedFiles}\n`;
                        reportContent += `- Detailed storage analysis (e.g., largest files) requires more complex GitHub crawling and is TBD.\n`;
                    } else {
                        reportContent += `- Storage insights TBD or no users.\n`;
                    }
                     reportContent += `\n`;


                    // --- 2. 将报告推送到 GitHub ---
                    const reportRepoOwner = env.REPORT_REPO_OWNER || env.GITHUB_REPO_OWNER;
                    const reportRepoName = env.REPORT_REPO_NAME || env.GITHUB_REPO_NAME;
                    const reportRepoBranch = env.REPORT_REPO_BRANCH || env.TARGET_BRANCH || "main";
                    const reportPathPrefix = env.REPORT_FILE_PATH_PREFIX || "system_reports/";
                    
                    const reportTimestamp = new Date(event.scheduledTime).toISOString().replace(/:/g, '-').replace(/\..+/, ''); // YYYY-MM-DDTHH-MM-SS
                    const reportFileName = `${reportTimestamp}_system_report.md`;
                    const reportFullPath = `${reportPathPrefix.endsWith('/') ? reportPathPrefix : reportPathPrefix + '/'}${reportFileName}`;
                    
                    const reportContentBase64 = arrayBufferToBase64(new TextEncoder().encode(reportContent));
                    const commitMessage = `System Report: ${reportTimestamp}`;

                    if (env.LOGGING_ENABLED === "true") {
                        console.log(`[ScheduledTask] Pushing report to ${reportRepoOwner}/${reportRepoName}/${reportFullPath} on branch ${reportRepoBranch}`);
                    }

                    // 检查报告文件是否已存在以获取 SHA (用于更新，尽管每次报告名都不同，所以通常是创建)
                    const existingReportSha = (await githubService.getFileShaFromPath(env, reportRepoOwner, reportRepoName, reportFullPath, reportRepoBranch))?.sha;
                    
                    const pushResult = await githubService.createFileOrUpdateFile(
                        env,
                        reportRepoOwner,
                        reportRepoName,
                        reportFullPath,
                        reportRepoBranch,
                        reportContentBase64,
                        commitMessage,
                        existingReportSha // 如果文件名唯一，sha 通常为 null
                    );

                    if (pushResult.error) {
                        console.error(`[ScheduledTask] Failed to push report to GitHub: ${pushResult.message}`, pushResult.details);
                    } else {
                        if (env.LOGGING_ENABLED === "true") {
                            console.log(`[ScheduledTask] System report pushed successfully to GitHub. Commit: ${pushResult.commit?.sha || 'N/A'}`);
                        }
                    }

                    if (env.LOGGING_ENABLED === "true") console.log("[ScheduledTask] Scheduled task finished.");

                } catch (error) {
                    console.error("[ScheduledTask] Error during scheduled execution:", error.message, error.stack);
                    // 在这里可以添加错误通知逻辑，例如发送邮件或消息到监控系统
                }
            })()
        );
    }
};

// --- 辅助函数：用于 scheduled 任务的 getUserIndex (不依赖 HTTP 请求) ---
// 注意：这个函数是 getUserIndex 的一个变体，或者 getUserIndex 本身就可以被这样调用。
// 我们需要确保 githubService 和 base64ToArrayBuffer 在此作用域可用。
async function getUserIndexForScheduledTask(env, username) {
    // 功能：获取指定用户的 index.json 内容 (为计划任务特化或复用)。
    // (此函数与 files.js 中的 getUserIndex 基本相同，确保它能在此处被调用)
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const branch = env.TARGET_BRANCH || "main";
    const indexPath = `${username}/index.json`;

    // 假设 githubService 和 base64ToArrayBuffer 已正确导入或在此文件定义
    const indexFile = await githubService.getFileContentAndSha(env, owner, repo, indexPath, branch);

    if (indexFile && indexFile.content_base64) {
        try {
            const decodedContent = new TextDecoder().decode(base64ToArrayBuffer(indexFile.content_base64));
            const indexData = JSON.parse(decodedContent);
            return { indexData: indexData.files ? indexData : { files: {} }, sha: indexFile.sha };
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") console.error(`[getUserIndexForScheduledTask] User: ${username} - Error parsing index.json:`, e.message);
            return { indexData: { files: {} }, sha: indexFile.sha }; // 返回 SHA 以便能覆盖损坏的索引
        }
    }
    return { indexData: { files: {} }, sha: null };
}