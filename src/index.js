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
        // 功能：根据触发的 CRON 表达式分发到不同的计划任务处理器。
        // 参数：event (包含 cron 和 scheduledTime), env, ctx
        // 返回：Promise<void>

        if (env.LOGGING_ENABLED === "true") {
            console.log(`[ScheduledHandler] Triggered by cron: '${event.cron}' at ${new Date(event.scheduledTime).toISOString()}`);
        }

        let taskPromise;

        // 根据 event.cron 的值来决定执行哪个任务
        switch (event.cron) {
            case "0 */2 * * *": // 每 2 小时
                taskPromise = generateAndPushStatusReport(event, env);
                break;
            case "0 3 * * *":   // 每天凌晨 3 点
                taskPromise = performMaintenanceChecks(event, env);
                break;
            default:
                if (env.LOGGING_ENABLED === "true") {
                    console.warn(`[ScheduledHandler] No specific task defined for cron schedule: '${event.cron}'`);
                }
                return; // 没有匹配的任务，直接返回
        }

        // 使用 ctx.waitUntil 确保异步任务在 Worker 实例结束前完成
        if (taskPromise) {
            ctx.waitUntil(
                taskPromise.catch(error => {
                    // 捕获特定任务中的未处理异常
                    console.error(`[ScheduledHandler] Error during scheduled task for cron '${event.cron}':`, error.message, error.stack);
                    // 可以考虑在这里发送错误通知
                })
            );
        }
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


// --- 新增：特定任务的逻辑函数 ---

/**
 * 生成并推送系统状态报告。
 * @param {ScheduledEvent} event
 * @param {object} env
 * @returns {Promise<void>}
 */
async function generateAndPushStatusReport(event, env) {
    // 功能：生成关于用户统计和近期活动的报告，并推送到 GitHub。
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[StatusReportTask] Starting - Triggered by: ${event.cron}`);
    }
    let reportContent = `# System Status Report - ${new Date(event.scheduledTime).toISOString()}\n\n`;

    // --- 用户统计 ---
    if (env.DB) {
        const countStmt = env.DB.prepare("SELECT COUNT(*) as total_users FROM Users WHERE status = 'active'");
        const countResult = await countStmt.first();
        reportContent += `## User Statistics\n- Active Users: ${countResult ? countResult.total_users : 0}\n\n`;
    } else {
        reportContent += `- User statistics unavailable (D1 DB not configured).\n\n`;
    }

    // --- 近期活动 (例如过去 24 小时) ---
    if (env.DB) {
        reportContent += `## Recent Activity Summary (Last 24 Hours)\n`;
        const activityTimeLimit = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        
        // 1. 按用户和操作类型统计成功次数
        const successActivityStmt = env.DB.prepare(
            "SELECT user_id, action_type, COUNT(*) as success_count, SUM(CASE WHEN action_type = 'upload' THEN file_size_bytes ELSE 0 END) as total_upload_size " +
            "FROM FileActivityLogs " +
            "WHERE logged_at >= ? AND status = 'success' " +
            "GROUP BY user_id, action_type " +
            "ORDER BY success_count DESC, total_upload_size DESC LIMIT 15"
        );
        const { results: successActivities } = await successActivityStmt.bind(activityTimeLimit).all();

        if (successActivities && successActivities.length > 0) {
            reportContent += `### Top Successful Activities:\n`;
            reportContent += `| User ID        | Action   | Success Count | Total Upload Size (Bytes) |\n`;
            reportContent += `|----------------|----------|---------------|---------------------------|\n`;
            for (const activity of successActivities) {
                reportContent += `| ${activity.user_id.padEnd(14)} | ${activity.action_type.padEnd(8)} | ${String(activity.success_count).padEnd(13)} | ${activity.action_type === 'upload' ? String(activity.total_upload_size || 0).padEnd(25) : 'N/A'.padEnd(25)} |\n`;
            }
        } else {
            reportContent += `- No successful activities recorded in the last 24 hours.\n`;
        }
        reportContent += `\n`;

        // 2. 按用户和操作类型统计失败次数
        const failureActivityStmt = env.DB.prepare(
            "SELECT user_id, action_type, COUNT(*) as failure_count, GROUP_CONCAT(DISTINCT SUBSTR(error_message, 1, 30)) as common_errors " + // 显示常见的错误信息（截断）
            "FROM FileActivityLogs " +
            "WHERE logged_at >= ? AND status = 'failure' " +
            "GROUP BY user_id, action_type " +
            "ORDER BY failure_count DESC LIMIT 10"
        );
        const { results: failureActivities } = await failureActivityStmt.bind(activityTimeLimit).all();

        if (failureActivities && failureActivities.length > 0) {
            reportContent += `### Top Failed Activities:\n`;
            reportContent += `| User ID        | Action   | Failure Count | Common Errors (truncated)    |\n`;
            reportContent += `|----------------|----------|---------------|------------------------------|\n`;
            for (const activity of failureActivities) {
                reportContent += `| ${activity.user_id.padEnd(14)} | ${activity.action_type.padEnd(8)} | ${String(activity.failure_count).padEnd(13)} | ${(activity.common_errors || 'N/A').padEnd(28)} |\n`;
            }
        } else {
            reportContent += `- No failed activities recorded in the last 24 hours.\n`;
        }
        reportContent += `\n`;

        // 3. 最近的几条详细日志 (示例)
        reportContent += `### Latest Activity Details (Sample - Max 10):\n`;
        const latestDetailsStmt = env.DB.prepare(
            "SELECT logged_at, user_id, action_type, SUBSTR(original_file_path, 1, 40) as path_preview, status, SUBSTR(error_message, 1, 30) as error_preview " +
            "FROM FileActivityLogs " +
            "WHERE logged_at >= ? " +
            "ORDER BY logged_at DESC LIMIT 10"
        );
        const { results: latestDetails } = await latestDetailsStmt.bind(activityTimeLimit).all();
        if (latestDetails && latestDetails.length > 0) {
            reportContent += `| Timestamp (UTC)       | User ID        | Action   | Path Preview (40 chars)      | Status  | Error Preview (30 chars) |\n`;
            reportContent += `|-----------------------|----------------|----------|------------------------------|---------|--------------------------|\n`;
            for (const detail of latestDetails) {
                const ts = detail.logged_at.replace('T', ' ').substring(0, 19);
                reportContent += `| ${ts.padEnd(21)} | ${detail.user_id.padEnd(14)} | ${detail.action_type.padEnd(8)} | ${(detail.path_preview || '').padEnd(28)} | ${detail.status.padEnd(7)} | ${(detail.error_preview || 'N/A').padEnd(24)} |\n`;
            }
        } else {
            reportContent += `- No detailed activity entries in the last 24 hours.\n`;
        }
        reportContent += `\n`;


    } else {
         reportContent += `- Recent activity unavailable (D1 DB not configured).\n\n`;
    }
    
    // ... (报告推送逻辑和之前一样) ...
    const reportRepoOwner = env.REPORT_REPO_OWNER || env.GITHUB_REPO_OWNER;
    const reportRepoName = env.REPORT_REPO_NAME || env.GITHUB_REPO_NAME;
    const reportRepoBranch = env.REPORT_REPO_BRANCH || env.TARGET_BRANCH || "main";
    const reportPathPrefix = env.STATUS_REPORT_PATH_PREFIX || "system_reports/status/";
    
    const reportTimestamp = new Date(event.scheduledTime).toISOString().replace(/:/g, '-').replace(/\..+/, '');
    const reportFileName = `${reportTimestamp}_status_report.md`;
    const reportFullPath = `${reportPathPrefix.endsWith('/') ? reportPathPrefix : reportPathPrefix + '/'}${reportFileName}`;
    
    const reportContentBase64 = arrayBufferToBase64(new TextEncoder().encode(reportContent)); // 确保 arrayBufferToBase64 从 crypto.js 导入
    const commitMessage = `System Status Report: ${reportTimestamp}`;

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[StatusReportTask] Attempting to push status report to: ${reportRepoOwner}/${reportRepoName} - ${reportFullPath}`);
    }

    const existingReportSha = (await githubService.getFileShaFromPath(env, reportRepoOwner, reportRepoName, reportFullPath, reportRepoBranch))?.sha;
    const pushResult = await githubService.createFileOrUpdateFile(env, reportRepoOwner, reportRepoName, reportFullPath, reportRepoBranch, reportContentBase64, commitMessage, existingReportSha);

    if (pushResult.error) {
        console.error(`[StatusReportTask] Failed to push status report: ${pushResult.message}`, pushResult.details ? JSON.stringify(pushResult.details).substring(0,500) : '');
    } else {
        if (env.LOGGING_ENABLED === "true") console.log(`[StatusReportTask] Status report pushed. Commit: ${pushResult.commit?.sha || (pushResult.content?.sha || 'N/A')}`);
    }
}


/**
 * 执行数据维护和一致性检查，并生成报告。
 * @param {ScheduledEvent} event
 * @param {object} env
 * @returns {Promise<void>}
 */
async function performMaintenanceChecks(event, env) {
    // 功能：检查数据一致性 (例如，索引与物理文件)，并生成维护报告。
    // 参数：event, env
    // 返回：Promise<void>
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[MaintenanceTask] Starting - Triggered by: ${event.cron}`);
    }
    let reportContent = `# Data Maintenance & Consistency Report - ${new Date(event.scheduledTime).toISOString()}\n\n`;
    let issuesFound = 0;

    // 这是一个非常复杂的操作，需要小心设计以避免性能问题和 API 限流
    // 简化版：仅报告有多少用户的索引文件存在
    reportContent += `## Index File Existence Check (Simplified)\n`;
    if (env.DB) {
        const usersStmt = env.DB.prepare("SELECT user_id FROM Users WHERE status = 'active'");
        const { results: activeUsers } = await usersStmt.all();
        if (activeUsers && activeUsers.length > 0) {
            reportContent += `Checking index files for ${activeUsers.length} active users...\n`;
            for (const user of activeUsers) {
                const indexPath = `${user.user_id}/index.json`;
                const indexFileMeta = await githubService.getFileShaFromPath(
                    env, 
                    env.GITHUB_REPO_OWNER, 
                    env.GITHUB_REPO_NAME, 
                    indexPath, 
                    env.TARGET_BRANCH || "main"
                );
                if (!indexFileMeta) {
                    reportContent += `- **ISSUE**: User '${user.user_id}' - index.json NOT FOUND at '${indexPath}'.\n`;
                    issuesFound++;
                } else {
                    // reportContent += `- User '${user.user_id}' - index.json found.\n`; // 可选，如果用户很多会使报告冗长
                }
            }
            if (issuesFound === 0) {
                reportContent += `- All checked active users have an index.json file.\n`;
            } else {
                reportContent += `\n**Total issues found: ${issuesFound}**\n`;
            }
        } else {
            reportContent += `- No active users to check.\n`;
        }
    } else {
        reportContent += `- Maintenance checks requiring D1 (Users table) skipped.\n`;
    }
    reportContent += `\n**Note**: Full consistency checks (orphaned files, broken index links) are complex and not fully implemented in this report.\n`;
    
    // 推送报告
    const reportRepoOwner = env.REPORT_REPO_OWNER || env.GITHUB_REPO_OWNER;
    const reportRepoName = env.REPORT_REPO_NAME || env.GITHUB_REPO_NAME;
    const reportRepoBranch = env.REPORT_REPO_BRANCH || env.TARGET_BRANCH || "main";
    const reportPathPrefix = env.MAINTENANCE_REPORT_PATH_PREFIX || "system_reports/maintenance/"; // 使用不同的前缀

    const reportTimestamp = new Date(event.scheduledTime).toISOString().replace(/:/g, '-').replace(/\..+/, '');
    const reportFileName = `${reportTimestamp}_maintenance_report.md`;
    const reportFullPath = `${reportPathPrefix.endsWith('/') ? reportPathPrefix : reportPathPrefix + '/'}${reportFileName}`;
    
    const reportContentBase64 = arrayBufferToBase64(new TextEncoder().encode(reportContent));
    const commitMessage = `System Maintenance Report: ${reportTimestamp}`;

    const existingReportSha = (await githubService.getFileShaFromPath(env, reportRepoOwner, reportRepoName, reportFullPath, reportRepoBranch))?.sha;
    const pushResult = await githubService.createFileOrUpdateFile(env, reportRepoOwner, reportRepoName, reportFullPath, reportRepoBranch, reportContentBase64, commitMessage, existingReportSha);

    if (pushResult.error) {
        console.error(`[MaintenanceTask] Failed to push maintenance report: ${pushResult.message}`, pushResult.details);
    } else {
        if (env.LOGGING_ENABLED === "true") console.log(`[MaintenanceTask] Maintenance report pushed. Commit: ${pushResult.commit?.sha || 'N/A'}`);
    }
}



