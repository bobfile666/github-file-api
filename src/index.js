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
 */
async function authenticateRequestWithDynamicToken(request, env, expectedUsername) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return { valid: false, message: "Authorization header missing or not Bearer type.", status: 401 };
    }
    const token = authHeader.substring(7); 
    if (!token) {
        return { valid: false, message: "Token missing in Authorization header.", status: 401 };
    }
    if (!env.DYNAMIC_TOKEN_SECRET) {
        if (env.LOGGING_ENABLED === "true") console.error("[authenticateRequest] DYNAMIC_TOKEN_SECRET is not configured.");
        return { valid: false, message: "Authentication service misconfigured.", status: 500 };
    }
    const verificationResult = await verifyAndDecodeDynamicToken(token, env.DYNAMIC_TOKEN_SECRET); // from crypto.js
    if (!verificationResult.valid) {
        return { valid: false, message: verificationResult.error || "Invalid token.", status: 401 };
    }
    if (verificationResult.payload.username !== expectedUsername) {
        if (env.LOGGING_ENABLED === "true") console.warn(`[authenticateRequest] Token username mismatch: Token for '${verificationResult.payload.username}', Path for '${expectedUsername}'`);
        return { valid: false, message: "Token not valid for this user resource.", status: 403 };
    }
    return { valid: true, username: verificationResult.payload.username, payload: verificationResult.payload };
}
/**
 * 处理 CORS 预检请求
 */
function handleOptions(request) {
    const headers = request.headers;
    if (headers.get('Origin') !== null && headers.get('Access-Control-Request-Method') !== null && headers.get('Access-Control-Request-Headers') !== null) {
        return new Response(null, {
            headers: {
                'Access-Control-Allow-Origin': '*', 
                'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Commit-Message, X-API-Key, X-Admin-API-Key',
                'Access-Control-Max-Age': '86400', 
            },
        });
    } else {
        return new Response(null, { headers: { Allow: 'GET, POST, PUT, DELETE, OPTIONS' } });
    }
}

// --- 主路由分发逻辑 ---
async function routeRequest(request, env, ctx) {
    // 功能：解析请求并将其分发到相应的处理器。
    // 参数：request, env, ctx
    // 返回：Promise<Response>
    const url = new URL(request.url);
    let pathname = url.pathname;
    const apiVersionPrefix = `/${env.API_VERSION || 'v1'}`;

    // 规范化路径：移除末尾斜杠 (除非是根路径)
    if (pathname !== '/' && pathname.endsWith('/')) {
        pathname = pathname.slice(0, -1);
    }

    // 根路径
    if (pathname === '/') {
        return jsonResponse({
            message: "GitHub File API Worker",
            version: env.API_VERSION || "v1",
            status: "operational"
        });
    }

    // --- 管理员路由 (/v1/admin/...) ---
    if (pathname.startsWith(`${apiVersionPrefix}/admin`)) {
        const adminSubPath = pathname.substring(`${apiVersionPrefix}/admin`.length);
        const adminPathSegments = adminSubPath.split('/').filter(Boolean);

        // GET /v1/admin (或 /v1/admin/dashboard) - 显示 HTML 仪表盘
        if ((adminSubPath === '' || adminSubPath === '/dashboard') && request.method === 'GET') {
            return handleAdminDashboard(request, env, ctx);
        }
        // POST /v1/admin (或 /v1/admin/dashboard) - 处理仪表盘表单提交
        if ((adminSubPath === '' || adminSubPath === '/dashboard') && request.method === 'POST') {
             return handleAdminDashboard(request, env, ctx); // handleAdminDashboard 内部分处理 POST
        }

        // POST /v1/admin/actions/trigger-status-report
        if (adminSubPath === '/actions/trigger-status-report' && request.method === 'POST') {
            const formData = await request.formData(); // Admin dashboard POSTs form data
            const password = formData.get("password");
            if (!env.ADMIN_PAGE_PASSWORD || password !== env.ADMIN_PAGE_PASSWORD) return errorResponse(env, "Invalid password for action.", 403);
            if (env.LOGGING_ENABLED === "true") console.log("[AdminActionTrigger] Manually triggering status report via HTTP POST.");
            ctx.waitUntil(generateAndPushStatusReport({ cron: "manual_admin_http", scheduledTime: Date.now() }, env));
            const redirectUrl = new URL(`${apiVersionPrefix}/admin`, url.origin);
            redirectUrl.searchParams.set("message", "Status report generation triggered.");
            redirectUrl.searchParams.set("password", password); // Preserve password for next action
            return Response.redirect(redirectUrl.toString(), 303);
        }
        // POST /v1/admin/actions/trigger-maintenance-check
        if (adminSubPath === '/actions/trigger-maintenance-check' && request.method === 'POST') {
            const formData = await request.formData();
            const password = formData.get("password");
            if (!env.ADMIN_PAGE_PASSWORD || password !== env.ADMIN_PAGE_PASSWORD) return errorResponse(env, "Invalid password for action.", 403);
            if (env.LOGGING_ENABLED === "true") console.log("[AdminActionTrigger] Manually triggering maintenance check via HTTP POST.");
            ctx.waitUntil(performMaintenanceChecks({ cron: "manual_admin_http", scheduledTime: Date.now() }, env));
            const redirectUrl = new URL(`${apiVersionPrefix}/admin`, url.origin);
            redirectUrl.searchParams.set("message", "Maintenance check triggered.");
            redirectUrl.searchParams.set("password", password);
            return Response.redirect(redirectUrl.toString(), 303);
        }
        
        // /v1/admin/users... (JSON API, 需要 X-Admin-API-Key)
        if (adminPathSegments[0] === 'users') {
            const userAdminPathSegments = adminPathSegments.slice(1);
            if (userAdminPathSegments.length === 0) { // /admin/users
                if (request.method === 'POST') return await handleAdminCreateUser(request, env, ctx);
                if (request.method === 'GET') return await handleAdminListUsers(request, env, ctx);
            } else if (userAdminPathSegments.length === 1) { // /admin/users/{username}
                const usernameParam = userAdminPathSegments[0];
                if (request.method === 'GET') return await handleAdminGetUserInfo(request, env, ctx, usernameParam);
                if (request.method === 'DELETE') return await handleAdminDeleteUser(request, env, ctx, usernameParam);
            } else if (userAdminPathSegments.length === 2) { // /admin/users/{username}/action
                const usernameParam = userAdminPathSegments[0];
                const action = userAdminPathSegments[1];
                if (request.method === 'PUT') {
                    if (action === 'disable') return await handleAdminDisableUser(request, env, ctx, usernameParam);
                    if (action === 'enable') return await handleAdminEnableUser(request, env, ctx, usernameParam);
                }
            }
        }
        return errorResponse(env, `Admin endpoint ${pathname} not found or method ${request.method} not supported.`, 404);
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
        
        const originalFilePathParts = fileOpPathSegments.filter(Boolean); // filter(Boolean) to remove empty segments from trailing slash
        const originalFilePath = originalFilePathParts.join('/');
        const isDirectoryListRequest = pathname.endsWith('/') || originalFilePathParts.length === 0 && pathname.substring(`${apiVersionPrefix}/files/`.length).split('/').length === 1;


        if (request.method === 'PUT' || request.method === 'POST') {
            if (originalFilePath === '' || pathname.endsWith('/')) return errorResponse(env, "File path must be specified and cannot be a directory path for upload.", 400);
            return await handleFileUpload(request, env, ctx, authenticatedUsername, originalFilePath);
        } else if (request.method === 'GET') {
            if (isDirectoryListRequest) {
                return await handleFileList(request, env, ctx, authenticatedUsername, originalFilePath);
            } else { 
                return await handleFileDownload(request, env, ctx, authenticatedUsername, originalFilePath);
            }
        } else if (request.method === 'DELETE') {
             if (originalFilePath === '' || pathname.endsWith('/')) {
                return errorResponse(env, "Specific file path (not a directory path) is required for deletion.", 400);
            }
            return await handleFileDelete(request, env, ctx, authenticatedUsername, originalFilePath);
        } else {
            return errorResponse(env, `Method ${request.method} not supported for files endpoint ${pathname}.`, 405);
        }
    }

    // --- 未匹配任何路由 ---
    if (env.LOGGING_ENABLED === "true") console.warn(`[RouteRequest] Endpoint not found for: ${request.method} ${pathname}`);
    return errorResponse(env, `The requested endpoint ${pathname} was not found.`, 404);
}


export default {
    async fetch(request, env, ctx) {
        // 功能：Worker 的主 fetch 处理函数，调用路由分发器。
        if (env && env.LOGGING_ENABLED === "true") {
            console.log(`[IndexFetch] START: ${request.method} ${request.url}`);
        }
        
        if (request.method === 'OPTIONS') {
            return handleOptions(request);
        }

        try {
            return await routeRequest(request, env, ctx);
        } catch (err) {
            // 捕获所有未处理的顶层错误
            const rayId = request.headers.get('cf-ray');
            err.rayId = rayId; 
            if (env.LOGGING_ENABLED === "true") console.error(`[IndexFetch CRITICAL] Unhandled error for ${request.method} ${request.url} (Ray ID: ${rayId}):`, err.message, err.stack, err);
            
            ctx.waitUntil(logErrorToGitHub(env, 'GlobalFetchError', err, `${request.method} ${request.url}`));
            
            return errorResponse(env, `Internal Server Error. Please contact support if the issue persists. Ray ID: ${rayId || 'N/A'}`, 500);
        } finally {
            if (env && env.LOGGING_ENABLED === "true") {
                console.log(`[IndexFetch] END: ${request.method} ${request.url}`);
            }
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
        // (此函数的逻辑和之前一样，包含 switch(event.cron) 和调用任务函数)
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[ScheduledHandler] START - Cron: '${event.cron}' at ${new Date(event.scheduledTime).toISOString()}`);
        }
        let taskPromise;
        switch (event.cron) {
            case "0 */2 * * *": 
                taskPromise = generateAndPushStatusReport(event, env);
                break;
            case "0 3 * * *":   
                taskPromise = performMaintenanceChecks(event, env);
                break;
            default:
                if (env.LOGGING_ENABLED === "true") console.warn(`[ScheduledHandler] No task for cron: '${event.cron}'`);
                return; 
        }
        if (taskPromise) {
            ctx.waitUntil(
                taskPromise
                .then(() => {
                    if (env.LOGGING_ENABLED === "true") console.log(`[ScheduledHandler] END - Successfully completed task for cron '${event.cron}'.`);
                })
                .catch(error => {
                    if (env.LOGGING_ENABLED === "true") console.error(`[ScheduledHandler CRITICAL] Error during scheduled task for cron '${event.cron}':`, error.message, error.stack);
                    ctx.waitUntil(logErrorToGitHub(env, 'ScheduledTaskExecutionError', error, `Cron: ${event.cron}`));
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

/**
 * 辅助函数：将 GitHub 上的文件移动/重命名 (通过复制和删除实现)
 * @param {object} env
 * @param {string} owner
 * @param {string} repo
 * @param {string} branch
 * @param {string} oldPath - 旧文件路径
 * @param {string} newPath - 新文件路径
 * @param {string} commitMessagePrefix - 提交信息前缀
 * @returns {Promise<boolean>} 是否成功
 */
async function moveGitHubFile(env, owner, repo, branch, oldPath, newPath, commitMessagePrefix) {
    // 功能：实现 GitHub 文件的移动（通过复制内容到新路径然后删除旧文件）。
    // 参数：env, owner, repo, branch, oldPath, newPath, commitMessagePrefix
    // 返回：Promise<boolean> - 操作是否成功。

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[moveGitHubFile] Attempting to move '${oldPath}' to '${newPath}'`);
    }
    // 1. 获取旧文件内容和 SHA
    const oldFileData = await githubService.getFileContentAndSha(env, owner, repo, oldPath, branch);
    if (!oldFileData || !oldFileData.content_base64) {
        if (env.LOGGING_ENABLED === "true") {
            console.warn(`[moveGitHubFile] Source file '${oldPath}' not found or content empty. Cannot move.`);
        }
        return false; // 源文件不存在，无需移动
    }

    // 2. 在新路径创建文件 (使用旧文件内容)
    const createMessage = `${commitMessagePrefix} - Copy from ${oldPath}`;
    const createResult = await githubService.createFileOrUpdateFile(
        env, owner, repo, newPath, branch, 
        oldFileData.content_base64, 
        createMessage, 
        null // 总是创建新文件，不提供 SHA
    );

    if (createResult.error) {
        console.error(`[moveGitHubFile] Failed to create new file at '${newPath}': ${createResult.message}`, createResult.details);
        return false;
    }
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[moveGitHubFile] File content copied to '${newPath}'.`);
    }

    // 3. 删除旧文件
    const deleteMessage = `${commitMessagePrefix} - Delete original after copy to ${newPath}`;
    const deleteResult = await githubService.deleteGitHubFile(
        env, owner, repo, oldPath, branch, 
        oldFileData.sha, // 使用旧文件的 SHA 来删除
        deleteMessage
    );

    if (deleteResult.error) {
        console.error(`[moveGitHubFile] Failed to delete old file '${oldPath}' after copying: ${deleteResult.message}`, deleteResult.details);
        // 新文件已创建，但旧文件删除失败。这是一个半成功状态。
        // 可以选择返回 true 并记录警告，或者返回 false。
        // 为简单起见，如果删除失败，我们仍认为移动操作部分失败，但数据已在新位置。
        return false; // 或者标记为部分成功
    }
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[moveGitHubFile] Old file '${oldPath}' deleted successfully.`);
    }
    return true;
}

/**
 * 新增辅助函数：将错误日志推送到 GitHub
 * @param {object} env
 * @param {string} errorType - 'ScheduledTaskError' or 'FetchHandlerError'
 * @param {Error} errorObject - 错误对象
 * @param {string} [additionalContext='N/A'] - 额外的上下文信息，如 cron 表达式或请求 URL
 * @returns {Promise<void>}
 */
async function logErrorToGitHub(env, errorType, errorObject, additionalContext = 'N/A') {
    // 功能：将捕获到的严重错误信息格式化并尝试推送到 GitHub 仓库的特定错误日志文件。
    // 参数：env, errorType, errorObject, additionalContext
    // 返回：Promise<void>
    if (env.LOGGING_ENABLED !== "true" && errorType !== 'CRITICAL_ERROR_LOGGING_TO_GITHUB') { // 允许一个特殊标记来强制记录
        // 通常情况下，如果普通日志关闭，错误日志到 GitHub 也可能关闭，除非特定需要
        // console.warn("[logErrorToGitHub] LOGGING_ENABLED is false, skipping GitHub error log unless critical.");
        // return; // 根据策略决定是否在此处返回
    }

    try {
        const timestamp = new Date().toISOString();
        const errorLogContent = `
# ${errorType} - ${timestamp}

## Error Message
\`\`\`
${errorObject.message || 'No message'}
\`\`\`

## Stack Trace
\`\`\`
${errorObject.stack || 'No stack trace'}
\`\`\`

## Additional Context
- Trigger/Request: ${additionalContext}
- Ray ID (if available from request headers): ${errorObject.rayId || 'N/A'} 

## Environment Snippet (Non-Sensitive)
- GITHUB_REPO_OWNER: ${env.GITHUB_REPO_OWNER}
- TARGET_BRANCH: ${env.TARGET_BRANCH}
- API_VERSION: ${env.API_VERSION || 'v1'}
---
`;
        const errorLogOwner = env.REPORT_REPO_OWNER || env.GITHUB_REPO_OWNER;
        const errorLogRepo = env.REPORT_REPO_NAME || env.GITHUB_REPO_NAME;
        const errorLogBranch = env.REPORT_REPO_BRANCH || env.TARGET_BRANCH || "main";
        const errorLogPathPrefix = "system_errors/";
        const errorFileName = `${timestamp.replace(/:/g, '-').replace(/\..+/, '')}_${errorType.toLowerCase().replace(/\s+/g, '_')}.md`;
        const errorLogFullPath = `${errorLogPathPrefix}${errorFileName}`;

        const contentBase64 = arrayBufferToBase64(new TextEncoder().encode(errorLogContent));
        const commitMessage = `Error Log: ${errorType} at ${timestamp}`;

        console.error(`[CRITICAL ERROR] Attempting to log to GitHub: ${errorLogFullPath}. Error: ${errorObject.message}`);

        // 我们不获取 SHA，总是尝试创建新文件，因为错误文件名包含时间戳，不太可能重复
        const pushResult = await githubService.createFileOrUpdateFile(
            env, errorLogOwner, errorLogRepo, errorLogFullPath, errorLogBranch,
            contentBase64, commitMessage, null
        );

        if (pushResult.error) {
            console.error(`[CRITICAL ERROR] FAILED to push error log to GitHub: ${pushResult.message}`, pushResult.details);
        } else {
            console.log(`[CRITICAL ERROR] Error log pushed successfully to GitHub: ${errorLogFullPath}`);
        }
    } catch (loggingError) {
        // 如果记录错误到 GitHub 本身也失败了，只能在控制台打印
        console.error("[CRITICAL ERROR] FAILED to log error to GitHub (secondary error):", loggingError.message, loggingError.stack);
        console.error("[CRITICAL ERROR] Original error was:", errorObject.message, errorObject.stack);
    }
}

/**
 * 生成并推送系统状态报告。
 * (此函数包含用户统计、近期活动等报告内容生成，以及将报告归档和推送到 GitHub 的逻辑)
 * @param {ScheduledEvent | { cron: string, scheduledTime: number }} event - 调度事件或模拟事件
 * @param {object} env - Worker 环境变量
 * @returns {Promise<void>}
 */
async function generateAndPushStatusReport(event, env) {
    // 功能：生成关于用户统计和近期活动的报告，归档旧报告，并推送到 GitHub。
    // (此函数的完整代码已在之前的回答中提供，包含报告内容生成和 GitHub 推送逻辑)
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[StatusReportTask] Starting - Triggered by: ${event.cron}`);
    }
    const reportTimestampDate = new Date(event.scheduledTime);
    const reportTimestampISO = reportTimestampDate.toISOString();
    let reportContent = `# System Status Report - ${reportTimestampISO}\n\nCron: ${event.cron}\n\n`;

    // --- 用户统计 ---
    if (env.DB) {
        try {
            const countStmt = env.DB.prepare("SELECT COUNT(*) as total_users FROM Users WHERE status = 'active'");
            const countResult = await countStmt.first();
            reportContent += `## User Statistics\n- Active Users: ${countResult ? countResult.total_users : 0}\n\n`;
        } catch (dbError) {
            reportContent += `## User Statistics\n- Error fetching user statistics: ${dbError.message}\n\n`;
            if (env.LOGGING_ENABLED === "true") console.error("[StatusReportTask] D1 Error fetching user count:", dbError);
        }
    } else {
        reportContent += `- User statistics unavailable (D1 DB not configured).\n\n`;
    }

    // --- 近期活动 (例如过去 24 小时) ---
    if (env.DB) {
        reportContent += `## Recent Activity Summary (Last 24 Hours)\n`;
        const activityTimeLimit = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        try {
            // 成功活动
            const successActivityStmt = env.DB.prepare(
                "SELECT user_id, action_type, COUNT(*) as success_count, SUM(CASE WHEN action_type = 'upload' THEN file_size_bytes ELSE 0 END) as total_upload_size " +
                "FROM FileActivityLogs WHERE logged_at >= ? AND status = 'success' GROUP BY user_id, action_type ORDER BY success_count DESC, total_upload_size DESC LIMIT 15"
            );
            const { results: successActivities } = await successActivityStmt.bind(activityTimeLimit).all();
            if (successActivities && successActivities.length > 0) {
                reportContent += `### Top Successful Activities:\n| User ID        | Action   | Success Count | Total Upload Size (Bytes) |\n|----------------|----------|---------------|---------------------------|\n`;
                successActivities.forEach(act => {
                    reportContent += `| ${act.user_id.padEnd(14)} | ${act.action_type.padEnd(8)} | ${String(act.success_count).padEnd(13)} | ${act.action_type === 'upload' ? String(act.total_upload_size || 0).padEnd(25) : 'N/A'.padEnd(25)} |\n`;
                });
            } else { reportContent += `- No successful activities recorded in the last 24 hours.\n`; }
            reportContent += `\n`;

            // 失败活动
            const failureActivityStmt = env.DB.prepare(
                "SELECT user_id, action_type, COUNT(*) as failure_count, GROUP_CONCAT(DISTINCT SUBSTR(error_message, 1, 30)) as common_errors " +
                "FROM FileActivityLogs WHERE logged_at >= ? AND status = 'failure' GROUP BY user_id, action_type ORDER BY failure_count DESC LIMIT 10"
            );
            const { results: failureActivities } = await failureActivityStmt.bind(activityTimeLimit).all();
            if (failureActivities && failureActivities.length > 0) {
                reportContent += `### Top Failed Activities:\n| User ID        | Action   | Failure Count | Common Errors (truncated)    |\n|----------------|----------|---------------|------------------------------|\n`;
                failureActivities.forEach(act => {
                    reportContent += `| ${act.user_id.padEnd(14)} | ${act.action_type.padEnd(8)} | ${String(act.failure_count).padEnd(13)} | ${(act.common_errors || 'N/A').padEnd(28)} |\n`;
                });
            } else { reportContent += `- No failed activities recorded in the last 24 hours.\n`; }
            reportContent += `\n`;

        } catch (dbError) {
            reportContent += `- Error fetching recent activity: ${dbError.message}\n\n`;
            if (env.LOGGING_ENABLED === "true") console.error("[StatusReportTask] D1 Error fetching activity logs:", dbError);
        }
    } else {
         reportContent += `- Recent activity unavailable (D1 DB not configured).\n\n`;
    }
    
    // --- 报告文件路径配置 ---
    const reportRepoOwner = env.REPORT_REPO_OWNER || env.GITHUB_REPO_OWNER;
    const reportRepoName = env.REPORT_REPO_NAME || env.GITHUB_REPO_NAME;
    const reportRepoBranch = env.REPORT_REPO_BRANCH || env.TARGET_BRANCH || "main";
    const baseReportDir = env.STATUS_REPORT_PATH_PREFIX || "system_reports/status/";
    const latestReportRelativePath = "latest_status_report.md";
    const latestReportFullPath = `${baseReportDir.endsWith('/') ? baseReportDir : baseReportDir + '/'}${latestReportRelativePath}`;

    // --- 1. 归档上一份 "最新" 报告 ---
    const previousReportData = await githubService.getFileShaFromPath(env, reportRepoOwner, reportRepoName, latestReportFullPath, reportRepoBranch);
    if (previousReportData && previousReportData.sha) {
        const archiveDate = new Date(reportTimestampDate.getTime() - (119 * 60 * 1000)); // 近似上次报告时间 (1 小时 59 分钟前)
        const archiveYear = archiveDate.getUTCFullYear();
        const archiveMonth = (archiveDate.getUTCMonth() + 1).toString().padStart(2, '0');
        const archiveDay = archiveDate.getUTCDate().toString().padStart(2, '0');
        const archiveHour = archiveDate.getUTCHours().toString().padStart(2, '0');
        const archiveMinute = archiveDate.getUTCMinutes().toString().padStart(2, '0');
        
        const archiveDir = `${baseReportDir.endsWith('/') ? baseReportDir : baseReportDir + '/'}archive/${archiveYear}/${archiveMonth}/${archiveDay}/`;
        const archivedReportFileName = `${archiveYear}-${archiveMonth}-${archiveDay}T${archiveHour}-${archiveMinute}_status_report.md`;
        const archivedReportFullPath = `${archiveDir}${archivedReportFileName}`;

        if (env.LOGGING_ENABLED === "true") console.log(`[StatusReportTask] Archiving previous report from '${latestReportFullPath}' to '${archivedReportFullPath}'`);
        const moved = await moveGitHubFile(env, reportRepoOwner, reportRepoName, reportRepoBranch, latestReportFullPath, archivedReportFullPath, "Chore: Archive status report");
        if (!moved && env.LOGGING_ENABLED === "true") console.warn(`[StatusReportTask] Failed to archive previous status report. New report might overwrite or create alongside.`);
    } else if (env.LOGGING_ENABLED === "true") {
        console.log(`[StatusReportTask] No previous '${latestReportRelativePath}' found to archive at ${latestReportFullPath}.`);
    }

    // --- 2. 将新报告写入 "最新" 报告路径 ---
    const reportContentBase64 = arrayBufferToBase64(new TextEncoder().encode(reportContent)); // Ensure arrayBufferToBase64 is imported
    const commitMessage = `System Status Report: ${reportTimestampISO}`;
    const latestReportShaAfterArchiveAttempt = (await githubService.getFileShaFromPath(env, reportRepoOwner, reportRepoName, latestReportFullPath, reportRepoBranch))?.sha;

    if (env.LOGGING_ENABLED === "true") console.log(`[StatusReportTask] Pushing new status report to '${latestReportFullPath}'`);
    const pushResult = await githubService.createFileOrUpdateFile(env, reportRepoOwner, reportRepoName, latestReportFullPath, reportRepoBranch, reportContentBase64, commitMessage, latestReportShaAfterArchiveAttempt);

    if (pushResult.error) {
        console.error(`[StatusReportTask] Failed to push new status report: ${pushResult.message}`, pushResult.details ? JSON.stringify(pushResult.details).substring(0,500) : '');
        // 如果推送到 GitHub 失败，尝试用 logErrorToGitHub 记录这个错误（它本身也会尝试推送到 GitHub 的不同路径）
        await logErrorToGitHub(env, 'StatusReportPushError', new Error(pushResult.message), `Report Path: ${latestReportFullPath}, Details: ${JSON.stringify(pushResult.details)}`);
    } else {
        if (env.LOGGING_ENABLED === "true") console.log(`[StatusReportTask] New status report pushed. Commit: ${pushResult.commit?.sha || (pushResult.content?.sha || 'N/A')}`);
    }
}

/**
 * 执行数据维护和一致性检查，并生成报告。
 * (此函数包含检查用户索引文件、索引条目有效性等，以及归档和推送报告)
 * @param {ScheduledEvent | { cron: string, scheduledTime: number }} event
 * @param {object} env
 * @returns {Promise<void>}
 */
async function performMaintenanceChecks(event, env) {
    // 功能：执行维护检查，归档旧报告，并生成和推送新报告。
    // (此函数的完整代码已在之前的回答中提供)
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[MaintenanceTask] Starting - Triggered by: ${event.cron}`);
    }
    const reportTimestampDate = new Date(event.scheduledTime);
    const reportTimestampISO = reportTimestampDate.toISOString();
    let reportContent = `# Data Maintenance & Consistency Report - ${reportTimestampISO}\n\nCron: ${event.cron}\n\n`;
    let issuesFoundDetails = [];

    // --- 1. 检查用户索引文件是否存在 ---
    reportContent += `## Phase 1: User Index File Existence Check\n`;
    if (env.DB) {
        try {
            const usersStmt = env.DB.prepare("SELECT user_id FROM Users WHERE status = 'active'");
            const { results: activeUsers } = await usersStmt.all();
            if (activeUsers && activeUsers.length > 0) {
                reportContent += `Checking index files for ${activeUsers.length} active users...\n`;
                for (const user of activeUsers) {
                    const indexPath = `${user.user_id}/index.json`;
                    const indexFileMeta = await githubService.getFileShaFromPath(env, env.GITHUB_REPO_OWNER, env.GITHUB_REPO_NAME, indexPath, env.TARGET_BRANCH || "main");
                    if (!indexFileMeta) {
                        const issue = `User '${user.user_id}': index.json NOT FOUND at '${indexPath}'.`;
                        reportContent += `- **ISSUE**: ${issue}\n`;
                        issuesFoundDetails.push({ type: "MissingIndexFile", user: user.user_id, path: indexPath, details: issue });
                    } else {
                        const { indexData } = await getUserIndexForScheduledTask(env, user.user_id); // 确保此函数可用
                        if (indexData && indexData.files) {
                            for (const originalPath in indexData.files) {
                                const fileHash = indexData.files[originalPath];
                                const hashedFilePath = `${user.user_id}/${fileHash}`;
                                const physicalFileMeta = await githubService.getFileShaFromPath(env, env.GITHUB_REPO_OWNER, env.GITHUB_REPO_NAME, hashedFilePath, env.TARGET_BRANCH || "main");
                                if (!physicalFileMeta) {
                                    const issue = `User '${user.user_id}': Index entry '${originalPath}' (hash: ${fileHash}) points to non-existent physical file '${hashedFilePath}'.`;
                                    reportContent += `- **ISSUE**: ${issue}\n`;
                                    issuesFoundDetails.push({ type: "BrokenIndexLink", user: user.user_id, originalPath, fileHash, physicalPath: hashedFilePath, details: issue });
                                }
                            }
                        }
                    }
                }
                if (issuesFoundDetails.length === 0) {
                    reportContent += `- All checked active users have an index.json file and basic index links seem valid.\n`;
                } else {
                    reportContent += `\n**Total primary issues found: ${issuesFoundDetails.length} (see details below)**\n`;
                }
            } else { reportContent += `- No active users to check.\n`; }
        } catch (dbError) {
            reportContent += `- Error during maintenance checks (DB query): ${dbError.message}\n\n`;
            if (env.LOGGING_ENABLED === "true") console.error("[MaintenanceTask] D1 Error during user query:", dbError);
        }
    } else { reportContent += `- Maintenance checks requiring D1 (Users table) skipped.\n`; }
    reportContent += `\n`;

    // ... (可选的孤立文件检查描述) ...

    if (issuesFoundDetails.length > 0) {
        reportContent += `## Detailed Issues Found:\n`;
        issuesFoundDetails.forEach(issue => { /* ... 格式化 issue ... */ 
             reportContent += `### Type: ${issue.type}\n- User: ${issue.user}\n`;
             if(issue.path) reportContent += `- Path: \`${issue.path}\`\n`;
             if(issue.originalPath) reportContent += `- Original Path: \`${issue.originalPath}\`\n`;
             if(issue.fileHash) reportContent += `- Hash: \`${issue.fileHash}\`\n`;
             if(issue.physicalPath) reportContent += `- Physical Path: \`${issue.physicalPath}\`\n`;
             reportContent += `- Details: ${issue.details}\n\n`;
        });
    }
    // ... (报告归档和推送逻辑，使用 MAINTENANCE_REPORT_PATH_PREFIX) ...
    const reportRepoOwner = env.REPORT_REPO_OWNER || env.GITHUB_REPO_OWNER;
    const reportRepoName = env.REPORT_REPO_NAME || env.GITHUB_REPO_NAME;
    const reportRepoBranch = env.REPORT_REPO_BRANCH || env.TARGET_BRANCH || "main";
    const baseReportDir = env.MAINTENANCE_REPORT_PATH_PREFIX || "system_reports/maintenance/";
    const latestReportRelativePath = "latest_maintenance_report.md";
    const latestReportFullPath = `${baseReportDir.endsWith('/') ? baseReportDir : baseReportDir + '/'}${latestReportRelativePath}`;

    // 归档
    const previousReportData = await githubService.getFileShaFromPath(env, reportRepoOwner, reportRepoName, latestReportFullPath, reportRepoBranch);
    if (previousReportData && previousReportData.sha) {
        const archiveDate = new Date(reportTimestampDate.getTime() - (23 * 60 * 60 * 1000 + 59 * 60 * 1000) ); // 23h 59m ago
        const archiveYear = archiveDate.getUTCFullYear();
        const archiveMonth = (archiveDate.getUTCMonth() + 1).toString().padStart(2, '0');
        const archiveDay = archiveDate.getUTCDate().toString().padStart(2, '0');
        const archiveDir = `${baseReportDir.endsWith('/') ? baseReportDir : baseReportDir + '/'}archive/${archiveYear}/${archiveMonth}/${archiveDay}/`;
        const archivedReportFileName = `${archiveDate.toISOString().replace(/:/g, '-').replace(/\..+/, '')}_maintenance_report.md`;
        const archivedReportFullPath = `${archiveDir}${archivedReportFileName}`;
        await moveGitHubFile(env, reportRepoOwner, reportRepoName, reportRepoBranch, latestReportFullPath, archivedReportFullPath, "Chore: Archive maintenance report");
    }

    // 推送新报告
    const reportContentBase64 = arrayBufferToBase64(new TextEncoder().encode(reportContent));
    const commitMessage = `System Maintenance Report: ${reportTimestampISO}`;
    const latestReportShaAfterArchiveAttempt = (await githubService.getFileShaFromPath(env, reportRepoOwner, reportRepoName, latestReportFullPath, reportRepoBranch))?.sha;
    const pushResult = await githubService.createFileOrUpdateFile(env, reportRepoOwner, reportRepoName, latestReportFullPath, reportRepoBranch, reportContentBase64, commitMessage, latestReportShaAfterArchiveAttempt);

    if (pushResult.error) {
        console.error(`[MaintenanceTask] Failed to push new maintenance report: ${pushResult.message}`, pushResult.details);
        await logErrorToGitHub(env, 'MaintenanceReportPushError', new Error(pushResult.message), `Report Path: ${latestReportFullPath}, Details: ${JSON.stringify(pushResult.details)}`);
    } else {
        if (env.LOGGING_ENABLED === "true") console.log(`[MaintenanceTask] New maintenance report pushed. Commit: ${pushResult.commit?.sha || (pushResult.content?.sha || 'N/A')}`);
    }
}








