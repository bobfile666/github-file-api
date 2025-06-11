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
    routeAdminRequests, // 主管理员路由器从 admin.js 导入
    handleAdminCreateUser // 也导入这个，以便 dashboard action 可以调用
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
        const adminSubPath = pathname.substring(`${apiVersionPrefix}/admin`.length); // e.g., "", "/dashboard", "/users", "/actions/..."
        
        // HTML Admin Dashboard (GET)
        if ((adminSubPath === '' || adminSubPath === '/dashboard') && request.method === 'GET') {
            // handleAdminDashboard 现在在 admin.js 中，并且期望 apiVersionPrefix
            // 我们从 index.js 调用它，所以需要将 apiVersionPrefix 传递过去
            // 或者 admin.js 中的 handleAdminDashboard 自己从 env.API_VERSION 构建
            // 为了一致性，我们假设 routeAdminRequests (在 admin.js 中) 会处理这个
            return await routeAdminRequests(adminSubPath, request, env, ctx, apiVersionPrefix);
        }

        // Actions triggered by Admin Dashboard (POST)
        if (adminSubPath === '/actions/trigger-status-report' && request.method === 'POST') {
            const formData = await request.formData();
            const password = formData.get("password");
            // 使用 admin.js 中的密码验证辅助函数 (如果已导出并导入)
            // 或者在这里直接比较：if (!env.ADMIN_PAGE_PASSWORD || password !== env.ADMIN_PAGE_PASSWORD)
            if (!(env.ADMIN_PAGE_PASSWORD && password === env.ADMIN_PAGE_PASSWORD)) { // 简化版验证
                 return errorResponse(env, "Invalid password for action.", 403);
            }
            if (env.LOGGING_ENABLED === "true") console.log("[AdminActionTrigger] Manually triggering status report via HTTP POST.");
            ctx.waitUntil(generateAndPushStatusReport({ cron: "manual_admin_http", scheduledTime: Date.now() }, env));
            const redirectUrl = new URL(`${apiVersionPrefix}/admin`, url.origin); // redirect back to dashboard
            redirectUrl.searchParams.set("message", "Status report generation triggered.");
            redirectUrl.searchParams.set("password", password);
            return Response.redirect(redirectUrl.toString(), 303);
        }
        if (adminSubPath === '/actions/trigger-maintenance-check' && request.method === 'POST') {
            const formData = await request.formData();
            const password = formData.get("password");
            if (!(env.ADMIN_PAGE_PASSWORD && password === env.ADMIN_PAGE_PASSWORD)) {
                 return errorResponse(env, "Invalid password for action.", 403);
            }
            if (env.LOGGING_ENABLED === "true") console.log("[AdminActionTrigger] Manually triggering maintenance check via HTTP POST.");
            ctx.waitUntil(performMaintenanceChecks({ cron: "manual_admin_http", scheduledTime: Date.now() }, env));
            const redirectUrl = new URL(`${apiVersionPrefix}/admin`, url.origin);
            redirectUrl.searchParams.set("message", "Maintenance check triggered.");
            redirectUrl.searchParams.set("password", password);
            return Response.redirect(redirectUrl.toString(), 303);
        }
        // 新增：处理来自 Admin Dashboard 的创建用户 POST 请求
        if (adminSubPath === '/actions/create-user-from-dashboard' && request.method === 'POST') {
            const formData = await request.formData();
            const password = formData.get("password_page"); // 从表单获取页面密码
            const newUsername = formData.get("new_username_dashboard");

            if (!(env.ADMIN_PAGE_PASSWORD && password === env.ADMIN_PAGE_PASSWORD)) {
                 return errorResponse(env, "Invalid page password for user creation.", 403);
            }
            if (!newUsername) {
                return errorResponse(env, "Username for creation is missing from dashboard form.", 400);
            }
            // 模拟一个内部 API 请求给 handleAdminCreateUser (它期望 X-Admin-API-Key)
            // 或者，更好的做法是重构 handleAdminCreateUser 的核心逻辑到一个不需要 request 对象的函数中
            // 然后这个路由和 /admin/users POST 路由都调用那个核心逻辑。
            // 为了当前能工作，我们暂时让这个路由直接调用 handleAdminCreateUser，并伪造一个带有 X-Admin-API-Key 的请求。
            // 这不是最佳实践，但能让页面表单工作。
            const pseudoRequestForCreateUser = new Request(url.toString(), { // 使用当前 URL，但主要是为了 headers 和 body
                method: "POST",
                headers: { 
                    'Content-Type': 'application/json',
                    'X-Admin-API-Key': env.ADMIN_API_KEY // 使用真实的 Admin API Key
                },
                body: JSON.stringify({ username: newUsername })
            });
            const createUserResponse = await handleAdminCreateUser(pseudoRequestForCreateUser, env, ctx); // 调用 admin.js 中的函数
            const resultJson = await createUserResponse.json().catch(() => ({}));
            const actionResult = `Dashboard User Creation for '${newUsername}': ${createUserResponse.status === 201 ? 'Success' : ('Failed - ' + (resultJson.error?.message || createUserResponse.statusText))}`;
            
            const redirectUrl = new URL(`${apiVersionPrefix}/admin`, url.origin);
            redirectUrl.searchParams.set("message", actionResult);
            redirectUrl.searchParams.set("password", password); // 保留页面密码
            return Response.redirect(redirectUrl.toString(), 303);
        }
        
        // 其他 /admin/* 请求 (主要是 /admin/users/* JSON API)
        // 将这些请求传递给 admin.js 中的 routeAdminRequests
        return await routeAdminRequests(adminSubPath, request, env, ctx, apiVersionPrefix);
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


// --- 辅助函数：用于 scheduled 任务的 getUserIndex (不依赖 HTTP 请求) ---
// 注意：这个函数是 getUserIndex 的一个变体，或者 getUserIndex 本身就可以被这样调用。
// 我们需要确保 githubService 和 base64ToArrayBuffer 在此作用域可用。
async function getUserIndexForScheduledTask(env, username) {
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const branch = env.TARGET_BRANCH || "main";
    const indexPath = `${username}/index.json`;

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[getUserIndexForScheduledTask] User: ${username} - Fetching index: ${indexPath}`);
    }
    const indexFile = await githubService.getFileContentAndSha(env, owner, repo, indexPath, branch);

    if (indexFile && indexFile.content_base64) {
        try {
            const decodedContent = new TextDecoder().decode(base64ToArrayBuffer(indexFile.content_base64)); // from crypto.js
            const indexData = JSON.parse(decodedContent);
            if (env.LOGGING_ENABLED === "true") {
                console.log(`[getUserIndexForScheduledTask] User: ${username} - Index found. SHA: ${indexFile.sha}. Files count: ${Object.keys(indexData.files || {}).length}`);
            }
            return { indexData: indexData.files ? indexData : { files: {} }, sha: indexFile.sha, error: null }; // 返回 error: null 表示成功
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") {
                console.error(`[getUserIndexForScheduledTask] User: ${username} - Error parsing index.json:`, e.message);
            }
            // 返回错误信息，而不是抛出，以便 performMaintenanceChecks 可以记录并继续
            return { indexData: { files: {} }, sha: indexFile.sha, error: `Failed to parse index.json: ${e.message}` };
        }
    }
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[getUserIndexForScheduledTask] User: ${username} - Index file not found or content empty.`);
    }
    // 如果索引文件不存在，也返回 error: null，由后续逻辑判断是否是 MissingIndexFile
    return { indexData: { files: {} }, sha: null, error: null }; 
}


// --- 新增：特定任务的逻辑函数 ---

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
    // 功能：执行详细的维护检查，包括检测和处理损坏的索引链接及孤立的物理文件，并生成报告。
    const taskStartTime = Date.now();
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[MaintenanceTask] Starting - Triggered by: ${event.cron} at ${new Date(event.scheduledTime).toISOString()}`);
    }
    const reportTimestampDate = new Date(event.scheduledTime);
    const reportTimestampISO = reportTimestampDate.toISOString();
    let reportContent = `# Data Maintenance & Consistency Report - ${reportTimestampISO}\n\nCron: ${event.cron}\n\n`;
    let issuesFoundDetails = [];
    let usersCheckedCount = 0;
    let usersWithIssuesCount = 0;
    let filesMovedCount = 0;

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";
    const orphanedFilesBaseDir = "_orphaned_files/"; // 用户目录下的孤立文件存放目录

    reportContent += `## Phase 1 & 2: User Index Link Integrity and Orphaned File Checks\n`;
    if (!env.DB) {
        reportContent += `- Maintenance checks skipped (D1 DB not configured).\n`;
        // ... (推送此简化报告的逻辑，已在之前给出) ...
        return;
    }

    try {
        const usersStmt = env.DB.prepare("SELECT user_id FROM Users WHERE status = 'active'");
        const { results: activeUsers } = await usersStmt.all();
        
        if (!activeUsers || activeUsers.length === 0) {
            reportContent += `- No active users found in database to check.\n`;
        } else {
            reportContent += `Attempting to check ${activeUsers.length} active users...\n\n`;
            for (const user of activeUsers) {
                usersCheckedCount++;
                let userHasIssuesThisRun = false;
                if (env.LOGGING_ENABLED === "true") console.log(`[MaintenanceTask] Checking user: ${user.user_id}`);
                
                const userDirPath = `${user.user_id}/`;
                const userOrphanedDirPath = `${userDirPath}${orphanedFilesBaseDir}`;

                try {
                    // --- 2.1 获取用户索引 ---
                    const indexPath = `${userDirPath}index.json`;
                    const indexFileCheckResult = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);
                    let userIndexData = { files: {} }; // 默认为空索引

                    if (!indexFileCheckResult.exists) {
                        if (indexFileCheckResult.error) { // 获取索引文件元数据时出错 (非 404)
                            const issue = `User '${user.user_id}': ERROR checking index.json at '${indexPath}' - ${indexFileCheckResult.error} (Status: ${indexFileCheckResult.status}).`;
                            issuesFoundDetails.push({ type: "IndexAccessError", user: user.user_id, path: indexPath, details: issue });
                            userHasIssuesThisRun = true;
                        } else { // 明确是 404
                            const issue = `User '${user.user_id}': index.json NOT FOUND at '${indexPath}'.`;
                            issuesFoundDetails.push({ type: "MissingIndexFile", user: user.user_id, path: indexPath, details: issue });
                            userHasIssuesThisRun = true;
                        }
                        // 如果索引文件不存在或无法访问，我们仍然可以继续检查该用户目录下的孤立文件
                    } else { // 索引文件存在，尝试加载
                        const indexResult = await getUserIndexForScheduledTask(env, user.user_id); // 确保此函数能获取到 sha
                        if (indexResult.error) {
                            const issue = `User '${user.user_id}': Error processing/parsing index.json at '${indexPath}' - ${indexResult.error}.`;
                            issuesFoundDetails.push({ type: "CorruptedIndexFile", user: user.user_id, path: indexPath, details: issue });
                            userHasIssuesThisRun = true;
                            // 即使索引损坏，也尝试加载一个空索引用来进行孤立文件检查，或者跳过对该用户的孤立文件检查
                        } else {
                            userIndexData = indexResult.indexData; // 加载成功
                        }
                    }

                    const indexedFileHashes = new Set(Object.values(userIndexData.files || {}));

                    // --- 2.2 检查索引中的条目是否指向存在的物理文件 (Broken Index Links) ---
                    if (userIndexData.files) {
                        for (const originalPath in userIndexData.files) {
                            const fileHash = userIndexData.files[originalPath];
                            if (!fileHash || typeof fileHash !== 'string' || fileHash.length < 32) {
                                const issue = `User '${user.user_id}': Index entry '${originalPath}' has INVALID HASH '${fileHash}'.`;
                                issuesFoundDetails.push({ type: "InvalidHashInIndex", user: user.user_id, originalPath, fileHash, details: issue });
                                userHasIssuesThisRun = true;
                                continue;
                            }
                            const hashedFilePath = `${userDirPath}${fileHash}`;
                            const physicalFileCheck = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePath, targetBranch);
                            if (!physicalFileCheck.exists) {
                                if (physicalFileCheck.error) { // 检查物理文件时出错 (非404)
                                     const issue = `User '${user.user_id}': Index entry '${originalPath}' (hash: ${fileHash}) - ERROR checking physical file '${hashedFilePath}': ${physicalFileCheck.error} (Status: ${physicalFileCheck.status}).`;
                                     issuesFoundDetails.push({ type: "PhysicalFileAccessError", user: user.user_id, originalPath, fileHash, physicalPath: hashedFilePath, details: issue });
                                } else { // 明确是404，物理文件丢失
                                    const issue = `User '${user.user_id}': Index entry '${originalPath}' (hash: ${fileHash}) points to MISSING physical file '${hashedFilePath}'.`;
                                    issuesFoundDetails.push({ type: "BrokenIndexLink", user: user.user_id, originalPath, fileHash, physicalPath: hashedFilePath, details: issue });
                                }
                                userHasIssuesThisRun = true;
                            }
                        }
                    }

                    // --- 2.3 检查孤立的物理文件 ---
                    if (env.LOGGING_ENABLED === "true") console.log(`[MaintenanceTask] User ${user.user_id}: Checking for orphaned files in '${userDirPath}'`);
                    const dirContentsResult = await githubService.listDirectoryContents(env, owner, repo, userDirPath, targetBranch);

                    if (dirContentsResult.error) {
                        const issue = `User '${user.user_id}': Could not list contents of directory '${userDirPath}' to check for orphans. Error: ${dirContentsResult.error} (Status: ${dirContentsResult.status})`;
                        issuesFoundDetails.push({ type: "DirectoryListError", user: user.user_id, path: userDirPath, details: issue });
                        userHasIssuesThisRun = true;
                    } else if (dirContentsResult.files && dirContentsResult.files.length > 0) {
                        for (const item of dirContentsResult.files) {
                            if (item.type === 'file' && item.name !== 'index.json') {
                                // item.name 就是哈希文件名
                                if (!indexedFileHashes.has(item.name)) {
                                    const orphanedFilePath = item.path; // GitHub API 返回的 path 是完整的
                                    const newOrphanedPath = `${userOrphanedDirPath}${item.name}`;
                                    
                                    const issue = `User '${user.user_id}': ORPHANED physical file found: '${orphanedFilePath}'. Not in index.json.`;
                                    issuesFoundDetails.push({ type: "OrphanedFile", user: user.user_id, physicalPath: orphanedFilePath, details: `${issue} Attempting to move to '${newOrphanedPath}'.` });
                                    userHasIssuesThisRun = true;
                                    if (env.LOGGING_ENABLED === "true") console.warn(`[MaintenanceTask] ${issue}`);

                                    // 移动孤立文件
                                    const moved = await moveGitHubFile(
                                        env, owner, repo, targetBranch,
                                        orphanedFilePath,
                                        newOrphanedPath,
                                        `Maintenance: Quarantine orphaned file for user ${user.user_id}`
                                    );
                                    if (moved) {
                                        filesMovedCount++;
                                        issuesFoundDetails.push({ type: "OrphanedFileMoved", user: user.user_id, oldPath: orphanedFilePath, newPath: newOrphanedPath, details: "Successfully moved to orphaned files directory."});
                                        if (env.LOGGING_ENABLED === "true") console.log(`[MaintenanceTask] User ${user.user_id}: Orphaned file '${orphanedFilePath}' moved to '${newOrphanedPath}'.`);
                                    } else {
                                        issuesFoundDetails.push({ type: "OrphanedFileMoveFailed", user: user.user_id, physicalPath: orphanedFilePath, details: `Failed to move orphaned file '${orphanedFilePath}' to quarantine.` });
                                        if (env.LOGGING_ENABLED === "true") console.error(`[MaintenanceTask] User ${user.user_id}: FAILED to move orphaned file '${orphanedFilePath}'.`);
                                    }
                                }
                            }
                        }
                    }
                    if (userHasIssuesThisRun) {
                        usersWithIssuesCount++;
                    }

                } catch (userCheckError) { // 捕获检查单个用户时发生的更顶层的意外错误
                    const issue = `User '${user.user_id}': UNEXPECTED CRITICAL ERROR during check - ${userCheckError.message}. Further checks for this user aborted.`;
                    if (env.LOGGING_ENABLED === "true") console.error(`[MaintenanceTask] ${issue}`, userCheckError.stack);
                    issuesFoundDetails.push({ type: "UserCheckFailedCritical", user: user.user_id, details: issue, stack: userCheckError.stack });
                    if (!userHasIssuesThisRun) usersWithIssuesCount++; // 确保计数
                }
            } // end for (const user of activeUsers)

            reportContent += `Checked ${usersCheckedCount} users. Found issues for ${usersWithIssuesCount} users. Moved ${filesMovedCount} orphaned files.\n`;
            if (issuesFoundDetails.length === 0 && usersCheckedCount > 0) {
                reportContent += `- All checked active users appear consistent based on implemented checks.\n`;
            } else if (usersCheckedCount === 0 && activeUsers.length > 0) {
                 reportContent += `- No users were effectively processed for checks (possibly due to errors).\n`;
            }
        }
    } catch (dbError) {
        reportContent += `- Error fetching users from D1: ${dbError.message}. Maintenance checks aborted.\n`;
        if (env.LOGGING_ENABLED === "true") console.error("[MaintenanceTask] D1 Error during user query:", dbError);
        await logErrorToGitHub(env, 'MaintenanceDbError', dbError, `Cron: ${event.cron} - Failed to query users`);
    }
    reportContent += `\n`;

    if (issuesFoundDetails.length > 0) {
        reportContent += `## Detailed Issues and Actions (${issuesFoundDetails.length}):\n`;
        issuesFoundDetails.forEach(issue => { 
            reportContent += `### Type: ${issue.type}\n`;
            reportContent += `- User: ${issue.user}\n`;
            if(issue.path) reportContent += `- Index Path: \`${issue.path}\`\n`;
            if(issue.originalPath) reportContent += `- Original Path in Index: \`${issue.originalPath}\`\n`;
            if(issue.fileHash) reportContent += `- Referenced Hash: \`${issue.fileHash}\`\n`;
            if(issue.physicalPath) reportContent += `- Physical Path: \`${issue.physicalPath}\`\n`;
            if(issue.oldPath) reportContent += `- Old Path: \`${issue.oldPath}\`\n`;
            if(issue.newPath) reportContent += `- New Path (Moved To): \`${issue.newPath}\`\n`;
            reportContent += `- Details: ${issue.details}\n\n`;
        });
    } else if (usersCheckedCount > 0) {
        reportContent += `**No consistency issues found for ${usersCheckedCount} checked users.**\n`;
    }

    reportContent += `**Note**: This report provides basic consistency checks. Orphaned files are moved to \`_orphaned_files/\` subdirectory within each user's folder. Manual review may be needed.\n`;
    
    // --- 报告归档和推送逻辑 (和之前一样，使用 MAINTENANCE_REPORT_PATH_PREFIX) ---
    const reportRepoOwner = env.REPORT_REPO_OWNER || env.GITHUB_REPO_OWNER;
    const reportRepoName = env.REPORT_REPO_NAME || env.GITHUB_REPO_NAME;
    const reportRepoBranch = env.REPORT_REPO_BRANCH || env.TARGET_BRANCH || "main";
    const baseReportDir = env.MAINTENANCE_REPORT_PATH_PREFIX || "system_reports/maintenance/";
    const latestReportRelativePath = "latest_maintenance_report.md";
    const latestReportFullPath = `${baseReportDir.endsWith('/') ? baseReportDir : baseReportDir + '/'}${latestReportRelativePath}`;

    // 归档
    const previousReportData = await githubService.getFileShaFromPath(env, reportRepoOwner, reportRepoName, latestReportFullPath, reportRepoBranch);
    if (previousReportData.exists && previousReportData.sha) { //  <-- 修正：检查 exists 属性
        const archiveDate = new Date(reportTimestampDate.getTime() - (23 * 60 * 60 * 1000 + 59 * 60 * 1000) ); // 约 24 小时前
        const archiveYear = archiveDate.getUTCFullYear();
        const archiveMonth = (archiveDate.getUTCMonth() + 1).toString().padStart(2, '0');
        const archiveDay = archiveDate.getUTCDate().toString().padStart(2, '0');
        const archiveDir = `${baseReportDir.endsWith('/') ? baseReportDir : baseReportDir + '/'}archive/${archiveYear}/${archiveMonth}/${archiveDay}/`;
        const archivedReportFileName = `${archiveDate.toISOString().replace(/:/g, '-').replace(/\..+/, '')}_maintenance_report.md`;
        const archivedReportFullPath = `${archiveDir}${archivedReportFileName}`;
        await moveGitHubFile(env, reportRepoOwner, reportRepoName, reportRepoBranch, latestReportFullPath, archivedReportFullPath, "Chore: Archive maintenance report");
    }

    // 推送新报告
    const reportContentBase64 = arrayBufferToBase64(new TextEncoder().encode(reportContent)); // 确保 arrayBufferToBase64 导入
    const commitMessage = `System Maintenance Report: ${reportTimestampISO}`;
    const latestReportShaAfterArchiveAttempt = (await githubService.getFileShaFromPath(env, reportRepoOwner, reportRepoName, latestReportFullPath, reportRepoBranch))?.sha; // 可能为 null
    const pushResult = await githubService.createFileOrUpdateFile(env, reportRepoOwner, reportRepoName, latestReportFullPath, reportRepoBranch, reportContentBase64, commitMessage, latestReportShaAfterArchiveAttempt);

    if (pushResult.error) {
        console.error(`[MaintenanceTask] Failed to push new maintenance report: ${pushResult.message}`, pushResult.details);
        await logErrorToGitHub(env, 'MaintenanceReportPushError', new Error(pushResult.message), `Report Path: ${latestReportFullPath}, Details: ${JSON.stringify(pushResult.details)}`);
    } else {
        if (env.LOGGING_ENABLED === "true") console.log(`[MaintenanceTask] New maintenance report pushed. Commit: ${pushResult.commit?.sha || (pushResult.content?.sha || 'N/A')}`);
    }

    if (env.LOGGING_ENABLED === "true") {
        const duration = Date.now() - taskStartTime;
        console.log(`[MaintenanceTask] Finished. Duration: ${duration}ms. Issues found: ${issuesFoundDetails.length}. Files moved: ${filesMovedCount}.`);
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
    // 功能：将捕获到的错误信息格式化并尝试推送到 GitHub 仓库的特定错误日志文件。
    if (!env.GITHUB_PAT) { // 如果没有 PAT，无法推送到 GitHub
        console.error("[logErrorToGitHub] GITHUB_PAT is not configured. Skipping GitHub error log.");
        console.error(`[logErrorToGitHub] Original Error (${errorType}) Context: ${additionalContext} Msg: ${errorObject.message}`);
        return;
    }
    // (其余逻辑和之前一样，格式化错误内容并推送到 GitHub)
    try {
        const timestamp = new Date().toISOString();
        const errorLogContent = `# ${errorType} - ${timestamp}\n\n## Error Message\n\`\`\`\n${errorObject.message || 'No message'}\n\`\`\`\n\n## Stack Trace\n\`\`\`\n${errorObject.stack || 'No stack trace'}\n\`\`\`\n\n## Additional Context\n- Trigger/Request: ${additionalContext}\n- Ray ID: ${errorObject.rayId || request?.headers?.get('cf-ray') || 'N/A'}\n\n## Environment (Non-Sensitive)\n- GITHUB_REPO_OWNER: ${env.GITHUB_REPO_OWNER}\n- TARGET_BRANCH: ${env.TARGET_BRANCH}\n- API_VERSION: ${env.API_VERSION || 'v1'}\n---\n`;
        const errorLogOwner = env.REPORT_REPO_OWNER || env.GITHUB_REPO_OWNER;
        const errorLogRepo = env.REPORT_REPO_NAME || env.GITHUB_REPO_NAME;
        const errorLogBranch = env.REPORT_REPO_BRANCH || env.TARGET_BRANCH || "main";
        const errorLogPathPrefix = "system_errors/";
        const errorFileName = `${timestamp.replace(/:/g, '-').replace(/\..+/, '')}_${errorType.toLowerCase().replace(/[^a-z0-9_]/g, '_').substring(0,50)}.md`;
        const errorLogFullPath = `${errorLogPathPrefix}${errorFileName}`;
        const contentBase64 = arrayBufferToBase64(new TextEncoder().encode(errorLogContent)); // 确保 arrayBufferToBase64 已导入
        const commitMessage = `Error Log: ${errorType} at ${timestamp.substring(0,19)}`;

        console.error(`[logErrorToGitHub] Attempting to log to GitHub: ${errorLogFullPath}. Error: ${errorObject.message}`);
        // 使用 githubService 模块
        const pushResult = await githubService.createFileOrUpdateFile(env, errorLogOwner, errorLogRepo, errorLogFullPath, errorLogBranch, contentBase64, commitMessage, null);
        if (pushResult.error) {
            console.error(`[logErrorToGitHub] FAILED to push error log to GitHub: ${pushResult.message}`, pushResult.details);
        } else {
            console.log(`[logErrorToGitHub] Error log pushed successfully to GitHub: ${errorLogFullPath}`);
        }
    } catch (loggingError) {
        console.error("[logErrorToGitHub] FAILED to log error to GitHub (secondary error):", loggingError.message, loggingError.stack);
        console.error("[logErrorToGitHub] Original error was:", errorObject.message, errorObject.stack);
    }
}


export default {
    async fetch(request, env, ctx) {
        // 功能：Worker 的主 fetch 处理函数。
        const startTime = Date.now();
        let response; 
        const rayId = request.headers.get('cf-ray') || `fetch-${Date.now()}-${Math.random().toString(36).substring(2,7)}`;

        if (env && env.LOGGING_ENABLED === "true") {
            console.log(`[IndexFetch] START: ${request.method} ${request.url} Ray: ${rayId}`);
        }
        
        if (request.method === 'OPTIONS') {
            return handleOptions(request); // 确保 handleOptions 已定义
        }

        try {
            response = await routeRequest(request, env, ctx); // routeRequest 是主要的请求处理器
        } catch (err) { 
            // 这个 catch 块处理从 routeRequest 或其调用的 handlers 中未被捕获而抛出的错误
            err.rayId = rayId; // 附加 Ray ID 以便追踪

            const isServerErrorLogTarget = err.isServerError || !err.isClientError; // 如果明确标记为服务器错误，或者没有明确标记为客户端错误，则认为是服务器问题需要记录
                                                                                    // 或者更简单：只要 status >= 500 或者 isServerError 为 true
            const effectiveStatus = (typeof err.status === 'number' && err.status >= 400 && err.status <= 599) ? err.status : 500;
            const shouldLogErrorToGithub = err.isServerError === true || effectiveStatus >= 500;


            if (env.LOGGING_ENABLED === "true") {
                console.error(`[IndexFetch CRITICAL] Unhandled error in routing/handler for ${request.method} ${request.url} (Ray ID: ${rayId}):`, 
                              `Message: ${err.message}`, 
                              `Status: ${effectiveStatus}`, 
                              `IsServerErrorFlag: ${err.isServerError}`,
                              `IsClientErrorFlag: ${err.isClientError}`,
                              err.stack, 
                              err.details || err);
            }
            
            if (shouldLogErrorToGithub) {
                // 确保传递的是 Error 实例
                const errorToLog = err instanceof Error ? err : new Error(String(err.message || err));
                if (!errorToLog.stack && err.stack) errorToLog.stack = err.stack; // 补上 stack
                if (!errorToLog.status && err.status) errorToLog.status = err.status; // 补上 status
                if (err.details) errorToLog.details = err.details;

                ctx.waitUntil(logErrorToGitHub(env, 'GlobalFetchUnhandledError', errorToLog, `${request.method} ${request.url}`));
            }
            
            // 为客户端构造响应
            let clientResponseMessage;
            let clientResponseStatus = effectiveStatus; // 默认使用错误对象上的 status，或 500
            let clientErrorCode = "UNEXPECTED_ERROR";

            if (err.isClientError || (clientResponseStatus >= 400 && clientResponseStatus < 500 && !err.isServerError)) {
                // 明确是客户端错误，或根据状态码判断（且未被标记为服务器错误）
                clientResponseMessage = err.message || "A client-side error occurred.";
                clientErrorCode = err.code || "CLIENT_REQUEST_ERROR";
            } else {
                // 认为是服务器端错误（或未明确分类的错误，默认为服务器端）
                clientResponseMessage = `An internal server error occurred. Please try again later or contact support if the issue persists. Ray ID: ${rayId}`;
                clientResponseStatus = effectiveStatus >= 500 ? effectiveStatus : 500; // 确保服务器错误至少是 500
                clientErrorCode = err.code || "INTERNAL_SERVER_ERROR";
            }
            
            // 如果原始错误就是一个 Response 对象 (例如从 errorResponse 返回的)，理论上不应该到这里，因为它不是被 throw 的 Error 实例
            // 但为了安全，检查一下
            if (err instanceof Response) {
                 response = err;
            } else {
                response = errorResponse(env, clientResponseMessage, clientResponseStatus, clientErrorCode, { originalError: err.message, detailsForLog: err.details });
            }
        } finally {
            if (env && env.LOGGING_ENABLED === "true") {
                const duration = Date.now() - startTime;
                const statusString = response ? response.status : 'N/A (no response generated)';
                console.log(`[IndexFetch] END: ${request.method} ${request.url} Status: ${statusString} Duration: ${duration}ms Ray: ${rayId}`);
            }
        }
        return response; // response 应该总是在 try 或 catch 中被赋值
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
        const scheduledTaskStartTime = Date.now(); // <--- 重命名以避免与 fetch 中的 startTime 混淆，并确保在此作用域
        
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[ScheduledHandler] START - Cron: '${event.cron}' at ${new Date(event.scheduledTime).toISOString()} (Task Start Time: ${scheduledTaskStartTime})`);
        }
        
        let taskToRun; // 这将是一个 async function

        switch (event.cron) {
            case "0 */2 * * *": 
                taskToRun = async () => generateAndPushStatusReport(event, env); // 包装成一个 async thunk
                break;
            case "0 3 * * *":   
                taskToRun = async () => performMaintenanceChecks(event, env); // 包装成一个 async thunk
                break;
            default:
                if (env.LOGGING_ENABLED === "true") {
                    const duration = Date.now() - scheduledTaskStartTime;
                    console.warn(`[ScheduledHandler] END - No specific task defined for cron schedule: '${event.cron}'. Duration: ${duration}ms`);
                }
                return; 
        }

        if (taskToRun) {
            ctx.waitUntil(
                (async () => { // 立即执行的异步函数 (IIFE) 来包裹 taskToRun 的调用和后续处理
                    try {
                        await taskToRun(); // 执行任务
                        if (env.LOGGING_ENABLED === "true") {
                            const duration = Date.now() - scheduledTaskStartTime;
                            console.log(`[ScheduledHandler] END - Successfully completed task for cron '${event.cron}'. Duration: ${duration}ms`);
                        }
                    } catch (error) {
                        if (env.LOGGING_ENABLED === "true") {
                            const duration = Date.now() - scheduledTaskStartTime;
                            console.error(`[ScheduledHandler CRITICAL] Error during scheduled task for cron '${event.cron}'. Duration: ${duration}ms:`, error.message, error.stack);
                        }
                        const errorToLog = error instanceof Error ? error : new Error(String(error.message || error));
                        if (!errorToLog.stack && error.stack) errorToLog.stack = error.stack;
                        errorToLog.rayId = `scheduled-${event.cron}-${event.scheduledTime}`; // 使用 event.scheduledTime
                        
                        // 确保 logErrorToGitHub 本身不会因错误而中断 waitUntil
                        try {
                            await logErrorToGitHub(env, 'ScheduledTaskExecutionError', errorToLog, `Cron: ${event.cron}`);
                        } catch (githubLogError) {
                            console.error("[ScheduledHandler CRITICAL] FAILED to log scheduled task error to GitHub as well:", githubLogError.message);
                        }
                    }
                })()
            );
        } else {
             //这种情况理论上已经被 switch 的 default 分支处理了
             if (env.LOGGING_ENABLED === "true") {
                const duration = Date.now() - scheduledTaskStartTime;
                console.log(`[ScheduledHandler] END - No task promise was generated for cron '${event.cron}'. Duration: ${duration}ms`);
             }
        }
    }
};






