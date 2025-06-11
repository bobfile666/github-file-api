// src/services/github.js
// 描述：封装所有与 GitHub REST API 的交互逻辑。

const GITHUB_API_BASE = 'https://api.github.com';

/**
 * 辅助函数，用于发起 GitHub API 请求
 * @param {string} url - 完整的 API URL
 * @param {string} method - HTTP 方法
 * @param {string} pat - GitHub Personal Access Token
 * @param {object} [body=null] - 请求体 (如果是 POST/PUT/DELETE)
 * @returns {Promise<object>} - 解析后的 JSON 响应或错误对象
 */
// src/services/github.js

// async function githubApiRequest(url, method, pat, body = null, envForLogging) { /* ... */ }
// (此函数需要修改其错误处理部分)
async function githubApiRequest(url, method, pat, body = null, envForLogging) {
    // 功能：通用的 GitHub API 请求辅助函数。
    // 参数：url, method, pat, body (可选), envForLogging (可选，用于日志记录)
    // 返回：Promise<object> - 解析后的 JSON 响应或自定义的错误/成功对象
    const headers = {
        'Authorization': `token ${pat}`,
        'User-Agent': 'Cloudflare-Worker-GitHub-File-API',
        'Accept': 'application/vnd.github.v3+json',
    };
    if (body) {
        headers['Content-Type'] = 'application/json';
    }

    if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
        console.log(`[GitHubAPI] Request: ${method} ${url}`);
        if (body && method !== 'GET' && method !== 'HEAD') { // 只记录非 GET/HEAD 的 body
             try {
                const bodyString = JSON.stringify(body);
                console.log(`[GitHubAPI] Body (first 200 chars): ${bodyString.substring(0, 200)}${bodyString.length > 200 ? '...' : ''}`);
            } catch (e) {
                console.warn("[GitHubAPI] Could not stringify body for logging.");
            }
        }
    }

    try {
        const response = await fetch(url, {
            method,
            headers,
            body: body ? JSON.stringify(body) : null,
        });

        if (response.status === 204) { // No Content (e.g., successful DELETE)
            if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
                console.log(`[GitHubAPI] Response: ${method} ${url} - Status 204 No Content`);
            }
            return { success: true, status: 204, commit: {sha: null} }; // GitHub delete API sometimes returns commit in header, not body
        }
        
        // 尝试解析 JSON，即使对于错误响应，GitHub 也可能返回 JSON 错误体
        let responseData = {};
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.includes("application/json")) {
            try {
                responseData = await response.json();
            } catch (e) {
                // 如果声明是 JSON 但解析失败
                if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
                    console.warn(`[GitHubAPI] Response for ${method} ${url} (Status: ${response.status}) declared JSON but failed to parse:`, e.message);
                }
                // 如果不是成功状态码，这仍然是一个错误
                if (!response.ok) {
                    return { error: true, message: `GitHub API Error: Declared JSON but failed to parse. Status: ${response.status}`, status: response.status, details: { rawError: e.message } };
                }
                // 如果是成功状态码但 JSON 解析失败 (例如空的 201)，特殊处理
                if (response.status === 201 && (response.headers.get('content-length') === '0' || !await response.clone().text()) ) {
                     if (envForLogging && envForLogging.LOGGING_ENABLED === "true") console.log(`[GitHubAPI] Response: ${method} ${url} - Status 201 Created (No JSON body or empty)`);
                    return { success: true, status: 201, message: "Created (No JSON body)", content: null, commit: {sha: null} }; // 模拟一个成功的结构
                }
            }
        } else if (!response.ok) {
            // 如果不是 JSON 且不是 OK，尝试读取文本
            const errorText = await response.text().catch(() => "Could not read error text");
            if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
                 console.error(`[GitHubAPI] Error (Non-JSON): ${method} ${url} - Status: ${response.status}, Body: ${errorText.substring(0,100)}`);
            }
            return { error: true, message: errorText.substring(0,100) || `GitHub API Error (Status: ${response.status})`, status: response.status, details: {rawText: errorText} };
        }


        if (!response.ok) {
            // 特别处理 GET 请求的 404 Not Found，不视为严重错误打印
            if (method === 'GET' && response.status === 404) {
                if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
                    console.log(`[GitHubAPI] Info: ${method} ${url} - Status 404 Not Found (File/Resource does not exist)`);
                }
            } else { // 其他错误，用 console.error
                if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
                    const errorMessage = responseData.message || (typeof responseData === 'string' ? responseData : `GitHub API Error (Status: ${response.status})`);
                    console.error(`[GitHubAPI] Error: ${method} ${url} - Status: ${response.status}, Message: ${errorMessage}`, responseData);
                }
            }
            // 将 GitHub 的错误信息和状态码包装起来
            return { 
                error: true, 
                message: responseData.message || (typeof responseData === 'string' ? responseData : `GitHub API Error (Status: ${response.status})`), 
                status: response.status, 
                details: responseData 
            };
        }
        
        // 将状态码附加到成功响应上，便于调用者判断
        if (typeof responseData === 'object' && responseData !== null) {
            responseData.status = response.status;
        } else if (typeof responseData !== 'object') { 
            // 如果 responseData 不是对象（例如，GitHub API 在某些情况下返回简单字符串或 null）
            // 但状态是 OK，我们包装一下
            if (envForLogging && envForLogging.LOGGING_ENABLED === "true") console.log(`[GitHubAPI] Response: ${method} ${url} - Status ${response.status}. Received non-object data:`, responseData);
            return { success: true, status: response.status, data: responseData, message: "Received non-object success data." };
        }


        if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
            console.log(`[GitHubAPI] Response: ${method} ${url} - Status ${response.status} OK.`);
        }
        return responseData;

    } catch (error) { // 网络错误或其他 fetch 本身的错误
        if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
            console.error(`[GitHubAPI] Network/Fetch Error: ${method} ${url}`, error.message, error.stack);
        }
        return { error: true, message: `Network/Fetch error: ${error.message}`, status: 0, type: 'network_or_fetch_error' }; // status 0 for network errors
    }
}


/**
 * 获取文件内容和 SHA。
 * @param {object} env - Worker 环境变量
 * @param {string} owner - 仓库所有者
 * @param {string} repo - 仓库名
 * @param {string} path - 文件路径
 * @param {string} branch - 分支名
 * @returns {Promise<object|null>} - 文件数据 { name, path, sha, size, type, content_base64, encoding, ... } 或 null
 */
export async function getFileContentAndSha(env, owner, repo, path, branch) {
    const apiUrl = `${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${path}?ref=${branch}`;
    const responseData = await githubApiRequest(apiUrl, 'GET', env.GITHUB_PAT, null, env);

    if (responseData.error) {
        // 404 Not Found 是预期中的 "文件不存在"
        if (responseData.status === 404) {
            if (env.LOGGING_ENABLED === "true") console.log(`File not found at ${path} on branch ${branch}`);
            return null;
        }
        // 其他错误则记录并返回 null
        console.error(`Failed to get file content for ${path}: ${responseData.message}`);
        return null;
    }
    // GitHub API content is base64 encoded
    return {
        name: responseData.name,
        path: responseData.path,
        sha: responseData.sha,
        size: responseData.size,
        type: responseData.type, // "file" or "dir"
        content_base64: responseData.content, // Base64 encoded content
        encoding: responseData.encoding, // usually "base64" for files
        html_url: responseData.html_url,
        download_url: responseData.download_url,
        status: responseData.status
    };
}

/**
 * 获取文件（或目录）的 SHA 和其他元数据，但不包含内容。
 * 主要用于检查文件是否存在以及获取其 SHA。
 * @param {object} env - Worker 环境变量
 * @param {string} owner - 仓库所有者
 * @param {string} repo - 仓库名
 * @param {string} path - 文件路径
 * @param {string} branch - 分支名
 * @returns {Promise<object|null>} - 文件元数据 { name, path, sha, size, type, ... } 或 null
 */
export async function getFileShaFromPath(env, owner, repo, path, branch) {
    // 功能：获取文件（或目录）的 SHA 和元数据，更好地区分错误。
    const apiUrl = `${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${path}?ref=${branch}`;
    // responseData 将包含 { error: true, message: ..., status: ..., details: ... } 或成功的数据
    const responseData = await githubApiRequest(apiUrl, 'GET', env.GITHUB_PAT, null, env);

    if (responseData.error) {
        if (responseData.status === 404) {
            // 文件明确不存在
            if (env.LOGGING_ENABLED === "true") console.log(`[getFileShaFromPath] File definitely not found (404): ${path} on branch ${branch}`);
            return { exists: false, error: null, status: 404 }; 
        }
        // 其他类型的错误，例如 API 限流、权限问题等
        if (env.LOGGING_ENABLED === "true") console.error(`[getFileShaFromPath] Error getting SHA for ${path} (Status: ${responseData.status}): ${responseData.message}`);
        return { exists: false, error: responseData.message, status: responseData.status, details: responseData.details };
    }
    // 文件存在
    return {
        exists: true,
        name: responseData.name,
        path: responseData.path,
        sha: responseData.sha,
        size: responseData.size,
        type: responseData.type,
        status: responseData.status, // 成功时的状态码 (200)
        error: null
    };
}

/**
 * 创建或更新 GitHub 上的文件。
 * @param {object} env - Worker 环境变量
 * @param {string} owner - 仓库所有者
 * @param {string} repo - 仓库名
 * @param {string} path - 文件路径
 * @param {string} branch - 分支名
 * @param {string} contentBase64 - Base64 编码的文件内容
 * @param {string} commitMessage - Git 提交信息
 * @param {string} [existingSha=null] - 如果是更新现有文件，则提供其 SHA
 * @returns {Promise<object>} - GitHub API 响应 (包含 content, commit 等) 或错误对象
 */
export async function createFileOrUpdateFile(env, owner, repo, path, branch, contentBase64, commitMessage, existingSha = null) {
    const apiUrl = `${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${path}`;
    const body = {
        message: commitMessage,
        content: contentBase64,
        branch: branch,
    };
    if (existingSha) {
        body.sha = existingSha;
    }

    const responseData = await githubApiRequest(apiUrl, 'PUT', env.GITHUB_PAT, body, env);
    // responseData.status 会被 githubApiRequest 附加
    return responseData;
}

/**
 * 删除 GitHub 上的文件。
 * @param {object} env - Worker 环境变量
 * @param {string} owner - 仓库所有者
 * @param {string} repo - 仓库名
 * @param {string} path - 文件路径
 * @param {string} branch - 分支名
 * @param {string} sha - 要删除文件的 SHA
 * @param {string} commitMessage - Git 提交信息
 * @returns {Promise<object>} - GitHub API 响应 (通常包含 commit 信息) 或错误对象
 */
export async function deleteGitHubFile(env, owner, repo, path, branch, sha, commitMessage) {
    const apiUrl = `${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${path}`;
    const body = {
        message: commitMessage,
        sha: sha,
        branch: branch,
    };

    const responseData = await githubApiRequest(apiUrl, 'DELETE', env.GITHUB_PAT, body, env);
    // responseData.status 会被 githubApiRequest 附加
    return responseData;
}


/**
 * 新添加的函数 或 修改 createFileOrUpdateFile 以适应此场景
 * 确保在指定路径创建一个（可能是空的）文件，通常用于初始化如 index.json。
 * 如果文件已存在，此操作可能根据 GitHub API 行为报错或无操作。
 * 我们这里利用 createFileOrUpdateFile，如果 sha 为 null 且文件不存在，它会创建。
 * @param {object} env - Worker 环境变量
 * @param {string} owner - 仓库所有者
 * @param {string} repo - 仓库名
 * @param {string} path - 要创建的文件的完整路径 (e.g., "username/index.json")
 * @param {string} branch - 分支名
 * @param {string} initialContentBase64 - 文件的初始 Base64 编码内容 (e.g., 空 JSON 对象的 Base64)
 * @param {string} commitMessage - Git 提交信息
 * @returns {Promise<object>} - GitHub API 响应或错误对象
 */
export async function ensureFileExists(env, owner, repo, path, branch, initialContentBase64, commitMessage) {
    // 功能：确保指定路径的文件存在，如果不存在则使用提供的内容创建它。
    // 参数：env, owner, repo, path, branch, initialContentBase64, commitMessage
    // 返回：Promise<object> - GitHub API 的响应

    // 首先检查文件是否已存在，避免不必要的创建尝试或错误
    const existingFile = await getFileShaFromPath(env, owner, repo, path, branch);
    if (existingFile) {
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[ensureFileExists] File ${path} already exists on branch ${branch}. No action needed.`);
        }
        // 返回一个模拟的成功响应或实际的 existingFile 数据
        return { success: true, status: 200, message: "File already exists.", content: existingFile };
    }

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[ensureFileExists] File ${path} does not exist on branch ${branch}. Attempting to create.`);
    }
    // 文件不存在，调用 createFileOrUpdateFile (sha 为 null) 来创建
    return createFileOrUpdateFile(env, owner, repo, path, branch, initialContentBase64, commitMessage, null);
}

/**
 * 列出 GitHub 仓库中指定目录的内容。
 * @param {object} env - Worker 环境变量
 * @param {string} owner - 仓库所有者
 * @param {string} repo - 仓库名
 * @param {string} dirPath - 目录路径 (空字符串表示根目录)
 * @param {string} branch - 分支名
 * @returns {Promise<{files: Array<object>, error?: string, status?: number}>} 包含文件/目录对象数组或错误信息
 */
export async function listDirectoryContents(env, owner, repo, dirPath, branch) {
    // 功能：获取指定目录下的文件和子目录列表。
    // 参数：env, owner, repo, dirPath, branch
    // 返回：Promise<{files: Array<object> (GitHub API 的 item 结构), error?, status?}>
    const apiUrl = `${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${dirPath}?ref=${branch}`;
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[GitHubService] Listing directory contents: ${apiUrl}`);
    }
    const responseData = await githubApiRequest(apiUrl, 'GET', env.GITHUB_PAT, null, env);

    if (responseData.error) {
        if (responseData.status === 404) { // 目录不存在
            if (env.LOGGING_ENABLED === "true") console.log(`[GitHubService] Directory not found (404): ${dirPath}`);
            return { files: [], error: "Directory not found", status: 404 }; // 返回空数组和错误信息
        }
        if (env.LOGGING_ENABLED === "true") console.error(`[GitHubService] Error listing directory ${dirPath}: ${responseData.message}`);
        return { files: [], error: responseData.message, status: responseData.status };
    }

    if (!Array.isArray(responseData)) {
        if (env.LOGGING_ENABLED === "true") console.error(`[GitHubService] Expected array from listDirectoryContents for ${dirPath}, got:`, typeof responseData);
        return { files: [], error: "Invalid response format from GitHub API (expected array).", status: 500 };
    }
    
    return { files: responseData, error: null, status: 200 };
}

