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
async function githubApiRequest(url, method, pat, body = null, envForLogging) {
    const headers = {
        'Authorization': `token ${pat}`,
        'User-Agent': 'Cloudflare-Worker-GitHub-File-API',
        'Accept': 'application/vnd.github.v3+json',
    };
    if (body) {
        headers['Content-Type'] = 'application/json';
    }

    if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
        console.log(`GitHub API Request: ${method} ${url}`);
        if (body) console.log(`GitHub API Body (partial for brevity): ${JSON.stringify(body).substring(0, 200)}...`);
    }

    try {
        const response = await fetch(url, {
            method,
            headers,
            body: body ? JSON.stringify(body) : null,
        });

        // 对于 204 No Content (例如成功删除但无返回体)，直接返回成功标记
        if (response.status === 204) {
            return { success: true, status: 204 };
        }
        
        const responseData = await response.json().catch(e => {
            // 如果响应体不是 JSON (例如某些错误情况或空的 201)
            if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
                console.warn(`GitHub API response for ${method} ${url} was not valid JSON or empty. Status: ${response.status}`);
            }
            // 对于成功的创建 (201) 但空 body 的情况，也认为是成功的
            if (response.status === 201 && response.headers.get('content-length') === '0') {
                return { success: true, status: 201, message: "Created but no content in response body." };
            }
            return { error: true, message: `Response not JSON: ${e.message}`, status: response.status, rawResponse: response };
        });

        if (!response.ok) {
            // 将 GitHub 的错误信息和状态码包装起来
            const errorMessage = responseData.message || `GitHub API Error (Status: ${response.status})`;
            if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
                console.error(`GitHub API Error: ${method} ${url} - Status: ${response.status}, Message: ${errorMessage}`, responseData);
            }
            return { error: true, message: errorMessage, status: response.status, details: responseData };
        }
        // 将状态码附加到成功响应上，便于调用者判断
        responseData.status = response.status;
        return responseData;

    } catch (error) {
        if (envForLogging && envForLogging.LOGGING_ENABLED === "true") {
            console.error(`Network or parsing error during GitHub API request: ${method} ${url}`, error.message, error.stack);
        }
        return { error: true, message: error.message, status: 500, type: 'network_or_parsing_error' };
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
    // GitHub contents API GET 请求不带文件内容时，如果文件存在，会返回元数据包括 SHA
    // 如果你想强制不获取内容（例如对于大文件只检查存在性），可以使用 HEAD 请求，
    // 但 HEAD 请求的响应头可能不直接包含所有元数据如 SHA，而是通过 Link 头等。
    // 这里我们继续用 GET，因为 Worker 获取内容通常不那么昂贵。
    const apiUrl = `${GITHUB_API_BASE}/repos/${owner}/${repo}/contents/${path}?ref=${branch}`;
    const responseData = await githubApiRequest(apiUrl, 'GET', env.GITHUB_PAT, null, env);

    if (responseData.error) {
        if (responseData.status === 404) return null; // 文件不存在
        console.error(`Failed to get file SHA for ${path}: ${responseData.message}`);
        return null;
    }
    return {
        name: responseData.name,
        path: responseData.path,
        sha: responseData.sha,
        size: responseData.size,
        type: responseData.type,
        status: responseData.status
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