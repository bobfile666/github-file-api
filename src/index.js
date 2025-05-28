// src/index.js

// 辅助函数：创建 JSON 响应
function jsonResponse(data, status = 200, headers = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', ...headers },
    });
}

// 辅助函数：创建错误响应
// 修改: 添加 env 参数
function errorResponse(env, message, status = 500) {
    // 检查 env 是否被正确传递，以及 LOGGING_ENABLED 是否为 "true"
    if (env && env.LOGGING_ENABLED === "true") {
        console.error(`Error: ${message}, Status: ${status}`);
    } else if (!env) {
        // 如果 env 没有被传递，也记录一个控制台错误，帮助调试
        console.error(`Error (env not provided to errorResponse): ${message}, Status: ${status}`);
    }
    return jsonResponse({ error: message }, status);
}

// 辅助函数：记录日志（如果开启）
function logMessage(message) {
    // env 会在 onRequest 中被传递，或者在模块作用域内通过全局 env 访问（取决于 worker 格式）
    // 为了简单起见，我们假设 env 在全局可用或通过参数传递
    // 在实际的模块 worker 中，env 通常作为参数传递给 fetch 处理函数
    // 这里我们假设 env 是一个在作用域内可访问的对象
    // if (typeof env !== 'undefined' && env.LOGGING_ENABLED === "true") {
    // console.log(message);
    // }
    // 由于 env 不是全局的，我们将在需要日志的地方直接检查 env.LOGGING_ENABLED
}


// 新添加的函数
async function getFileSha(env, owner, repo, branch, path) {
    // 功能: 获取 GitHub 上指定路径文件的 SHA，如果文件不存在则返回 null
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   owner: 仓库所有者
    //   repo: 仓库名称
    //   branch: 分支名称
    //   path: 文件在仓库中的路径
    // 返回: 文件的 SHA 字符串或 null

    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${path}?ref=${branch}`;
    if (env.LOGGING_ENABLED === "true") {
        console.log(`Fetching SHA for: ${apiUrl}`);
    }

    try {
        const response = await fetch(apiUrl, {
            headers: {
                'Authorization': `token ${env.GITHUB_PAT}`,
                'User-Agent': 'Cloudflare-Worker-GitHub-API',
                'Accept': 'application/vnd.github.v3+json',
            },
        });

        if (response.status === 404) {
            if (env.LOGGING_ENABLED === "true") {
                console.log(`File not found (404) at ${path} on branch ${branch}, cannot get SHA.`);
            }
            return null; // 文件不存在
        }

        if (!response.ok) {
            const errorData = await response.json();
            console.error(`GitHub API error while fetching SHA for ${path} on branch ${branch}: ${response.status}`, errorData);
            throw new Error(`GitHub API error: ${response.status} - ${errorData.message || 'Failed to fetch file metadata'}`);
        }

        const data = await response.json();
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Successfully fetched SHA: ${data.sha} for ${path} on branch ${branch}`);
        }
        return data.sha;
    } catch (error) {
        console.error(`Error in getFileSha for ${path} on branch ${branch}:`, error.message, error.stack);
        // 不在这里抛出，让调用者决定如何处理 SHA 获取失败的情况（通常是认为文件不存在或无法操作）
        return null;
    }
}

// src/index.js
// 修改: 在 catch 块中调用 errorResponse 时传递 env
async function uploadFileToGitHub(env, username, filePath, contentArrayBuffer, commitMessage) {
    // 功能: 上传或更新文件到用户的 GitHub 分支
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   username: 用户名，将作为分支名
    //   filePath: 文件在仓库中的路径
    //   contentArrayBuffer: 文件的 ArrayBuffer 内容
    //   commitMessage: Git 提交信息
    // 返回: 包含操作结果的 Response 对象

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const branch = username; // 用户名即分支名

    // 将 ArrayBuffer 转换为 Base64 字符串
    const base64Content = arrayBufferToBase64(contentArrayBuffer);

    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}`;
    if (env.LOGGING_ENABLED === "true") {
        console.log(`Attempting to upload/update: ${apiUrl} on branch ${branch}`);
    }

    const sha = await getFileSha(env, owner, repo, branch, filePath);

    const body = {
        message: commitMessage,
        content: base64Content,
        branch: branch,
    };

    if (sha) {
        body.sha = sha;
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Updating existing file ${filePath} on branch ${branch} with SHA ${sha}`);
        }
    } else {
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Creating new file ${filePath} on branch ${branch}`);
        }
    }

    try {
        const response = await fetch(apiUrl, {
            method: 'PUT',
            headers: {
                'Authorization': `token ${env.GITHUB_PAT}`,
                'User-Agent': 'Cloudflare-Worker-GitHub-API',
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
        });

        const responseData = await response.json();

        if (!response.ok) {
            console.error(`GitHub API error during upload/update for ${filePath} on branch ${branch}: ${response.status}`, responseData);
            // 修改: 传递 env
            return errorResponse(env, `GitHub API error: ${response.status} - ${responseData.message || 'Failed to upload file'}`, response.status);
        }

        if (env.LOGGING_ENABLED === "true") {
            console.log(`File ${filePath} successfully ${sha ? 'updated' : 'created'} on branch ${branch}. Commit: ${responseData.commit.sha}`);
        }
        return jsonResponse({
            message: `File ${filePath} successfully ${sha ? 'updated' : 'created'} on branch ${branch}.`,
            path: responseData.content.path,
            commit: responseData.commit.sha,
            url: responseData.content.html_url
        }, sha ? 200 : 201);

    } catch (error) {
        console.error(`Error in uploadFileToGitHub for ${filePath} on branch ${branch}:`, error.message, error.stack);
        // 修改: 传递 env
        return errorResponse(env, "Server error during file upload: " + error.message, 500);
    }
}


// 新添加的函数
function arrayBufferToBase64(buffer) {
    // 功能: 将 ArrayBuffer 转换为 Base64 编码的字符串
    // 参数:
    //   buffer: ArrayBuffer 对象
    // 返回: Base64 编码的字符串
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}


// 修改: 在 catch 块和错误处理中调用 errorResponse 时传递 env
async function getFileFromGitHub(env, username, filePath) {
    // 功能: 从用户的 GitHub 分支下载文件
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   username: 用户名，将作为分支名
    //   filePath: 文件在仓库中的路径
    // 返回: 包含文件内容的 Response 对象，或错误 Response

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const branch = username;
    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filePath}`;

    if (env.LOGGING_ENABLED === "true") {
        console.log(`Attempting to download (raw): ${rawUrl}`);
    }

    try {
        const response = await fetch(rawUrl, {
            headers: {
                'User-Agent': 'Cloudflare-Worker-GitHub-API',
            },
        });

        if (!response.ok) {
            if (response.status === 404) {
                if (env.LOGGING_ENABLED === "true") {
                    console.log(`File not found (404) at ${rawUrl}`);
                }
                // 修改: 传递 env
                return errorResponse(env, `File not found at path: ${filePath} for user ${username}`, 404);
            }
            const errorText = await response.text();
            console.error(`GitHub raw content error for ${filePath} on branch ${branch}: ${response.status}`, errorText);
            // 修改: 传递 env
            return errorResponse(env, `GitHub error: ${response.status} - ${errorText || 'Failed to download file'}`, response.status);
        }

        if (env.LOGGING_ENABLED === "true") {
            console.log(`File ${filePath} successfully fetched from branch ${branch}`);
        }
        const newHeaders = new Headers(response.headers);
        newHeaders.set('X-Proxied-By', 'Cloudflare-Worker-GitHub-API');
        newHeaders.set('Content-Disposition', `attachment; filename="${filePath.split('/').pop()}"`);

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: newHeaders
        });

    } catch (error) {
        console.error(`Error in getFileFromGitHub for ${filePath} on branch ${branch}:`, error.message, error.stack);
        // 修改: 传递 env
        return errorResponse(env, "Server error during file download: " + error.message, 500);
    }
}

// 修改: 在 catch 块和错误处理中调用 errorResponse 时传递 env
async function deleteFileFromGitHub(env, username, filePath, commitMessage) {
    // 功能: 从用户的 GitHub 分支删除文件
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   username: 用户名，将作为分支名
    //   filePath: 文件在仓库中的路径
    //   commitMessage: Git 提交信息
    // 返回: 包含操作结果的 Response 对象

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const branch = username;

    if (env.LOGGING_ENABLED === "true") {
        console.log(`Attempting to delete: ${filePath} from branch ${branch}`);
    }

    const sha = await getFileSha(env, owner, repo, branch, filePath);
    if (!sha) {
        if (env.LOGGING_ENABLED === "true") {
            console.log(`File not found: ${filePath} on branch ${branch}, cannot delete.`);
        }
        // 修改: 传递 env
        return errorResponse(env, `File not found at path: ${filePath} for user ${username}, cannot delete.`, 404);
    }

    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${filePath}`;
    const body = {
        message: commitMessage,
        sha: sha,
        branch: branch,
    };

    try {
        const response = await fetch(apiUrl, {
            method: 'DELETE',
            headers: {
                'Authorization': `token ${env.GITHUB_PAT}`,
                'User-Agent': 'Cloudflare-Worker-GitHub-API',
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
        });

        if (!response.ok) {
            if (response.status === 404) {
                 // 修改: 传递 env
                return errorResponse(env, `File not found (or already deleted) at path: ${filePath} for user ${username}`, 404);
            }
            const errorData = await response.json();
            console.error(`GitHub API error during deletion of ${filePath} on branch ${branch}: ${response.status}`, errorData);
            // 修改: 传递 env
            return errorResponse(env, `GitHub API error: ${response.status} - ${errorData.message || 'Failed to delete file'}`, response.status);
        }
        
        const responseData = await response.json(); 
        if (env.LOGGING_ENABLED === "true") {
            console.log(`File ${filePath} successfully deleted from branch ${branch}. Commit: ${responseData.commit.sha}`);
        }
        return jsonResponse({
            message: `File ${filePath} successfully deleted from branch ${branch}.`,
            commit: responseData.commit.sha
        }, 200);

    } catch (error) {
        console.error(`Error in deleteFileFromGitHub for ${filePath} on branch ${branch}:`, error.message, error.stack);
        // 修改: 传递 env
        return errorResponse(env, "Server error during file deletion: " + error.message, 500);
    }
}

// 修改: 在 catch 块和错误处理中调用 errorResponse 时传递 env
async function listFilesFromGitHub(env, username, directoryPath = '') {
    // 功能: 列出用户 GitHub 分支中指定目录的文件和文件夹
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   username: 用户名，将作为分支名
    //   directoryPath: 要列出的目录路径，默认为根目录
    // 返回: 包含文件列表的 Response 对象

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const branch = username;

    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${directoryPath}?ref=${branch}`;
    if (env.LOGGING_ENABLED === "true") {
        console.log(`Attempting to list files in: ${apiUrl}`);
    }

    try {
        const response = await fetch(apiUrl, {
            headers: {
                'Authorization': `token ${env.GITHUB_PAT}`,
                'User-Agent': 'Cloudflare-Worker-GitHub-API',
                'Accept': 'application/vnd.github.v3+json',
            },
        });

        if (response.status === 404) {
            const errorDataCheck = await response.clone().json().catch(() => null);
            if (errorDataCheck && errorDataCheck.message && errorDataCheck.message.includes("No commit found for the ref")) {
                if (env.LOGGING_ENABLED === "true") {
                    console.log(`Branch ${branch} not found or empty.`);
                }
                // 注意：这里返回的是 jsonResponse，不需要改动 errorResponse
                return jsonResponse({ message: `User (branch) '${username}' not found or has no content. Please upload a file first to create the branch.`, files: [] }, 200);
            }
            if (env.LOGGING_ENABLED === "true") {
                console.log(`Directory not found (404): ${directoryPath} on branch ${branch}`);
            }
            // 修改: 传递 env
            return errorResponse(env, `Directory not found at path: /${directoryPath} for user ${username}`, 404);
        }

        if (!response.ok) {
            const errorData = await response.json();
            console.error(`GitHub API error while listing files in ${directoryPath} on branch ${branch}: ${response.status}`, errorData);
            // 修改: 传递 env
            return errorResponse(env, `GitHub API error: ${response.status} - ${errorData.message || 'Failed to list files'}`, response.status);
        }

        const data = await response.json();
        const files = data.map(item => ({
            name: item.name,
            path: item.path,
            type: item.type,
            size: item.size,
            url: item.html_url,
            download_url: item.download_url
        }));

        if (env.LOGGING_ENABLED === "true") {
            console.log(`Successfully listed ${files.length} items in ${directoryPath} on branch ${branch}`);
        }
        return jsonResponse({ path: directoryPath || '/', files: files }, 200);

    } catch (error) {
        console.error(`Error in listFilesFromGitHub for ${directoryPath} on branch ${branch}:`, error.message, error.stack);
        // 修改: 传递 env
        return errorResponse(env, "Server error during file listing: " + error.message, 500);
    }
}


// 修改: 所有对 errorResponse 的调用都传递 env
export default {
    async fetch(request, env, ctx) {
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Request received: ${request.method} ${request.url}`);
            const safeEnv = {...env};
            delete safeEnv.GITHUB_PAT; // 确保 PAT 不被记录到日志中
            console.log("Current ENV:", JSON.stringify(safeEnv));
        }

        const url = new URL(request.url);
        const pathSegments = url.pathname.split('/').filter(Boolean);

        if (pathSegments.length === 0 && request.method === 'GET') {
            return jsonResponse({
                message: "GitHub File API Worker. Usage: /[username]/[filepath]",
                repository: `https://github.com/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}`
            });
        }
        
        if (pathSegments.length < 1) {
            // 修改: 传递 env
            return errorResponse(env, "Invalid path. Expected format: /[username]/[filepath] or /[username]/ for listing root.", 400);
        }

        const username = pathSegments[0];
        const filePath = pathSegments.slice(1).join('/');

        if (!env.GITHUB_PAT || !env.GITHUB_REPO_OWNER || !env.GITHUB_REPO_NAME) {
            console.error("Missing critical GitHub configuration in environment variables.");
            // 修改: 传递 env
            return errorResponse(env, "Server configuration error: Missing GitHub credentials or repository info.", 500);
        }
        
        switch (request.method) {
            case 'PUT':
            case 'POST':
                if (!filePath) {
                    // 修改: 传递 env
                    return errorResponse(env, "File path is required for uploads.", 400);
                }
                const contentArrayBuffer = await request.arrayBuffer();
                if (contentArrayBuffer.byteLength === 0) {
                    // 修改: 传递 env
                    return errorResponse(env, "Cannot upload an empty file.", 400);
                }
                const commitMessageUpload = request.headers.get('X-Commit-Message') || `Upload file: ${filePath} by ${username}`;
                return await uploadFileToGitHub(env, username, filePath, contentArrayBuffer, commitMessageUpload);

            case 'GET':
                if (filePath) {
                    return await getFileFromGitHub(env, username, filePath);
                } else {
                    return await listFilesFromGitHub(env, username, '');
                }

            case 'DELETE':
                if (!filePath) {
                    // 修改: 传递 env
                    return errorResponse(env, "File path is required for deletion.", 400);
                }
                const commitMessageDelete = request.headers.get('X-Commit-Message') || `Delete file: ${filePath} by ${username}`;
                return await deleteFileFromGitHub(env, username, filePath, commitMessageDelete);

            default:
                // 修改: 传递 env
                return errorResponse(env, `Method ${request.method} not allowed.`, 405);
        }
    },
};