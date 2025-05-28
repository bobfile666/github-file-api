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

// 重写: handleFileUpload (替代旧的 uploadFileToGitHub)
async function handleFileUpload(env, username, originalFilePath, contentArrayBuffer, targetBranch) {
    // 功能: 处理文件上传，文件名使用哈希，并更新用户索引
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   username: 用户名
    //   originalFilePath: 用户提供的原始文件路径 (e.g., "documents/report.pdf")
    //   contentArrayBuffer: 文件的 ArrayBuffer 内容
    //   targetBranch: 目标分支名 (e.g., "main")
    // 返回: Response 对象

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;

    // 1. 计算文件哈希
    const fileHash = await calculateSha256(contentArrayBuffer);
    const hashedFilePath = `${username}/${fileHash}`; // 实际存储在 GitHub 的路径

    if (env.LOGGING_ENABLED === "true") {
        console.log(`Uploading file for user ${username}: original='${originalFilePath}', hash='${fileHash}', targetPath='${hashedFilePath}'`);
    }

    // 2. 获取当前用户索引和其 SHA
    const indexResult = await getUserIndex(env, username, targetBranch);
    if (!indexResult) {
        return errorResponse(env, "Failed to retrieve user index.", 500);
    }
    let { indexData, sha: indexSha } = indexResult;

    // 检查文件是否已存在（通过哈希），如果内容相同，可以避免重复上传物理文件，只需更新索引
    // 为了简化，我们总是尝试上传物理文件。GitHub 的 PUT content API 如果路径和内容都相同，可能不会创建新 commit。
    // 或者我们可以先用 getFileSha 检查 hashedFilePath 是否存在。
    const existingHashedFileSha = await getFileSha(env, owner, repo, targetBranch, hashedFilePath);


    // 3. 上传物理文件 (以哈希为名)
    let fileUploadedOrExisted = false;
    if (existingHashedFileSha) {
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Hashed file ${hashedFilePath} already exists with SHA ${existingHashedFileSha}. Skipping physical upload.`);
        }
        fileUploadedOrExisted = true;
    } else {
        const base64Content = arrayBufferToBase64(contentArrayBuffer);
        const uploadApiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${hashedFilePath}`;
        const uploadBody = {
            message: `Chore: Upload content file ${fileHash} for user ${username}`,
            content: base64Content,
            branch: targetBranch,
        };

        try {
            const uploadResponse = await fetch(uploadApiUrl, {
                method: 'PUT',
                headers: {
                    'Authorization': `token ${env.GITHUB_PAT}`,
                    'User-Agent': 'Cloudflare-Worker-GitHub-API',
                    'Accept': 'application/vnd.github.v3+json',
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(uploadBody),
            });
            const uploadResponseData = await uploadResponse.json();
            if (!uploadResponse.ok) {
                // 如果上传失败因为分支不存在 (不太可能，因为 updateUserIndex 应该依赖于主分支)
                if (uploadResponseData.message && uploadResponseData.message.toLowerCase().includes("branch not found")) {
                     console.error(`Target branch ${targetBranch} for hashed file upload not found.`);
                     return errorResponse(env, `Target branch ${targetBranch} for hashed file upload not found.`, 500);
                }
                console.error(`GitHub API error during hashed file upload ${hashedFilePath}: ${uploadResponse.status}`, uploadResponseData);
                return errorResponse(env, `Failed to upload hashed file: ${uploadResponseData.message || uploadResponse.statusText}`, uploadResponse.status);
            }
            if (env.LOGGING_ENABLED === "true") {
                console.log(`Hashed file ${hashedFilePath} uploaded successfully.`);
            }
            fileUploadedOrExisted = true;
        } catch (e) {
            console.error(`Exception during hashed file upload ${hashedFilePath}:`, e.message, e.stack);
            return errorResponse(env, `Server error during hashed file upload: ${e.message}`, 500);
        }
    }

    if (!fileUploadedOrExisted) {
         // 如果上一步因为某些原因没有完成上传也没有标记为已存在，则返回错误
        return errorResponse(env, "Failed to ensure physical file presence.", 500);
    }

    // 4. 更新索引
    const oldHashForOriginalPath = indexData.files[originalFilePath];
    indexData.files[originalFilePath] = fileHash; // 将原始路径映射到新哈希

    const indexCommitMessage = `Feat: Update index for ${username}, add/update ${originalFilePath}`;
    const indexUpdated = await updateUserIndex(env, username, indexData, indexSha, targetBranch, indexCommitMessage);

    if (!indexUpdated) {
        // 索引更新失败，这是一个问题状态。物理文件可能已上传。
        // 可以考虑回滚物理文件上传，或标记错误让用户重试。
        // 为简单起见，我们只报告错误。
        console.error(`Failed to update user index for ${username} after uploading file ${originalFilePath}.`);
        return errorResponse(env, "File content might have been uploaded, but failed to update user index. Please try again or contact support.", 500);
    }

    // 可选：如果旧的哈希值与新的不同，并且旧哈希不再被任何其他原始文件引用，则可以删除旧的物理哈希文件。
    // 这需要更复杂的引用计数，暂时跳过。

    return jsonResponse({
        message: `File '${originalFilePath}' (as '${fileHash}') uploaded successfully for user '${username}'.`,
        originalPath: originalFilePath,
        filePathInRepo: hashedFilePath,
        fileHash: fileHash,
        indexPath: `${username}/index.json`
    }, 201);
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


// 重写: handleFileDownload
async function handleFileDownload(env, username, originalFilePath, targetBranch) {
    // 功能: 根据原始文件名从索引中查找哈希并下载文件
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   username: 用户名
    //   originalFilePath: 用户请求的原始文件路径
    //   targetBranch: 目标分支名
    // 返回: Response 对象

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;

    // 1. 获取用户索引
    const indexResult = await getUserIndex(env, username, targetBranch);
    if (!indexResult || !indexResult.indexData) {
        return errorResponse(env, `User index for '${username}' not found or failed to load.`, 404);
    }
    const { indexData } = indexResult;

    // 2. 从索引查找文件哈希
    const fileHash = indexData.files[originalFilePath];
    if (!fileHash) {
        return errorResponse(env, `File '${originalFilePath}' not found in index for user '${username}'.`, 404);
    }

    // 3. 下载哈希文件
    const hashedFilePath = `${username}/${fileHash}`;
    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${targetBranch}/${hashedFilePath}`;

    if (env.LOGGING_ENABLED === "true") {
        console.log(`Attempting to download (raw): ${rawUrl} for original path ${originalFilePath}`);
    }

    try {
        const response = await fetch(rawUrl, {
            headers: { 'User-Agent': 'Cloudflare-Worker-GitHub-API' },
        });

        if (!response.ok) {
            if (response.status === 404) {
                if (env.LOGGING_ENABLED === "true") {
                    console.log(`Hashed file not found (404) at ${rawUrl}. Index might be inconsistent.`);
                }
                // 这表示索引指向了一个不存在的哈希文件，是个问题
                return errorResponse(env, `File content for '${originalFilePath}' (hash: ${fileHash}) not found in repository. Index may be out of sync.`, 404);
            }
            const errorText = await response.text();
            console.error(`GitHub raw content error for ${hashedFilePath}: ${response.status}`, errorText);
            return errorResponse(env, `GitHub error: ${response.status} - ${errorText || 'Failed to download file content'}`, response.status);
        }

        const newHeaders = new Headers(response.headers);
        newHeaders.set('X-Proxied-By', 'Cloudflare-Worker-GitHub-API');
        // 使用原始文件名进行下载
        const downloadFilename = originalFilePath.split('/').pop() || fileHash;
        newHeaders.set('Content-Disposition', `attachment; filename="${downloadFilename}"`);

        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: newHeaders
        });

    } catch (error) {
        console.error(`Error in handleFileDownload for ${originalFilePath} (hash ${fileHash}):`, error.message, error.stack);
        return errorResponse(env, `Server error during file download: ${error.message}`, 500);
    }
}

// 重写: handleFileDelete
async function handleFileDelete(env, username, originalFilePath, targetBranch) {
    // 功能: 从索引中移除文件条目，并删除对应的哈希文件
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   username: 用户名
    //   originalFilePath: 要删除的原始文件路径
    //   targetBranch: 目标分支名
    // 返回: Response 对象

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;

    // 1. 获取用户索引
    const indexResult = await getUserIndex(env, username, targetBranch);
    if (!indexResult || !indexResult.indexData) {
        return errorResponse(env, `User index for '${username}' not found or failed to load. Cannot delete.`, 404);
    }
    let { indexData, sha: indexSha } = indexResult;

    // 2. 从索引查找文件哈希
    const fileHashToDelete = indexData.files[originalFilePath];
    if (!fileHashToDelete) {
        return errorResponse(env, `File '${originalFilePath}' not found in index for user '${username}'. Nothing to delete.`, 404);
    }

    // 3. 从索引中移除条目
    delete indexData.files[originalFilePath];
    if (env.LOGGING_ENABLED === "true") {
        console.log(`Removed '${originalFilePath}' from index for user ${username}.`);
    }
    
    // 4. 更新索引文件
    const indexCommitMessage = `Feat: Update index for ${username}, remove ${originalFilePath}`;
    const indexUpdated = await updateUserIndex(env, username, indexData, indexSha, targetBranch, indexCommitMessage);
    if (!indexUpdated) {
        return errorResponse(env, `Failed to update user index after removing entry for '${originalFilePath}'. Physical file may not have been deleted.`, 500);
    }

    // 5. 检查该哈希是否仍被其他原始文件名引用 (简单实现：如果此哈希在当前索引的值中不存在了，就删除)
    // 注意：这非常简化，并发场景下可能有问题。更健壮的需要引用计数。
    let isHashStillReferenced = false;
    for (const key in indexData.files) {
        if (indexData.files[key] === fileHashToDelete) {
            isHashStillReferenced = true;
            break;
        }
    }

    let physicalFileDeletedMessage = "";
    if (!isHashStillReferenced) {
        const hashedFilePathToDelete = `${username}/${fileHashToDelete}`;
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Hash ${fileHashToDelete} is no longer referenced. Attempting to delete physical file: ${hashedFilePathToDelete}`);
        }
        // 需要获取该哈希文件的 SHA 才能删除
        const physicalFileSha = await getFileSha(env, owner, repo, targetBranch, hashedFilePathToDelete);
        if (physicalFileSha) {
            const deleteApiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${hashedFilePathToDelete}`;
            const deleteBody = {
                message: `Chore: Delete unreferenced content file ${fileHashToDelete} for user ${username}`,
                sha: physicalFileSha,
                branch: targetBranch,
            };
            try {
                const deleteResponse = await fetch(deleteApiUrl, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `token ${env.GITHUB_PAT}`,
                        'User-Agent': 'Cloudflare-Worker-GitHub-API',
                        'Accept': 'application/vnd.github.v3+json',
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(deleteBody),
                });
                if (!deleteResponse.ok) {
                    const errorData = await deleteResponse.json();
                    console.warn(`Failed to delete physical file ${hashedFilePathToDelete}: ${deleteResponse.status}`, errorData);
                    physicalFileDeletedMessage = ` (Warning: Failed to delete physical file ${fileHashToDelete})`;
                } else {
                    if (env.LOGGING_ENABLED === "true") {
                        console.log(`Physical file ${hashedFilePathToDelete} deleted successfully.`);
                    }
                    physicalFileDeletedMessage = ` (Physical file ${fileHashToDelete} also deleted)`;
                }
            } catch (e) {
                 console.warn(`Exception during physical file deletion ${hashedFilePathToDelete}:`, e.message);
                 physicalFileDeletedMessage = ` (Warning: Error during physical file ${fileHashToDelete} deletion: ${e.message})`;
            }
        } else {
             if (env.LOGGING_ENABLED === "true") {
                console.log(`Physical file ${hashedFilePathToDelete} for hash ${fileHashToDelete} not found, or SHA could not be retrieved. Skipping deletion.`);
            }
            physicalFileDeletedMessage = ` (Physical file for hash ${fileHashToDelete} not found or already deleted)`;
        }
    } else {
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Hash ${fileHashToDelete} is still referenced by other entries. Physical file not deleted.`);
        }
        physicalFileDeletedMessage = ` (Physical file ${fileHashToDelete} kept as it's still referenced)`;
    }


    return jsonResponse({
        message: `File '${originalFilePath}' removed from index successfully for user '${username}'.${physicalFileDeletedMessage}`
    }, 200);
}

// 重写: handleFileList
async function handleFileList(env, username, originalDirectoryPath, targetBranch) {
    // 功能: 根据用户索引列出指定目录下的文件
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   username: 用户名
    //   originalDirectoryPath: 用户请求的原始目录路径 (e.g., "documents/" or "")
    //   targetBranch: 目标分支名
    // 返回: Response 对象

    // 1. 获取用户索引
    const indexResult = await getUserIndex(env, username, targetBranch);
    if (!indexResult || !indexResult.indexData) {
        // 如果是根目录请求且索引不存在，可以返回空列表，而不是404，因为用户可能还没上传文件
        if (originalDirectoryPath === '') {
             if (env.LOGGING_ENABLED === "true") {
                console.log(`User index for '${username}' not found. Returning empty list for root directory.`);
            }
            return jsonResponse({ path: '/', files: [] }, 200);
        }
        return errorResponse(env, `User index for '${username}' not found or failed to load.`, 404);
    }
    const { indexData } = indexResult;

    // 2. 过滤索引中的文件
    const requestedPathPrefix = originalDirectoryPath === '' ? '' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
    const filesInDirectory = [];
    const directoriesInDirectory = new Set(); // 用于跟踪子目录

    for (const originalPath in indexData.files) {
        if (originalPath.startsWith(requestedPathPrefix)) {
            const remainingPath = originalPath.substring(requestedPathPrefix.length);
            const parts = remainingPath.split('/');
            if (parts.length === 1) { // 文件在当前目录下
                filesInDirectory.push({
                    name: parts[0],
                    path: originalPath, // 完整的原始路径
                    type: "file",
                    hash: indexData.files[originalPath]
                    // size and url would require another GitHub API call per file or assumptions
                });
            } else if (parts.length > 1) { // 文件在子目录下，记录子目录名
                directoriesInDirectory.add(parts[0]);
            }
        }
    }
    
    // 将Set转换为对象数组以匹配之前的格式
    const directoryEntries = Array.from(directoriesInDirectory).map(dirName => ({
        name: dirName,
        path: requestedPathPrefix + dirName,
        type: "dir"
    }));

    const allEntries = [...directoryEntries, ...filesInDirectory];
    // 按类型（目录优先）然后按名称排序
    allEntries.sort((a, b) => {
        if (a.type === 'dir' && b.type === 'file') return -1;
        if (a.type === 'file' && b.type === 'dir') return 1;
        return a.name.localeCompare(b.name);
    });


    if (env.LOGGING_ENABLED === "true") {
        console.log(`Listed ${allEntries.length} items in '${requestedPathPrefix || "/"}' for user ${username}`);
    }
    return jsonResponse({ path: requestedPathPrefix || '/', files: allEntries }, 200);
}

// 新添加的函数
async function getMainBranchSha(env, owner, repo) {
    // 功能: 获取仓库默认分支（通常是 main 或 master）的最新 commit SHA
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   owner: 仓库所有者
    //   repo: 仓库名称
    // 返回: 默认分支的最新 commit SHA，如果失败则返回 null

    // 首先获取仓库信息，以确定默认分支名
    const repoInfoUrl = `https://api.github.com/repos/${owner}/${repo}`;
    let defaultBranchName = 'main'; // 默认猜测是 main

    if (env.LOGGING_ENABLED === "true") {
        console.log(`Fetching repository info to determine default branch: ${repoInfoUrl}`);
    }
    try {
        const repoResponse = await fetch(repoInfoUrl, {
            headers: {
                'Authorization': `token ${env.GITHUB_PAT}`,
                'User-Agent': 'Cloudflare-Worker-GitHub-API',
                'Accept': 'application/vnd.github.v3+json',
            },
        });
        if (repoResponse.ok) {
            const repoData = await repoResponse.json();
            defaultBranchName = repoData.default_branch;
            if (env.LOGGING_ENABLED === "true") {
                console.log(`Default branch for ${owner}/${repo} is ${defaultBranchName}`);
            }
        } else {
            // 如果获取仓库信息失败，记录错误但继续使用 'main' 作为猜测
            const errorData = await repoResponse.text();
            console.error(`Failed to fetch repo info for ${owner}/${repo}: ${repoResponse.status}`, errorData);
        }
    } catch (error) {
        console.error(`Error fetching repo info for ${owner}/${repo}:`, error.message, error.stack);
    }

    // 获取默认分支的最新 commit
    const branchInfoUrl = `https://api.github.com/repos/${owner}/${repo}/branches/${defaultBranchName}`;
    if (env.LOGGING_ENABLED === "true") {
        console.log(`Fetching SHA for default branch (${defaultBranchName}): ${branchInfoUrl}`);
    }
    try {
        const response = await fetch(branchInfoUrl, {
            headers: {
                'Authorization': `token ${env.GITHUB_PAT}`,
                'User-Agent': 'Cloudflare-Worker-GitHub-API',
                'Accept': 'application/vnd.github.v3+json',
            },
        });

        if (!response.ok) {
            const errorData = await response.json();
            console.error(`GitHub API error while fetching default branch SHA for ${defaultBranchName}: ${response.status}`, errorData);
            return null;
        }
        const data = await response.json();
        if (env.LOGGING_ENABLED === "true") {
            console.log(`SHA for default branch ${defaultBranchName} is ${data.commit.sha}`);
        }
        return data.commit.sha;
    } catch (error) {
        console.error(`Error in getMainBranchSha for ${defaultBranchName}:`, error.message, error.stack);
        return null;
    }
}

// 新添加的函数
async function createBranch(env, owner, repo, newBranchName, baseSha) {
    // 功能: 在 GitHub 仓库中创建一个新分支
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   owner: 仓库所有者
    //   repo: 仓库名称
    //   newBranchName: 新分支的名称
    //   baseSha: 新分支将基于此 commit SHA 创建
    // 返回: true 如果成功创建，false 如果失败

    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/git/refs`;
    const body = {
        ref: `refs/heads/${newBranchName}`,
        sha: baseSha,
    };

    if (env.LOGGING_ENABLED === "true") {
        console.log(`Attempting to create branch: ${newBranchName} from SHA: ${baseSha} at ${apiUrl}`);
    }

    try {
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: {
                'Authorization': `token ${env.GITHUB_PAT}`,
                'User-Agent': 'Cloudflare-Worker-GitHub-API',
                'Accept': 'application/vnd.github.v3+json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(body),
        });

        if (response.status === 201) { // 201 Created
            if (env.LOGGING_ENABLED === "true") {
                console.log(`Branch ${newBranchName} created successfully.`);
            }
            return true;
        } else if (response.status === 422) { // Unprocessable Entity - often means ref already exists
            const errorData = await response.json();
            if (errorData.message && errorData.message.toLowerCase().includes("reference already exists")) {
                if (env.LOGGING_ENABLED === "true") {
                    console.log(`Branch ${newBranchName} already exists.`);
                }
                return true; // 认为分支已存在也是一种成功
            }
            console.error(`GitHub API error (422) while creating branch ${newBranchName}:`, errorData);
            return false;
        } else {
            const errorData = await response.json();
            console.error(`GitHub API error while creating branch ${newBranchName}: ${response.status}`, errorData);
            return false;
        }
    } catch (error) {
        console.error(`Error in createBranch for ${newBranchName}:`, error.message, error.stack);
        return false;
    }
}

// 新添加的函数
async function calculateSha256(arrayBuffer) {
    // 功能: 计算 ArrayBuffer 内容的 SHA-256 哈希值
    // 参数:
    //   arrayBuffer: 文件的 ArrayBuffer 内容
    // 返回: SHA-256 哈希值的十六进制字符串
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

// 新添加的函数
async function getUserIndex(env, username, targetBranch) {
    // 功能: 获取指定用户的 index.json 内容
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   username: 用户名
    //   targetBranch: 文件存储的目标分支名 (e.g., "main")
    // 返回: { indexData: object, sha: string | null } 或 null 如果索引不存在或获取失败

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${indexPath}?ref=${targetBranch}`;

    if (env.LOGGING_ENABLED === "true") {
        console.log(`Fetching user index: ${apiUrl}`);
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
                console.log(`User index not found for ${username}. Will create a new one.`);
            }
            return { indexData: { files: {} }, sha: null }; // 返回空索引和 null SHA
        }

        if (!response.ok) {
            const errorData = await response.json();
            console.error(`GitHub API error while fetching user index for ${username}: ${response.status}`, errorData);
            return null;
        }

        const data = await response.json();
        if (data.type !== 'file' || !data.content) {
            console.error(`Invalid index file structure for ${username}:`, data);
            return null;
        }
        // GitHub API 返回 base64 编码的内容
        const decodedContent = atob(data.content);
        const indexData = JSON.parse(decodedContent);
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Successfully fetched user index for ${username} with SHA ${data.sha}`);
        }
        return { indexData, sha: data.sha };

    } catch (error) {
        console.error(`Error in getUserIndex for ${username}:`, error.message, error.stack);
        return null;
    }
}

// 新添加的函数
async function updateUserIndex(env, username, indexData, currentSha, targetBranch, commitMessage) {
    // 功能: 更新或创建用户的 index.json 文件
    // 参数:
    //   env: Cloudflare Worker 的环境变量对象
    //   username: 用户名
    //   indexData: 要写入的索引对象
    //   currentSha: 当前 index.json 的 SHA (如果是更新)，或 null (如果是创建)
    //   targetBranch: 目标分支名
    //   commitMessage: Git 提交信息
    // 返回: true 如果成功，false 如果失败

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;
    const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${indexPath}`;

    const contentBase64 = btoa(JSON.stringify(indexData, null, 2)); // 美化 JSON 输出

    const body = {
        message: commitMessage,
        content: contentBase64,
        branch: targetBranch,
    };
    if (currentSha) {
        body.sha = currentSha; // 提供 SHA 以更新现有文件
    }

    if (env.LOGGING_ENABLED === "true") {
        console.log(`${currentSha ? 'Updating' : 'Creating'} user index for ${username} on branch ${targetBranch}`);
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

        if (!response.ok) {
            const errorData = await response.json();
            console.error(`GitHub API error while updating user index for ${username}: ${response.status}`, errorData);
            // 特别处理：如果是因为分支不存在而无法创建 index.json
            if (responseData.message && responseData.message.toLowerCase().includes("branch not found") && !currentSha) {
                 console.error(`Target branch ${targetBranch} not found. Index cannot be created.`);
            }
            return false;
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`User index for ${username} ${currentSha ? 'updated' : 'created'} successfully.`);
        }
        return true;
    } catch (error) {
        console.error(`Error in updateUserIndex for ${username}:`, error.message, error.stack);
        return false;
    }
}


// 修改: 更新 fetch handler 以使用新的函数和逻辑
export default {
    async fetch(request, env, ctx) {
        // 日志记录 (保持不变)
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Request received: ${request.method} ${request.url}`);
            const safeEnv = {...env};
            delete safeEnv.GITHUB_PAT;
            console.log("Current ENV:", JSON.stringify(safeEnv));
        }

        // 检查必要的环境变量 (保持不变)
        if (!env.GITHUB_PAT || !env.GITHUB_REPO_OWNER || !env.GITHUB_REPO_NAME) {
            console.error("Missing critical GitHub configuration in environment variables.");
            return errorResponse(env, "Server configuration error: Missing GitHub credentials or repository info.", 500);
        }
        
        // 定义目标分支，例如主分支 (可以从环境变量读取，如果需要灵活性)
        const TARGET_BRANCH = env.TARGET_BRANCH || "main"; 
        // 确保主分支存在。如果Worker刚刚部署到一个空仓库，主分支可能不存在。
        // 首次上传时，updateUserIndex 中的 PUT content API 应该能创建主分支（如果配置正确）。
        // 或者可以在 worker 初始化时或通过一个特殊端点来确保主分支存在。
        // 为了简化，我们假设 TARGET_BRANCH (e.g., "main") 在仓库中是存在的。
        // 你可以添加一个启动检查或一个 one-time setup 来创建它。
        // 例如，在 getFileSha 或 getMainBranchSha 稍作修改，若主分支不存在则用 PAT 创建它。
        // 但 GitHub 的 contents API 在指定 branch 时，如果 branch 不存在，它会尝试创建它（如果它是默认分支或基于默认分支）。

        const url = new URL(request.url);
        const pathSegments = url.pathname.split('/').filter(Boolean); // [username, ...originalFilePathParts]

        if (pathSegments.length === 0 && request.method === 'GET') {
            return jsonResponse({
                message: "GitHub Hashed File API Worker. Usage: /[username]/[filepath]",
                repository: `https://github.com/${env.GITHUB_REPO_OWNER}/${env.GITHUB_REPO_NAME}`,
                targetBranch: TARGET_BRANCH
            });
        }
        
        if (pathSegments.length < 1) {
            return errorResponse(env, "Invalid path. Username is required. Expected format: /[username]/[filepath] or /[username]/ for listing root.", 400);
        }

        const username = pathSegments[0];
        // originalFilePath 可以包含子目录，例如 "documents/notes/meeting.txt"
        // 或者为空，用于列出用户根目录
        const originalFilePath = pathSegments.slice(1).join('/'); 

        switch (request.method) {
            case 'PUT': // 上传文件，原始路径从 URL 中获取
            case 'POST':
                if (!originalFilePath) {
                    return errorResponse(env, "Original file path is required for uploads (e.g., /user/path/to/file.txt).", 400);
                }
                const contentArrayBuffer = await request.arrayBuffer();
                if (contentArrayBuffer.byteLength === 0) {
                    return errorResponse(env, "Cannot upload an empty file.", 400);
                }
                // X-Commit-Message 不再直接用于文件提交，而是用于索引提交
                return await handleFileUpload(env, username, originalFilePath, contentArrayBuffer, TARGET_BRANCH);

            case 'GET': // 下载文件或列出目录
                if (originalFilePath) { 
                    // 如果路径末尾是 /，视为列出目录
                    if (originalFilePath.endsWith('/')) {
                        return await handleFileList(env, username, originalFilePath, TARGET_BRANCH);
                    }
                    // 否则，视为下载文件
                    return await handleFileDownload(env, username, originalFilePath, TARGET_BRANCH);
                } else { // 没有 originalFilePath，列出用户根目录
                    return await handleFileList(env, username, '', TARGET_BRANCH);
                }

            case 'DELETE':
                if (!originalFilePath) {
                    return errorResponse(env, "Original file path is required for deletion.", 400);
                }
                 if (originalFilePath.endsWith('/')) {
                    return errorResponse(env, "Cannot delete a directory. Please delete files individually.", 400);
                }
                // X-Commit-Message 不再直接用于文件提交，而是用于索引提交
                return await handleFileDelete(env, username, originalFilePath, TARGET_BRANCH);

            default:
                return errorResponse(env, `Method ${request.method} not allowed.`, 405);
        }
    },
};