// src/handlers/files.js
// 描述：处理所有与文件操作相关的核心逻辑 (简化版 - 无认证、无加密)
import * as githubService from '../services/github.js';
import { jsonResponse, errorResponse } from '../utils/response.js';
// 辅助函数，暂时放在这里，后续可以移到 utils/crypto.js 或其他
async function calculateSha256(arrayBuffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}
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


/**
 * 获取用户索引文件 (index.json)
 * @param {object} env - Worker 环境变量
 * @param {string} username - 用户名
 * @param {string} targetBranch - 目标分支
 * @returns {Promise<{indexData: object, sha: string|null}>} - 索引数据和SHA，或默认空索引
 */
async function getUserIndex(env, username, targetBranch) {
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;

    const indexFile = await githubService.getFileContentAndSha(env, owner, repo, indexPath, targetBranch);

    if (indexFile && indexFile.content_base64) {
        try {
            const decodedContent = new TextDecoder().decode(base64ToArrayBuffer(indexFile.content_base64));
            const indexData = JSON.parse(decodedContent);
            return { indexData, sha: indexFile.sha };
        } catch (e) {
            console.error(`Error parsing index.json for user ${username}:`, e.message);
            // 如果解析失败，视为新索引处理，但记录错误
            return { indexData: { files: {} }, sha: null }; // 返回空索引，让它被覆盖
        }
    }
    // 索引文件不存在或内容为空
    return { indexData: { files: {} }, sha: null };
}

/**
 * 更新用户索引文件 (index.json)
 * @param {object} env - Worker 环境变量
 * @param {string} username - 用户名
 * @param {object} indexData - 新的索引数据
 * @param {string|null} currentSha - 当前 index.json 的 SHA (如果是更新)
 * @param {string} targetBranch - 目标分支
 * @param {string} commitMessage - 提交信息
 * @returns {Promise<boolean>} - 是否成功
 */
async function updateUserIndex(env, username, indexData, currentSha, targetBranch, commitMessage) {
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;
    const contentBase64 = arrayBufferToBase64(new TextEncoder().encode(JSON.stringify(indexData, null, 2)));

    const result = await githubService.createFileOrUpdateFile(env, owner, repo, indexPath, targetBranch, contentBase64, commitMessage, currentSha);
    return result && !result.error && (result.status === 200 || result.status === 201);
}


export async function handleFileUpload(request, env, ctx, username, originalFilePath) {
    if (!username || !originalFilePath) {
        return errorResponse(env, "Username and original file path are required.", 400);
    }

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";

    const contentArrayBuffer = await request.arrayBuffer();
    if (contentArrayBuffer.byteLength === 0) {
        return errorResponse(env, "Cannot upload an empty file.", 400);
    }

    // 1. 计算文件哈希 (基于原始内容)
    const fileHash = await calculateSha256(contentArrayBuffer);
    const hashedFilePath = `${username}/${fileHash}`; // 实际存储在 GitHub 的路径

    if (env.LOGGING_ENABLED === "true") {
        console.log(`User '${username}', Uploading: original='${originalFilePath}', hash='${fileHash}', targetPath='${hashedFilePath}'`);
    }

    // 2. 获取当前用户索引和其 SHA
    const { indexData, sha: indexSha } = await getUserIndex(env, username, targetBranch);

    // 3. 上传物理文件 (以哈希为名) - 简化版：总是尝试上传，GitHub 的 SHA 机制会处理更新
    // 实际应用中，可以先检查哈希文件是否存在，如果内容相同则跳过物理上传
    const contentBase64 = arrayBufferToBase64(contentArrayBuffer); // 原始内容的 Base64
    const fileCommitMessage = `Chore: Upload content file ${fileHash} for user ${username}`;
    
    // 检查物理哈希文件是否已存在，获取其 SHA 用于更新（或避免重复上传相同内容）
    const existingHashedFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePath, targetBranch);
    const existingHashedFileSha = existingHashedFile ? existingHashedFile.sha : null;

    // 只有当文件不存在，或者我们想要强制更新时才上传（此处简化为如果 SHA 不同则更新）
    // 更优化的方式是比较内容哈希，但此处我们依赖 GitHub 的 PUT 行为
    let physicalFileUploadedOrUpdated = false;
    if (!existingHashedFileSha) { // 如果文件不存在，则创建
        const uploadResult = await githubService.createFileOrUpdateFile(env, owner, repo, hashedFilePath, targetBranch, contentBase64, fileCommitMessage, null);
        if (uploadResult.error) {
            return errorResponse(env, `Failed to upload physical file ${hashedFilePath}: ${uploadResult.message}`, uploadResult.status || 500);
        }
        physicalFileUploadedOrUpdated = true;
        if (env.LOGGING_ENABLED === "true") console.log(`Physical file ${hashedFilePath} created.`);
    } else {
        // 文件已存在，理论上如果内容相同，哈希也相同，无需操作。
        // 但如果逻辑允许用不同原始名指向同一哈希，这里可以跳过。
        // 为简单起见，我们假设如果哈希文件已存在，就认为它 OK。
        physicalFileUploadedOrUpdated = true;
        if (env.LOGGING_ENABLED === "true") console.log(`Physical file ${hashedFilePath} already exists or assumed same content.`);
    }
    

    // 4. 更新索引
    indexData.files[originalFilePath] = fileHash; // 将原始路径映射到哈希
    const indexCommitMessage = `Feat: Update index for ${username}, maps '${originalFilePath}' to '${fileHash}'`;
    const indexUpdated = await updateUserIndex(env, username, indexData, indexSha, targetBranch, indexCommitMessage);

    if (!indexUpdated) {
        // 注意：此时物理文件可能已上传，但索引更新失败。这是一个潜在的不一致状态。
        return errorResponse(env, "File content uploaded, but failed to update user index.", 500);
    }

    return jsonResponse({
        message: `File '${originalFilePath}' (as '${fileHash}') processed successfully for user '${username}'.`,
        username: username,
        originalPath: originalFilePath,
        filePathInRepo: hashedFilePath,
        fileHash: fileHash,
        indexPath: `${username}/index.json`
    }, 201); // 201 Created (或 200 OK 如果是更新)
}


export async function handleFileDownload(request, env, ctx, username, originalFilePath) {
    if (!username || !originalFilePath) {
        return errorResponse(env, "Username and original file path are required.", 400);
    }

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";

    // 1. 获取用户索引
    const { indexData } = await getUserIndex(env, username, targetBranch);
    if (!indexData || Object.keys(indexData.files).length === 0 && !(await githubService.getFileShaFromPath(env, owner, repo, `${username}/index.json`, targetBranch))) {
        // 如果索引数据为空且索引文件本身也不存在，则用户可能不存在或无文件
         return errorResponse(env, `User '${username}' or their index not found.`, 404);
    }


    // 2. 从索引查找文件哈希
    const fileHash = indexData.files[originalFilePath];
    if (!fileHash) {
        return errorResponse(env, `File '${originalFilePath}' not found in index for user '${username}'.`, 404);
    }

    // 3. 下载哈希文件 (此时下载的是原始内容，因为我们还没加密)
    const hashedFilePath = `${username}/${fileHash}`;
    const fileData = await githubService.getFileContentAndSha(env, owner, repo, hashedFilePath, targetBranch);

    if (!fileData || !fileData.content_base64) {
        return errorResponse(env, `Physical file content for '${originalFilePath}' (hash: ${fileHash}) not found. Index may be out of sync.`, 404);
    }
    
    // 4. 返回文件内容
    const fileBuffer = base64ToArrayBuffer(fileData.content_base64);
    const downloadFilename = originalFilePath.split('/').pop() || fileHash;

    return new Response(fileBuffer, {
        headers: {
            'Content-Type': 'application/octet-stream', // 通用二进制流，后续可根据文件类型改进
            'Content-Disposition': `attachment; filename="${downloadFilename}"`,
        }
    });
}

export async function handleFileDelete(request, env, ctx, username, originalFilePath) {
    if (!username || !originalFilePath) {
        return errorResponse(env, "Username and original file path are required.", 400);
    }

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";

    // 1. 获取用户索引
    const { indexData, sha: indexSha } = await getUserIndex(env, username, targetBranch);
    if (!indexData || !indexSha) { // 如果索引文件不存在 (sha is null)，则没什么可删的
        return errorResponse(env, `Index for user '${username}' not found. Nothing to delete.`, 404);
    }

    // 2. 从索引查找文件哈希
    const fileHashToDelete = indexData.files[originalFilePath];
    if (!fileHashToDelete) {
        return errorResponse(env, `File '${originalFilePath}' not found in index for user '${username}'.`, 404);
    }

    // 3. 从索引中移除条目
    delete indexData.files[originalFilePath];
    if (env.LOGGING_ENABLED === "true") {
        console.log(`User '${username}', Removed '${originalFilePath}' (hash: ${fileHashToDelete}) from index.`);
    }
    
    // 4. 更新索引文件
    const indexCommitMessage = `Feat: Update index for ${username}, remove '${originalFilePath}'`;
    const indexUpdated = await updateUserIndex(env, username, indexData, indexSha, targetBranch, indexCommitMessage);
    if (!indexUpdated) {
        return errorResponse(env, `Failed to update user index after removing entry for '${originalFilePath}'. Physical file not deleted.`, 500);
    }

    // 5. 检查该哈希是否仍被其他原始文件名引用
    let isHashStillReferenced = false;
    for (const key in indexData.files) {
        if (indexData.files[key] === fileHashToDelete) {
            isHashStillReferenced = true;
            break;
        }
    }

    let physicalFileDeleteMessage = "";
    if (!isHashStillReferenced) {
        const hashedFilePathToDelete = `${username}/${fileHashToDelete}`;
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Hash ${fileHashToDelete} no longer referenced by user ${username}. Attempting to delete physical file.`);
        }
        const physicalFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePathToDelete, targetBranch);
        if (physicalFile && physicalFile.sha) {
            const deleteResult = await githubService.deleteGitHubFile(env, owner, repo, hashedFilePathToDelete, targetBranch, physicalFile.sha, `Chore: Delete unreferenced content ${fileHashToDelete} for ${username}`);
            if (deleteResult.error) {
                physicalFileDeleteMessage = ` (Warning: Failed to delete physical file ${fileHashToDelete}: ${deleteResult.message})`;
                console.warn(`Failed to delete physical file ${hashedFilePathToDelete} for user ${username}: ${deleteResult.message}`);
            } else {
                physicalFileDeleteMessage = ` (Physical file ${fileHashToDelete} also deleted)`;
            }
        } else {
            physicalFileDeleteMessage = ` (Physical file for hash ${fileHashToDelete} not found or already deleted)`;
        }
    } else {
        physicalFileDeleteMessage = ` (Physical file ${fileHashToDelete} kept as it's still referenced by other entries for user ${username})`;
    }

    return jsonResponse({
        message: `File '${originalFilePath}' removed from index successfully for user '${username}'.${physicalFileDeleteMessage}`
    }, 200);
}

export async function handleFileList(request, env, ctx, username, originalDirectoryPath = '') {
    if (!username) {
        return errorResponse(env, "Username is required.", 400);
    }
    const targetBranch = env.TARGET_BRANCH || "main";

    const { indexData } = await getUserIndex(env, username, targetBranch);
    
    if (!indexData || Object.keys(indexData.files).length === 0) {
        // 如果请求的是根目录且索引为空，返回空列表是合理的
        if (originalDirectoryPath === '' || originalDirectoryPath === '/') {
            return jsonResponse({ path: '/', files: [] }, 200);
        }
        // 否则，如果请求特定子目录但索引为空，则目录不存在
        return errorResponse(env, `User '${username}' has no files or index is empty.`, 404);
    }

    const requestedPathPrefix = originalDirectoryPath === '/' ? '' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
    // 如果是根目录列表，prefix 也应该是空字符串，以便匹配所有路径
    const finalPrefix = (originalDirectoryPath === '' || originalDirectoryPath === '/') ? '' : requestedPathPrefix;

    const filesInDirectory = [];
    const directoriesInDirectory = new Set();

    for (const originalPath in indexData.files) {
        if (originalPath.startsWith(finalPrefix)) {
            const remainingPath = originalPath.substring(finalPrefix.length);
            const parts = remainingPath.split('/');
            if (parts.length === 1 && parts[0] !== '') { // 文件在当前目录下
                filesInDirectory.push({
                    name: parts[0],
                    path: originalPath,
                    type: "file",
                    hash: indexData.files[originalPath]
                });
            } else if (parts.length > 1 && parts[0] !== '') { // 文件在子目录下，记录子目录名
                directoriesInDirectory.add(parts[0]);
            }
        }
    }
    
    const directoryEntries = Array.from(directoriesInDirectory).map(dirName => ({
        name: dirName,
        path: finalPrefix + dirName,
        type: "dir"
    }));

    const allEntries = [...directoryEntries, ...filesInDirectory];
    allEntries.sort((a, b) => {
        if (a.type === 'dir' && b.type === 'file') return -1;
        if (a.type === 'file' && b.type === 'dir') return 1;
        return a.name.localeCompare(b.name);
    });

    return jsonResponse({ path: finalPrefix || '/', files: allEntries }, 200);
}