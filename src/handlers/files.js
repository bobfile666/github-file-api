// src/handlers/files.js
// 描述：处理所有与文件操作相关的核心逻辑，包括加密、索引、速率限制和日志。

import * as githubService from '../services/github.js';
import * as d1Service from '../services/d1Database.js';
import * as kvService from '../services/kvStore.js';
import { 
    jsonResponse, 
    errorResponse 
} from '../utils/response.js';
import { 
    calculateSha256, 
    arrayBufferToBase64, 
    base64ToArrayBuffer,
    encryptDataAesGcm,
    decryptDataAesGcm,
    AES_GCM_IV_LENGTH_BYTES // 从 crypto.js 导入 IV 长度常量
} from '../utils/crypto.js'; 

// --- 内部辅助函数：索引管理 ---

/**
 * 获取用户索引文件 (index.json) 内容和 SHA。
 * @param {object} env - Worker 环境变量
 * @param {string} username - 用户名
 * @param {string} targetBranch - 目标分支
 * @returns {Promise<{indexData: object, sha: string|null}>} 索引数据和 SHA，或默认空索引。
 */
async function getUserIndex(env, username, targetBranch) {
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;

    if (env.LOGGING_ENABLED === "true") console.log(`[getUserIndex] User: ${username}, Fetching index: ${indexPath}`);
    const indexFile = await githubService.getFileContentAndSha(env, owner, repo, indexPath, targetBranch);

    if (indexFile && indexFile.content_base64) {
        try {
            const decodedContent = new TextDecoder().decode(base64ToArrayBuffer(indexFile.content_base64));
            const indexData = JSON.parse(decodedContent);
            if (env.LOGGING_ENABLED === "true") console.log(`[getUserIndex] User: ${username}, Index found. SHA: ${indexFile.sha}`);
            return { indexData, sha: indexFile.sha };
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") console.error(`[getUserIndex] User: ${username}, Error parsing index.json:`, e.message);
            // 如果解析失败，视为新索引处理，但记录错误，这样可以覆盖损坏的索引
            return { indexData: { files: {} }, sha: indexFile.sha || null }; // 使用获取到的 SHA 尝试覆盖
        }
    }
    if (env.LOGGING_ENABLED === "true") console.log(`[getUserIndex] User: ${username}, Index not found or content empty. Returning new index structure.`);
    return { indexData: { files: {} }, sha: null }; // 索引文件不存在或内容为空
}

/**
 * 更新或创建用户的 index.json 文件到 GitHub。
 * @param {object} env - Worker 环境变量
 * @param {string} username - 用户名
 * @param {object} indexData - 新的索引数据对象
 * @param {string|null} currentSha - 当前 index.json 的 SHA (如果是更新)，或 null (如果是创建)
 * @param {string} targetBranch - 目标分支名
 * @param {string} commitMessage - Git 提交信息
 * @returns {Promise<boolean>} - true 如果成功，false 如果失败
 */
async function updateUserIndex(env, username, indexData, currentSha, targetBranch, commitMessage) {
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;
    
    // 确保 files 属性存在
    if (!indexData.files) {
        indexData.files = {};
    }

    const contentString = JSON.stringify(indexData, null, 2); // 美化 JSON 输出以便于阅读
    const contentBase64 = arrayBufferToBase64(new TextEncoder().encode(contentString));

    if (env.LOGGING_ENABLED === "true") console.log(`[updateUserIndex] User: ${username}, Updating index. SHA: ${currentSha}, Message: ${commitMessage}`);
    const result = await githubService.createFileOrUpdateFile(env, owner, repo, indexPath, targetBranch, contentBase64, commitMessage, currentSha);
    
    const success = result && !result.error && (result.status === 200 || result.status === 201);
    if (env.LOGGING_ENABLED === "true") {
        if (success) console.log(`[updateUserIndex] User: ${username}, Index update successful.`);
        else console.error(`[updateUserIndex] User: ${username}, Index update failed:`, result?.message || "Unknown error");
    }
    return success;
}


// --- API 处理函数 ---

export async function handleFileUpload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件上传，包括速率限制、加密、GitHub 存储、索引更新、KV 时间戳更新和日志记录。
    // 参数：request, env, ctx, authenticatedUsername (来自令牌), originalFilePath (来自 URL)
    // 返回：Response 对象
    
    if (!authenticatedUsername || !originalFilePath) {
        // 这个检查在 index.js 中可能已经做过，但作为防御性编程保留
        return errorResponse(env, "Authenticated username and original file path are required.", 400);
    }

    const UPLOAD_INTERVAL_SECONDS = parseInt(env.UPLOAD_INTERVAL_SECONDS || "10", 10); // 从环境变量或默认值
    const currentTimeMs = Date.now();
    
    let logEntry = { // 初始化日志条目
        user_id: authenticatedUsername,
        action_type: 'upload',
        original_file_path: originalFilePath,
        file_hash: null, 
        file_size_bytes: 0, 
        status: 'failure', // 默认为失败
        error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'),
        user_agent: request.headers.get('user-agent')
    };

    try {
        // ---- 1. 执行速率限制检查 ----
        const lastUploadTimeMs = await kvService.getLastUploadTimestamp(env, authenticatedUsername);
        if (lastUploadTimeMs && (currentTimeMs - lastUploadTimeMs) < (UPLOAD_INTERVAL_SECONDS * 1000)) {
            const waitSeconds = Math.ceil(((UPLOAD_INTERVAL_SECONDS * 1000) - (currentTimeMs - lastUploadTimeMs)) / 1000);
            logEntry.status = 'rate_limited';
            logEntry.error_message = `Rate limited. Wait ${waitSeconds}s.`;
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry)); // 使用通用日志函数名
            return errorResponse(env, `Too many upload requests. Please wait ${waitSeconds} seconds.`, 429);
        }
        // -------------------------

        const plainContentArrayBuffer = await request.arrayBuffer();
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength;

        if (plainContentArrayBuffer.byteLength === 0) {
            logEntry.error_message = "Cannot upload an empty file.";
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, logEntry.error_message, 400);
        }

        // ---- 2. 获取用户文件加密密钥 ----
        const userFileEncryptionKey = await d1Service.getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) {
            logEntry.error_message = `Encryption key not found for user.`;
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `Could not retrieve encryption key for user '${authenticatedUsername}'. Setup may be incomplete or user inactive.`, 403);
        }
        // ---------------------------------

        // ---- 3. 加密文件内容 ----
        let encryptedData;
        try {
            encryptedData = await encryptDataAesGcm(plainContentArrayBuffer, userFileEncryptionKey);
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileUpload] User: ${authenticatedUsername}, Encryption failed:`, e.message);
            logEntry.error_message = "File encryption failed.";
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, logEntry.error_message, 500);
        }
        const ivAndCiphertextBuffer = new Uint8Array(AES_GCM_IV_LENGTH_BYTES + encryptedData.ciphertext.byteLength);
        ivAndCiphertextBuffer.set(encryptedData.iv, 0);
        ivAndCiphertextBuffer.set(new Uint8Array(encryptedData.ciphertext), AES_GCM_IV_LENGTH_BYTES);
        const contentToUploadBase64 = arrayBufferToBase64(ivAndCiphertextBuffer.buffer);
        // ---------------------------

        // ---- 4. 计算原始文件内容的哈希 (用于索引和文件名) ----
        const fileHash = await calculateSha256(plainContentArrayBuffer);
        logEntry.file_hash = fileHash;
        const hashedFilePath = `${authenticatedUsername}/${fileHash}`; 
        const owner = env.GITHUB_REPO_OWNER;
        const repo = env.GITHUB_REPO_NAME;
        const targetBranch = env.TARGET_BRANCH || "main";

        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileUpload] User '${authenticatedUsername}', Uploading (encrypted): original='${originalFilePath}', hash='${fileHash}', targetPath='${hashedFilePath}'`);
        }

        // ---- 5. 获取当前用户索引和其 SHA ----
        const { indexData, sha: indexSha } = await getUserIndex(env, authenticatedUsername, targetBranch);

        // ---- 6. 上传已加密的物理文件到 GitHub (如果它尚不存在) ----
        const fileCommitMessage = `Chore: Upload encrypted content ${fileHash} for ${authenticatedUsername} (orig: ${originalFilePath})`;
        const existingHashedFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePath, targetBranch);
        
        if (!existingHashedFile) {
            const uploadResult = await githubService.createFileOrUpdateFile(env, owner, repo, hashedFilePath, targetBranch, contentToUploadBase64, fileCommitMessage, null);
            if (uploadResult.error) {
                logEntry.error_message = `GitHub: Failed to upload encrypted file ${hashedFilePath}: ${uploadResult.message}`;
                ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
                return errorResponse(env, logEntry.error_message, uploadResult.status || 500);
            }
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileUpload] User: ${authenticatedUsername}, Encrypted file ${hashedFilePath} created.`);
        } else {
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileUpload] User: ${authenticatedUsername}, Encrypted file for hash ${fileHash} already exists. Skipping physical upload.`);
        }
        
        // ---- 7. 更新索引 ----
        const oldHashForPath = indexData.files[originalFilePath]; // 检查是否是更新操作
        indexData.files[originalFilePath] = fileHash; 
        const indexAction = oldHashForPath ? (oldHashForPath === fileHash ? "Refreshed" : "Updated") : "Added";
        const indexCommitMessage = `Feat: ${indexAction} '${originalFilePath}' to index for ${authenticatedUsername}`;
        const indexUpdated = await updateUserIndex(env, authenticatedUsername, indexData, indexSha, targetBranch, indexCommitMessage);

        if (!indexUpdated) {
            logEntry.error_message = "GitHub: Failed to update user index after file upload.";
            if (env.LOGGING_ENABLED === "true") console.error(logEntry.error_message + ` Physical file ${hashedFilePath} might be orphaned for ${originalFilePath}.`);
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, "Encrypted file content possibly uploaded, but failed to update user index.", 500);
        }

        // ---- 8. 所有操作成功，更新KV中的速率限制时间戳 ----
        const kvTimestampTtl = parseInt(env.KV_TIMESTAMP_TTL_SECONDS || (UPLOAD_INTERVAL_SECONDS * 60 * 6).toString(), 10); // default 1 hour TTL
        ctx.waitUntil(kvService.updateLastUploadTimestamp(env, authenticatedUsername, currentTimeMs, kvTimestampTtl));
        
        // ---- 9. 记录成功日志 ----
        logEntry.status = 'success';
        ctx.waitUntil(d1Service.logFileActivity(env, logEntry));

        return jsonResponse({
            message: `File '${originalFilePath}' (as '${fileHash}') ${indexAction.toLowerCase()} and processed successfully for user '${authenticatedUsername}'.`,
            username: authenticatedUsername,
            originalPath: originalFilePath,
            filePathInRepo: hashedFilePath,
            fileHash: fileHash,
            indexPath: `${authenticatedUsername}/index.json`
        }, indexAction === "Added" ? 201 : 200);

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleFileUpload] User: ${authenticatedUsername}, File: ${originalFilePath}, Unexpected error:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message}`;
        ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
        return errorResponse(env, "An unexpected server error occurred during file upload.", 500);
    }
}

export async function handleFileDownload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能: 处理文件下载，包括认证、索引查找、GitHub文件获取、解密和日志记录。
    // 参数: request, env, ctx, authenticatedUsername, originalFilePath
    // 返回: Response 对象 (包含解密后的文件内容)
    
    if (!authenticatedUsername || !originalFilePath) {
        return errorResponse(env, "Authenticated username and original file path are required.", 400);
    }

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";
    
    let logEntry = {
        user_id: authenticatedUsername,
        action_type: 'download',
        original_file_path: originalFilePath,
        file_hash: null,
        status: 'failure',
        source_ip: request.headers.get('cf-connecting-ip'),
        user_agent: request.headers.get('user-agent')
    };

    try {
        // ---- 1. 获取用户文件加密密钥 ----
        const userFileEncryptionKey = await d1Service.getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) {
            logEntry.error_message = "Encryption key not found for user.";
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `Could not retrieve encryption key for user '${authenticatedUsername}'.`, 403);
        }
        // ---------------------------------

        // ---- 2. 获取用户索引 ----
        const { indexData } = await getUserIndex(env, authenticatedUsername, targetBranch);
        const indexPathInRepo = `${authenticatedUsername}/index.json`; // 用于检查索引文件本身是否存在
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPathInRepo, targetBranch);

        if (!indexFileExists) {
            logEntry.error_message = "User index file not found.";
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `User '${authenticatedUsername}' index not found.`, 404);
        }
        if (!indexData || !indexData.files) { // 确保 indexData.files 存在
            logEntry.error_message = "User index data is invalid or empty.";
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `User '${authenticatedUsername}' index data is invalid.`, 404);
        }

        // ---- 3. 从索引查找文件哈希 ----
        const fileHash = indexData.files[originalFilePath];
        logEntry.file_hash = fileHash;
        if (!fileHash) {
            logEntry.error_message = `File not found in user index.`;
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `File '${originalFilePath}' not found in index for user '${authenticatedUsername}'.`, 404);
        }

        // ---- 4. 下载加密的哈希文件 ----
        const hashedFilePath = `${authenticatedUsername}/${fileHash}`;
        const encryptedFileData = await githubService.getFileContentAndSha(env, owner, repo, hashedFilePath, targetBranch);

        if (!encryptedFileData || !encryptedFileData.content_base64) {
            logEntry.error_message = `Encrypted physical file (hash: ${fileHash}) not found in repository. Index out of sync.`;
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `Physical file content for '${originalFilePath}' (hash: ${fileHash}) not found. Index may be out of sync.`, 404);
        }
        
        // ---- 5. 解密文件内容 ----
        const ivAndCiphertextBuffer = base64ToArrayBuffer(encryptedFileData.content_base64);
        if (ivAndCiphertextBuffer.byteLength < AES_GCM_IV_LENGTH_BYTES) {
            logEntry.error_message = `Encrypted data is too short to contain IV (hash: ${fileHash}).`;
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, "Encrypted data is corrupted (too short).", 500);
        }
        const iv = new Uint8Array(ivAndCiphertextBuffer.slice(0, AES_GCM_IV_LENGTH_BYTES));
        const ciphertext = ivAndCiphertextBuffer.slice(AES_GCM_IV_LENGTH_BYTES);

        let plainContentArrayBuffer;
        try {
            plainContentArrayBuffer = await decryptDataAesGcm(ciphertext, iv, userFileEncryptionKey);
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDownload] User: ${authenticatedUsername}, Decryption failed for ${originalFilePath} (hash ${fileHash}):`, e.message);
            logEntry.error_message = "File decryption failed (key/IV mismatch or corruption).";
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, logEntry.error_message, 500);
        }

        if (!plainContentArrayBuffer) { // decryptDataAesGcm 返回 null 表示解密失败
            logEntry.error_message = "File decryption resulted in null (key/IV mismatch or corruption).";
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, logEntry.error_message, 500);
        }
        // ---------------------------
        
        logEntry.status = 'success';
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength; // 解密后的文件大小
        ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
        
        const downloadFilename = originalFilePath.split('/').pop() || fileHash;
        return new Response(plainContentArrayBuffer, {
            status: 200,
            headers: {
                'Content-Type': 'application/octet-stream', // 或者尝试从文件名推断更具体的MIME类型
                'Content-Disposition': `attachment; filename="${encodeURIComponent(downloadFilename)}"`,
                'Content-Length': plainContentArrayBuffer.byteLength.toString()
            }
        });

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDownload] User: ${authenticatedUsername}, File: ${originalFilePath}, Unexpected error:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message}`;
        ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
        return errorResponse(env, "An unexpected server error occurred during file download.", 500);
    }
}


export async function handleFileDelete(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能: 处理文件删除，包括认证、索引更新、GitHub文件删除（如果不再引用）和日志记录。
    // 参数: request, env, ctx, authenticatedUsername, originalFilePath
    // 返回: Response 对象
    
    if (!authenticatedUsername || !originalFilePath) {
        return errorResponse(env, "Authenticated username and original file path are required.", 400);
    }

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";

    let logEntry = {
        user_id: authenticatedUsername,
        action_type: 'delete',
        original_file_path: originalFilePath,
        file_hash: null,
        status: 'failure',
        source_ip: request.headers.get('cf-connecting-ip'),
        user_agent: request.headers.get('user-agent')
    };

    try {
        // ---- 1. 获取用户索引 ----
        const { indexData, sha: indexSha } = await getUserIndex(env, authenticatedUsername, targetBranch);
        
        const indexPathInRepo = `${authenticatedUsername}/index.json`;
        const indexFileExists = indexSha !== null || (await githubService.getFileShaFromPath(env, owner, repo, indexPathInRepo, targetBranch));

        if (!indexFileExists) {
            logEntry.error_message = "User index file not found. Nothing to delete.";
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `Index for user '${authenticatedUsername}' not found. Nothing to delete.`, 404);
        }
        if (!indexData || !indexData.files) {
             logEntry.error_message = "User index data is invalid or empty.";
             ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
             return errorResponse(env, `User '${authenticatedUsername}' index data is invalid.`,404);
        }


        // ---- 2. 从索引查找文件哈希 ----
        const fileHashToDelete = indexData.files[originalFilePath];
        logEntry.file_hash = fileHashToDelete;
        if (!fileHashToDelete) {
            logEntry.error_message = `File not found in user index.`;
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `File '${originalFilePath}' not found in index for user '${authenticatedUsername}'.`, 404);
        }

        // ---- 3. 从索引中移除条目 ----
        delete indexData.files[originalFilePath];
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDelete] User '${authenticatedUsername}', Removed '${originalFilePath}' (hash: ${fileHashToDelete}) from index.`);
        }
        
        // ---- 4. 更新索引文件 ----
        const indexCommitMessage = `Feat: Remove '${originalFilePath}' from index for ${authenticatedUsername}`;
        // indexSha 必须是有效的，如果索引文件刚被创建且为空，indexSha可能是null，但我们已经检查过indexFileExists
        if (!indexSha && Object.keys(indexData.files).length === 0) { 
            // 如果原索引不存在或为空，且删除后也为空，可能不需要更新一个空索引，或者删除索引文件本身
            // 为简单起见，如果删除后索引为空，也尝试更新它为一个空的 {"files":{}}
            // 或者，如果indexSha为null且删除后indexData.files为空，则不需要调用updateUserIndex，因为没有旧的SHA
        }
        // 只有当 indexSha 存在（表示原文件存在）或者 indexData.files 不为空（表示即使原文件不存在，新文件也要写入）时，才更新
        // 如果 indexSha 为 null 且 indexData.files 也为空（删除了最后一个条目导致索引空），GitHub上可能不需要一个空文件。
        // 但为了保持一致性，我们总是尝试更新。updateUserIndex 会处理 sha 为 null 的情况（创建）。
        const indexUpdated = await updateUserIndex(env, authenticatedUsername, indexData, indexSha, targetBranch, indexCommitMessage);
        if (!indexUpdated) {
            logEntry.error_message = `GitHub: Failed to update user index after removing entry.`;
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `Failed to update user index for '${authenticatedUsername}' after removing entry for '${originalFilePath}'. Physical file not deleted.`, 500);
        }

        // ---- 5. 检查该哈希是否仍被其他原始文件名引用 ----
        let isHashStillReferenced = false;
        for (const key in indexData.files) {
            if (indexData.files[key] === fileHashToDelete) {
                isHashStillReferenced = true;
                break;
            }
        }

        let physicalFileDeleteMessageInfo = "";
        if (!isHashStillReferenced) {
            const hashedFilePathToDelete = `${authenticatedUsername}/${fileHashToDelete}`;
            if (env.LOGGING_ENABLED === "true") {
                console.log(`[handleFileDelete] User: ${authenticatedUsername}, Hash ${fileHashToDelete} no longer referenced. Attempting to delete physical file.`);
            }
            const physicalFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePathToDelete, targetBranch);
            if (physicalFile && physicalFile.sha) {
                const deleteCommitMessage = `Chore: Delete unreferenced content ${fileHashToDelete} for ${authenticatedUsername}`;
                const deleteResult = await githubService.deleteGitHubFile(env, owner, repo, hashedFilePathToDelete, targetBranch, physicalFile.sha, deleteCommitMessage);
                if (deleteResult.error) {
                    physicalFileDeleteMessageInfo = ` (Warning: Failed to delete physical file ${fileHashToDelete}: ${deleteResult.message})`;
                    if (env.LOGGING_ENABLED === "true") console.warn(`[handleFileDelete] User: ${authenticatedUsername}, ${physicalFileDeleteMessageInfo}`);
                } else {
                    physicalFileDeleteMessageInfo = ` (Physical file ${fileHashToDelete} also deleted)`;
                }
            } else {
                physicalFileDeleteMessageInfo = ` (Physical file for hash ${fileHashToDelete} not found or already deleted)`;
            }
        } else {
            physicalFileDeleteMessageInfo = ` (Physical file ${fileHashToDelete} kept as it's still referenced by user ${authenticatedUsername})`;
        }
        
        logEntry.status = 'success';
        logEntry.error_message = physicalFileDeleteMessageInfo; // 可以用error_message字段记录额外信息
        ctx.waitUntil(d1Service.logFileActivity(env, logEntry));

        return jsonResponse({
            message: `File '${originalFilePath}' removed from index successfully for user '${authenticatedUsername}'.${physicalFileDeleteMessageInfo}`
        }, 200);

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDelete] User: ${authenticatedUsername}, File: ${originalFilePath}, Unexpected error:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message}`;
        ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
        return errorResponse(env, "An unexpected server error occurred during file deletion.", 500);
    }
}


export async function handleFileList(request, env, ctx, authenticatedUsername, originalDirectoryPath = '') {
    // 功能: 处理文件列表请求，包括认证、索引获取和日志记录。
    // 参数: request, env, ctx, authenticatedUsername, originalDirectoryPath
    // 返回: Response 对象 (包含文件和目录列表)

    if (!authenticatedUsername) {
        return errorResponse(env, "Authenticated username is required.", 400);
    }
    const targetBranch = env.TARGET_BRANCH || "main";
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    
    let logEntry = {
        user_id: authenticatedUsername,
        action_type: 'list',
        original_file_path: originalDirectoryPath || '/', // 记录请求的路径
        status: 'failure',
        source_ip: request.headers.get('cf-connecting-ip'),
        user_agent: request.headers.get('user-agent')
    };

    try {
        const { indexData } = await getUserIndex(env, authenticatedUsername, targetBranch);
        const indexPathInRepo = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPathInRepo, targetBranch);

        if (!indexFileExists) {
            if (originalDirectoryPath === '' || originalDirectoryPath === '/') {
                if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername}, Index file does not exist. Returning empty list for root.`);
                logEntry.status = 'success'; // 索引不存在，但列表根目录是有效的空列表
                logEntry.error_message = "Index file does not exist, returned empty list.";
                ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
                return jsonResponse({ path: '/', files: [] }, 200);
            }
            logEntry.error_message = "User index file not found.";
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `User '${authenticatedUsername}' or their index file not found.`, 404);
        }
        
        if (!indexData || !indexData.files) { // 确保 indexData.files 存在
             if (originalDirectoryPath === '' || originalDirectoryPath === '/') {
                logEntry.status = 'success';
                logEntry.error_message = "Index data is empty, returned empty list.";
                ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
                return jsonResponse({ path: '/', files: [] }, 200);
            }
            logEntry.error_message = "User index data is invalid or empty.";
            ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
            return errorResponse(env, `User '${authenticatedUsername}' index data is invalid.`, 404); // 或返回空列表
        }

        const requestedPathPrefix = (originalDirectoryPath === '/' || originalDirectoryPath === '') ? '' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
        
        const filesInDirectory = [];
        const directoriesInDirectory = new Set();

        for (const originalPath in indexData.files) {
            if (originalPath.startsWith(requestedPathPrefix)) {
                const remainingPath = originalPath.substring(requestedPathPrefix.length);
                const parts = remainingPath.split('/');
                if (parts.length === 1 && parts[0] !== '') { 
                    filesInDirectory.push({
                        name: parts[0],
                        path: originalPath, // 完整的原始路径
                        type: "file",
                        hash: indexData.files[originalPath]
                        // size: 可以在这里从github获取，但会增加API调用，或在上传时存入index.json
                    });
                } else if (parts.length > 1 && parts[0] !== '') { 
                    directoriesInDirectory.add(parts[0]);
                }
            }
        }
        
        const directoryEntries = Array.from(directoriesInDirectory).map(dirName => ({
            name: dirName,
            path: requestedPathPrefix + dirName,
            type: "dir"
        }));

        const allEntries = [...directoryEntries, ...filesInDirectory];
        allEntries.sort((a, b) => {
            if (a.type === 'dir' && b.type === 'file') return -1;
            if (a.type === 'file' && b.type === 'dir') return 1;
            return a.name.localeCompare(b.name);
        });

        logEntry.status = 'success';
        // logEntry.file_size_bytes = allEntries.length; // 可以记录列出的条目数
        ctx.waitUntil(d1Service.logFileActivity(env, logEntry));

        return jsonResponse({ path: requestedPathPrefix || '/', files: allEntries }, 200);

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleFileList] User: ${authenticatedUsername}, Path: ${originalDirectoryPath}, Unexpected error:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message}`;
        ctx.waitUntil(d1Service.logFileActivity(env, logEntry));
        return errorResponse(env, "An unexpected server error occurred during file listing.", 500);
    }
}