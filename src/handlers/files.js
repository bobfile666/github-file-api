// src/handlers/files.js
// 描述：处理所有与文件操作相关的核心逻辑，包括认证后的操作、加密、索引、速率限制和日志。

import * as githubService from '../services/github.js';
import { jsonResponse, errorResponse } from '../utils/response.js';
import { 
    AES_GCM_IV_LENGTH_BYTES,
    calculateSha256, 
    arrayBufferToBase64, 
    base64ToArrayBuffer,
    encryptDataAesGcm,
    decryptDataAesGcm,
} from '../utils/crypto.js'; 
import { getUserSymmetricKey, logFileActivity } from '../services/d1Database.js';
import * as kvService from '../services/kvStore.js';

// --- 内部辅助函数：索引管理 ---
// getUserIndex 和 updateUserIndex 是内部辅助函数，不需要从 files.js 导出给 index.js
// 它们被下面的导出函数所调用。
async function getUserIndex(env, username, targetBranch) {
    // 功能：获取指定用户的 index.json 内容。
    // (代码和之前一样)
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[getUserIndex] User: ${username} - Fetching index: ${indexPath}`);
    }

    const indexFile = await githubService.getFileContentAndSha(env, owner, repo, indexPath, targetBranch);

    if (indexFile && indexFile.content_base64) {
        try {
            const decodedContent = new TextDecoder().decode(base64ToArrayBuffer(indexFile.content_base64));
            const indexData = JSON.parse(decodedContent);
            if (env.LOGGING_ENABLED === "true") {
                console.log(`[getUserIndex] User: ${username} - Index found with SHA: ${indexFile.sha}. Files count: ${Object.keys(indexData.files || {}).length}`);
            }
            return { indexData: indexData.files ? indexData : { files: {} }, sha: indexFile.sha };
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") {
                console.error(`[getUserIndex] User: ${username} - Error parsing index.json:`, e.message, "Content causing error:", indexFile.content_base64.substring(0,100));
            }
            return { indexData: { files: {} }, sha: indexFile.sha }; 
        }
    }
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[getUserIndex] User: ${username} - Index file not found or content empty. Returning new index structure.`);
    }
    return { indexData: { files: {} }, sha: null };
}

async function updateUserIndex(env, username, indexData, currentSha, targetBranch, commitMessage) {
    // 功能：更新或创建用户的 index.json 文件。
    // (代码和之前一样)
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;
    
    const dataToWrite = { files: indexData.files || {} };
    const contentBase64 = arrayBufferToBase64(new TextEncoder().encode(JSON.stringify(dataToWrite, null, 2)));

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[updateUserIndex] User: ${username} - Attempting to ${currentSha ? 'update' : 'create'} index. SHA: ${currentSha || 'N/A'}. Commit: "${commitMessage}"`);
    }

    const result = await githubService.createFileOrUpdateFile(env, owner, repo, indexPath, targetBranch, contentBase64, commitMessage, currentSha);
    
    const success = result && !result.error && (result.status === 200 || result.status === 201);
    if (env.LOGGING_ENABLED === "true") {
        if (success) {
            console.log(`[updateUserIndex] User: ${username} - Index ${currentSha ? 'updated' : 'created'} successfully.`);
        } else {
            console.error(`[updateUserIndex] User: ${username} - Failed to update index. GitHub API response:`, result);
        }
    }
    return success;
}


// --- 导出的请求处理函数 ---

export async function handleFileUpload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件上传，包括唯一原始文件名检查、速率限制、加密、GitHub 存储、索引更新、KV 时间戳更新和日志记录。
    // (函数开始部分的参数检查和日志初始化与之前类似)
    if (!authenticatedUsername || !originalFilePath) {
        return errorResponse(env, "Authenticated username and original file path are required for upload.", 400);
    }

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleFileUpload] User: ${authenticatedUsername} - Initiating upload for: ${originalFilePath}`);
    }

    // ---- 1. 速率限制检查 ----
    const UPLOAD_INTERVAL_SECONDS = parseInt(env.UPLOAD_INTERVAL_SECONDS || "10", 10);
    const currentTimeMs = Date.now();
    // ... (速率限制检查逻辑和之前一样)
    const lastUploadTimeMs = await kvService.getLastUploadTimestamp(env, authenticatedUsername);
    if (lastUploadTimeMs && (currentTimeMs - lastUploadTimeMs) < (UPLOAD_INTERVAL_SECONDS * 1000)) {
        const waitSeconds = Math.ceil(((UPLOAD_INTERVAL_SECONDS * 1000) - (currentTimeMs - lastUploadTimeMs)) / 1000);
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileUpload] User: ${authenticatedUsername} - Rate limited. Wait: ${waitSeconds}s`);
        }
        return errorResponse(env, `Too many upload requests. Please wait ${waitSeconds} seconds.`, 429);
    }
    // -------------------------

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";
    
    let logEntry = { /* ... (logEntry 初始化和之前一样) ... */ 
        user_id: authenticatedUsername,
        action_type: 'upload',
        original_file_path: originalFilePath,
        file_hash: null, 
        file_size_bytes: 0, 
        status: 'failure', 
        error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'),
        user_agent: request.headers.get('user-agent')
    };

    try {
        const plainContentArrayBuffer = await request.arrayBuffer();
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength;

        if (plainContentArrayBuffer.byteLength === 0) {
            logEntry.error_message = "Cannot upload an empty file.";
            // ... (记录日志并返回错误)
            if (env.LOGGING_ENABLED === "true") console.warn(`[handleFileUpload] User: ${authenticatedUsername} - ${logEntry.error_message}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, logEntry.error_message, 400);
        }

        // ---- 2. 获取用户索引并检查原始文件名是否已存在 ----
        const { indexData, sha: indexSha } = await getUserIndex(env, authenticatedUsername, targetBranch);
        if (indexData && indexData.files && indexData.files[originalFilePath]) {
            logEntry.error_message = `File with the name '${originalFilePath}' already exists for this user. Upload aborted to prevent overwrite.`;
            if (env.LOGGING_ENABLED === "true") {
                console.warn(`[handleFileUpload] User: ${authenticatedUsername} - ${logEntry.error_message}`);
            }
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, logEntry.error_message, 409); // 409 Conflict
        }
        // ------------------------------------------------

        // ---- 3. 获取用户文件加密密钥 ----
        // ... (逻辑和之前一样: getUserSymmetricKey)
        const userFileEncryptionKey = await getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) {
            logEntry.error_message = `Encryption key not found for user.`;
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileUpload] User: ${authenticatedUsername} - ${logEntry.error_message}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, `Could not retrieve encryption key for user '${authenticatedUsername}'. Setup may be incomplete.`, 403);
        }
        // ---------------------------------
        
        // ---- 4. 加密文件内容 ----
        // ... (逻辑和之前一样: encryptDataAesGcm)
        let encryptedData;
        try {
            encryptedData = await encryptDataAesGcm(plainContentArrayBuffer, userFileEncryptionKey);
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileUpload] User: ${authenticatedUsername} - Encryption failed for ${originalFilePath}:`, e.message, e.stack);
            logEntry.error_message = "File encryption failed.";
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, logEntry.error_message, 500);
        }
        const ivAndCiphertextBuffer = new Uint8Array(encryptedData.iv.byteLength + encryptedData.ciphertext.byteLength);
        ivAndCiphertextBuffer.set(encryptedData.iv, 0);
        ivAndCiphertextBuffer.set(new Uint8Array(encryptedData.ciphertext), encryptedData.iv.byteLength);
        const contentToUploadBase64 = arrayBufferToBase64(ivAndCiphertextBuffer.buffer);
        // ---------------------------

        // ---- 5. 计算原始文件内容的哈希 ----
        const fileHash = await calculateSha256(plainContentArrayBuffer);
        logEntry.file_hash = fileHash;
        const hashedFilePath = `${authenticatedUsername}/${fileHash}`; 

        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileUpload] User: ${authenticatedUsername} - Encrypted. Original='${originalFilePath}', Hash='${fileHash}', TargetPath='${hashedFilePath}'`);
        }

        // ---- 6. 上传已加密的物理文件到 GitHub ----
        // (逻辑和之前一样：检查哈希文件是否存在，如果不存在则创建)
        const fileCommitMessage = `Chore: Upload encrypted content ${fileHash} for user ${authenticatedUsername} (file: ${originalFilePath})`;
        const existingHashedFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePath, targetBranch);
        if (!existingHashedFile) { 
            const uploadResult = await githubService.createFileOrUpdateFile(env, owner, repo, hashedFilePath, targetBranch, contentToUploadBase64, fileCommitMessage, null);
            if (uploadResult.error) {
                logEntry.error_message = `GitHub: Failed to upload encrypted file ${hashedFilePath}: ${uploadResult.message}`;
                if (env.LOGGING_ENABLED === "true") console.error(`[handleFileUpload] User: ${authenticatedUsername} - ${logEntry.error_message}`);
                ctx.waitUntil(logFileActivity(env, logEntry));
                return errorResponse(env, logEntry.error_message, uploadResult.status || 500);
            }
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileUpload] User: ${authenticatedUsername} - Encrypted file ${hashedFilePath} created on GitHub.`);
        } else {
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileUpload] User: ${authenticatedUsername} - Encrypted file for hash ${fileHash} already exists on GitHub. Skipping physical upload.`);
        }
        // -----------------------------------------
        
        // ---- 7. 更新索引 ----
        if (!indexData.files) indexData.files = {}; // 确保 files 对象存在
        indexData.files[originalFilePath] = fileHash; 
        const indexCommitMessage = `Feat: Update index for ${authenticatedUsername}, add '${originalFilePath}' mapping to '${fileHash}'`;
        const indexUpdated = await updateUserIndex(env, authenticatedUsername, indexData, indexSha, targetBranch, indexCommitMessage);

        if (!indexUpdated) {
            logEntry.error_message = "GitHub: Failed to update user index after file upload.";
            // ... (记录日志并返回错误)
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileUpload] User: ${authenticatedUsername} - ${logEntry.error_message} Physical file ${hashedFilePath} might be orphaned if newly created.`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, "Encrypted file content possibly uploaded, but failed to update user index.", 500);
        }
        // --------------------

        // ---- 8. 更新KV速率限制时间戳 ----
        // ... (逻辑和之前一样: updateLastUploadTimestamp)
        const kvTimestampTtl = parseInt(env.KV_TIMESTAMP_TTL_SECONDS || (UPLOAD_INTERVAL_SECONDS * 60 * 24).toString(), 10); // 例如24小时TTL
        ctx.waitUntil(kvService.updateLastUploadTimestamp(env, authenticatedUsername, currentTimeMs, kvTimestampTtl ));
        // ------------------------------
        
        // ---- 9. 记录成功日志 ----
        logEntry.status = 'success';
        ctx.waitUntil(logFileActivity(env, logEntry));
        // ----------------------

        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileUpload] User: ${authenticatedUsername} - Successfully processed upload for ${originalFilePath}`);
        }
        return jsonResponse({
            message: `File '${originalFilePath}' (as '${fileHash}') encrypted and uploaded successfully for user '${authenticatedUsername}'.`,
            // ... (其他响应字段和之前一样)
            username: authenticatedUsername,
            originalPath: originalFilePath,
            filePathInRepo: hashedFilePath,
            fileHash: fileHash,
            indexPath: `${authenticatedUsername}/index.json`
        }, 201);

    } catch (error) {
        // ... (通用错误处理和日志记录，和之前一样)
        if (env.LOGGING_ENABLED === "true") console.error(`[handleFileUpload] User: ${authenticatedUsername} - Unexpected error for ${originalFilePath}:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message.substring(0, 255)}`; // 限制错误信息长度
        ctx.waitUntil(logFileActivity(env, logEntry));
        return errorResponse(env, "An unexpected server error occurred during file upload.", 500);
    }
}

export async function handleFileDownload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能: 处理文件下载，包括认证、从索引查找、解密和日志记录。
    // (代码和之前一样)
    if (!authenticatedUsername || !originalFilePath) {
        return errorResponse(env, "Authenticated username and original file path are required for download.", 400);
    }

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleFileDownload] User: ${authenticatedUsername} - Initiating download for: ${originalFilePath}`);
    }

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";
    
    let logEntry = {
        user_id: authenticatedUsername,
        action_type: 'download',
        original_file_path: originalFilePath,
        file_hash: null,
        file_size_bytes: null,
        status: 'failure',
        error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'),
        user_agent: request.headers.get('user-agent')
    };

    try {
        const userFileEncryptionKey = await getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) {
            logEntry.error_message = "Encryption key retrieval failed.";
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDownload] User: ${authenticatedUsername} - ${logEntry.error_message}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, `Could not retrieve encryption key for user '${authenticatedUsername}'.`, 403);
        }

        const { indexData } = await getUserIndex(env, authenticatedUsername, targetBranch);
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);

        if (!indexFileExists) {
            logEntry.error_message = "User index file not found.";
            if (env.LOGGING_ENABLED === "true") console.warn(`[handleFileDownload] User: ${authenticatedUsername} - ${logEntry.error_message}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, `User '${authenticatedUsername}' or their index file not found.`, 404);
        }

        const fileHash = (indexData && indexData.files) ? indexData.files[originalFilePath] : null;
        logEntry.file_hash = fileHash;

        if (!fileHash) {
            logEntry.error_message = "File not found in user index.";
            if (env.LOGGING_ENABLED === "true") console.warn(`[handleFileDownload] User: ${authenticatedUsername} - ${logEntry.error_message} for path ${originalFilePath}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, `File '${originalFilePath}' not found in index for user '${authenticatedUsername}'.`, 404);
        }

        const hashedFilePath = `${authenticatedUsername}/${fileHash}`;
        const encryptedFileData = await githubService.getFileContentAndSha(env, owner, repo, hashedFilePath, targetBranch);

        if (!encryptedFileData || !encryptedFileData.content_base64) {
            logEntry.error_message = "Encrypted physical file not found or content empty.";
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDownload] User: ${authenticatedUsername} - ${logEntry.error_message} for hash ${fileHash}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, `Encrypted file content for '${originalFilePath}' (hash: ${fileHash}) not found. Index may be out of sync.`, 404);
        }
        
        const ivAndCiphertextBuffer = base64ToArrayBuffer(encryptedFileData.content_base64);
        if (ivAndCiphertextBuffer.byteLength < AES_GCM_IV_LENGTH_BYTES) {
            logEntry.error_message = "Encrypted file data is too short to contain IV.";
             if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDownload] User: ${authenticatedUsername} - ${logEntry.error_message}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, "Invalid encrypted file data format.", 500);
        }
        const iv = new Uint8Array(ivAndCiphertextBuffer.slice(0, AES_GCM_IV_LENGTH_BYTES));
        const ciphertext = ivAndCiphertextBuffer.slice(AES_GCM_IV_LENGTH_BYTES);

        const plainContentArrayBuffer = await decryptDataAesGcm(ciphertext, iv, userFileEncryptionKey);

        if (!plainContentArrayBuffer) {
            logEntry.error_message = "File decryption failed (key mismatch or data corruption).";
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDownload] User: ${authenticatedUsername} - ${logEntry.error_message} for ${originalFilePath}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, "File decryption failed.", 500);
        }
        
        logEntry.status = 'success';
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength;
        ctx.waitUntil(logFileActivity(env, logEntry));
        
        const downloadFilename = originalFilePath.split('/').pop() || fileHash;
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - Successfully decrypted and serving ${originalFilePath}`);
        }
        return new Response(plainContentArrayBuffer, {
            headers: {
                'Content-Type': 'application/octet-stream',
                'Content-Disposition': `attachment; filename="${encodeURIComponent(downloadFilename)}"`,
            }
        });

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDownload] User: ${authenticatedUsername} - Unexpected error for ${originalFilePath}:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message.substring(0, 255)}`;
        ctx.waitUntil(logFileActivity(env, logEntry));
        return errorResponse(env, "An unexpected server error occurred during file download.", 500);
    }
}

export async function handleFileDelete(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能: 处理文件删除，包括认证、索引更新、物理文件删除（如果无引用）和日志记录。
    // (代码和之前一样)
    if (!authenticatedUsername || !originalFilePath) {
        return errorResponse(env, "Authenticated username and original file path are required for delete.", 400);
    }
     if (originalFilePath.endsWith('/')) {
        return errorResponse(env, "Cannot delete a directory-like path. Specify a file.", 400);
    }

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleFileDelete] User: ${authenticatedUsername} - Initiating delete for: ${originalFilePath}`);
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
        error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'),
        user_agent: request.headers.get('user-agent')
    };

    try {
        const { indexData, sha: indexSha } = await getUserIndex(env, authenticatedUsername, targetBranch);
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);

        if (!indexFileExists) {
            logEntry.error_message = "User index file not found.";
            if (env.LOGGING_ENABLED === "true") console.warn(`[handleFileDelete] User: ${authenticatedUsername} - ${logEntry.error_message}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, `Index for user '${authenticatedUsername}' not found. Nothing to delete.`, 404);
        }
        
        const fileHashToDelete = (indexData && indexData.files) ? indexData.files[originalFilePath] : null;
        logEntry.file_hash = fileHashToDelete;

        if (!fileHashToDelete) {
            logEntry.error_message = "File not found in user index.";
             if (env.LOGGING_ENABLED === "true") console.warn(`[handleFileDelete] User: ${authenticatedUsername} - ${logEntry.error_message} for ${originalFilePath}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, `File '${originalFilePath}' not found in index for user '${authenticatedUsername}'.`, 404);
        }

        delete indexData.files[originalFilePath];
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDelete] User: ${authenticatedUsername} - Removed '${originalFilePath}' (hash: ${fileHashToDelete}) from local index data.`);
        }
        
        const indexCommitMessage = `Feat: Update index for ${authenticatedUsername}, remove '${originalFilePath}'`;
        const indexUpdated = await updateUserIndex(env, authenticatedUsername, indexData, indexSha, targetBranch, indexCommitMessage);
        if (!indexUpdated) {
            logEntry.error_message = "Failed to update user index on GitHub after removing entry.";
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDelete] User: ${authenticatedUsername} - ${logEntry.error_message}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, `Failed to update user index for '${originalFilePath}'. Physical file not deleted to maintain consistency.`, 500);
        }

        let isHashStillReferenced = false;
        if (indexData.files) {
            for (const key in indexData.files) {
                if (indexData.files[key] === fileHashToDelete) {
                    isHashStillReferenced = true;
                    break;
                }
            }
        }

        let physicalFileDeleteOutcomeMessage = "";
        if (!isHashStillReferenced) {
            const hashedFilePathToDelete = `${authenticatedUsername}/${fileHashToDelete}`;
            if (env.LOGGING_ENABLED === "true") {
                console.log(`[handleFileDelete] User: ${authenticatedUsername} - Hash ${fileHashToDelete} no longer referenced. Attempting to delete physical file: ${hashedFilePathToDelete}`);
            }
            const physicalFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePathToDelete, targetBranch);
            if (physicalFile && physicalFile.sha) {
                const deleteResult = await githubService.deleteGitHubFile(env, owner, repo, hashedFilePathToDelete, targetBranch, physicalFile.sha, `Chore: Delete unreferenced encrypted content ${fileHashToDelete} for ${authenticatedUsername}`);
                if (deleteResult.error) {
                    physicalFileDeleteOutcomeMessage = ` (Warning: Failed to delete physical file ${fileHashToDelete}: ${deleteResult.message})`;
                    if (env.LOGGING_ENABLED === "true") console.warn(`[handleFileDelete] User: ${authenticatedUsername} - ${physicalFileDeleteOutcomeMessage}`);
                } else {
                    physicalFileDeleteOutcomeMessage = ` (Physical file ${fileHashToDelete} also deleted)`;
                    if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDelete] User: ${authenticatedUsername} - ${physicalFileDeleteOutcomeMessage}`);
                }
            } else {
                physicalFileDeleteOutcomeMessage = ` (Physical file for hash ${fileHashToDelete} not found or already deleted)`;
                 if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDelete] User: ${authenticatedUsername} - ${physicalFileDeleteOutcomeMessage}`);
            }
        } else {
            physicalFileDeleteOutcomeMessage = ` (Physical file ${fileHashToDelete} kept as it's still referenced by other entries for user ${authenticatedUsername})`;
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDelete] User: ${authenticatedUsername} - ${physicalFileDeleteOutcomeMessage}`);
        }
        
        logEntry.status = 'success';
        ctx.waitUntil(logFileActivity(env, logEntry));

        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDelete] User: ${authenticatedUsername} - Successfully processed delete for ${originalFilePath}`);
        }
        return jsonResponse({
            message: `File '${originalFilePath}' removed from index successfully for user '${authenticatedUsername}'.${physicalFileDeleteOutcomeMessage}`
        }, 200);

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDelete] User: ${authenticatedUsername} - Unexpected error for ${originalFilePath}:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message.substring(0, 255)}`;
        ctx.waitUntil(logFileActivity(env, logEntry));
        return errorResponse(env, "An unexpected server error occurred during file deletion.", 500);
    }
}

export async function handleFileList(request, env, ctx, authenticatedUsername, originalDirectoryPath = '') {
    // 功能: 处理文件列表请求，包括认证和日志记录（可选）。
    // (代码和之前一样)
    if (!authenticatedUsername) {
        return errorResponse(env, "Authenticated username is required for listing files.", 400);
    }

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleFileList] User: ${authenticatedUsername} - Initiating list for path: '${originalDirectoryPath || "/"}'`);
    }

    const targetBranch = env.TARGET_BRANCH || "main";
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    
    let logEntry = {
        user_id: authenticatedUsername,
        action_type: 'list',
        original_file_path: originalDirectoryPath || '/', 
        status: 'failure', 
        error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'),
        user_agent: request.headers.get('user-agent')
    };

    try {
        const { indexData } = await getUserIndex(env, authenticatedUsername, targetBranch);
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);

        if (!indexFileExists) {
            if ((originalDirectoryPath === '' || originalDirectoryPath === '/')) {
                logEntry.status = 'success'; 
                if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername} - Index file does not exist. Returning empty list for root.`);
                // 对于列表操作，成功返回空列表通常不强制记录详细日志，除非审计需要
                // ctx.waitUntil(logFileActivity(env, logEntry)); 
                return jsonResponse({ path: '/', files: [] }, 200);
            }
            logEntry.error_message = "User index file not found.";
            if (env.LOGGING_ENABLED === "true") console.warn(`[handleFileList] User: ${authenticatedUsername} - ${logEntry.error_message} for path ${originalDirectoryPath}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, `User '${authenticatedUsername}' or their index file not found.`, 404);
        }
        
        const userFiles = (indexData && indexData.files) ? indexData.files : {};

        if (Object.keys(userFiles).length === 0) {
            const currentPathNormalized = (originalDirectoryPath === '' || originalDirectoryPath === '/') ? '/' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
            logEntry.status = 'success';
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername} - Index is empty. Returning empty list for path ${currentPathNormalized}`);
            // ctx.waitUntil(logFileActivity(env, logEntry));
            return jsonResponse({ path: currentPathNormalized, files: [] }, 200);
        }

        const requestedPathPrefix = originalDirectoryPath === '/' ? '' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
        const finalPrefix = (originalDirectoryPath === '' || originalDirectoryPath === '/') ? '' : requestedPathPrefix;

        const filesInDirectory = [];
        const directoriesInDirectory = new Set();

        for (const originalPath in userFiles) {
            if (originalPath.startsWith(finalPrefix)) {
                const remainingPath = originalPath.substring(finalPrefix.length);
                const parts = remainingPath.split('/');
                if (parts.length === 1 && parts[0] !== '') { 
                    filesInDirectory.push({
                        name: parts[0],
                        path: originalPath,
                        type: "file",
                        hash: userFiles[originalPath]
                    });
                } else if (parts.length > 1 && parts[0] !== '') { 
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

        logEntry.status = 'success';
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileList] User: ${authenticatedUsername} - Listed ${allEntries.length} items for path '${finalPrefix || "/"}'`);
        }
        // ctx.waitUntil(logFileActivity(env, logEntry));
        return jsonResponse({ path: finalPrefix || '/', files: allEntries }, 200);

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleFileList] User: ${authenticatedUsername} - Unexpected error for path ${originalDirectoryPath}:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message.substring(0, 255)}`;
        ctx.waitUntil(logFileActivity(env, logEntry));
        return errorResponse(env, "An unexpected server error occurred during file listing.", 500);
    }
}