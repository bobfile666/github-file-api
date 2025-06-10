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
    const owner = env.GITHUB_REPO_OWNER; const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;
    if (env.LOGGING_ENABLED === "true") console.log(`[getUserIndex] User: ${username} - Fetching: ${indexPath}@${targetBranch}`);
    const indexFile = await githubService.getFileContentAndSha(env, owner, repo, indexPath, targetBranch);
    if (indexFile && indexFile.content_base64) {
        try {
            const decodedContent = new TextDecoder().decode(base64ToArrayBuffer(indexFile.content_base64));
            const indexData = JSON.parse(decodedContent);
            if (env.LOGGING_ENABLED === "true") console.log(`[getUserIndex] User: ${username} - Index found. SHA: ${indexFile.sha}. Files: ${Object.keys(indexData.files || {}).length}`);
            return { indexData: indexData.files ? indexData : { files: {} }, sha: indexFile.sha };
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") console.error(`[getUserIndex] User: ${username} - Error parsing index.json:`, e.message);
            return { indexData: { files: {} }, sha: indexFile.sha }; 
        }
    }
    if (env.LOGGING_ENABLED === "true") console.log(`[getUserIndex] User: ${username} - Index file not found/empty.`);
    return { indexData: { files: {} }, sha: null };
}

async function updateUserIndex(env, username, indexData, currentSha, targetBranch, commitMessage) {
    const owner = env.GITHUB_REPO_OWNER; const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;
    const dataToWrite = { files: indexData.files || {} }; // 确保总是写入 files 键
    const contentBase64 = arrayBufferToBase64(new TextEncoder().encode(JSON.stringify(dataToWrite, null, 2)));
    if (env.LOGGING_ENABLED === "true") console.log(`[updateUserIndex] User: ${username} - ${currentSha ? 'Updating' : 'Creating'} index. SHA: ${currentSha || 'N/A'}.`);
    const result = await githubService.createFileOrUpdateFile(env, owner, repo, indexPath, targetBranch, contentBase64, commitMessage, currentSha);
    const success = result && !result.error && (result.status === 200 || result.status === 201);
    if (env.LOGGING_ENABLED === "true") {
        if (success) console.log(`[updateUserIndex] User: ${username} - Index ${currentSha ? 'updated' : 'created'}.`);
        else console.error(`[updateUserIndex] User: ${username} - Failed to update index. GitHub:`, result);
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
    let responseToReturn;
    let isServerError = false; // 标记是否为服务器端错误


    try {
        if (lastUploadTimeMs && (currentTimeForRateLimit - lastUploadTimeMs) < (UPLOAD_INTERVAL_SECONDS * 1000)) {
            const waitSeconds = Math.ceil(((UPLOAD_INTERVAL_SECONDS * 1000) - (currentTimeForRateLimit - lastUploadTimeMs)) / 1000);
            logEntry.error_message = `Rate limited. Wait ${waitSeconds}s.`;
            logEntry.status = 'failure_rate_limited'; // 可以用更具体的status
            responseToReturn = errorResponse(env, logEntry.error_message, 429, "RATE_LIMITED");
            throw new Error("RateLimited"); // 跳到finally进行日志记录
        }

        const plainContentArrayBuffer = await request.arrayBuffer();
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength;
        if (plainContentArrayBuffer.byteLength === 0) {
            logEntry.error_message = "Cannot upload an empty file.";
            responseToReturn = errorResponse(env, logEntry.error_message, 400, "EMPTY_FILE");
            throw new Error("EmptyFile");
        }

        const { indexData, sha: indexSha } = await getUserIndex(env, authenticatedUsername, targetBranch);
        if (indexData && indexData.files && indexData.files[originalFilePath]) {
            logEntry.error_message = `File with the name '${originalFilePath}' already exists.`;
            responseToReturn = errorResponse(env, logEntry.error_message, 409, "FILE_EXISTS");
            throw new Error("FileExists");
        }
        
        const userFileEncryptionKey = await getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) {
            logEntry.error_message = `Encryption key not found for user.`;
            isServerError = true; // 可能是服务器配置问题或D1问题
            responseToReturn = errorResponse(env, `Could not retrieve encryption key for user '${authenticatedUsername}'.`, 500, "KEY_RETRIEVAL_FAILED"); // 或403
            throw new Error("KeyRetrievalFailed");
        }
        
        let encryptedData;
        try { encryptedData = await encryptDataAesGcm(plainContentArrayBuffer, userFileEncryptionKey); } 
        catch (e) { 
            logEntry.error_message = `File encryption failed: ${e.message}`;
            isServerError = true;
            responseToReturn = errorResponse(env, "File encryption failed.", 500, "ENCRYPTION_ERROR");
            throw new Error("EncryptionError");
        }
        
        const ivAndCiphertextBuffer = new Uint8Array(encryptedData.iv.byteLength + encryptedData.ciphertext.byteLength);
        ivAndCiphertextBuffer.set(encryptedData.iv, 0);
        ivAndCiphertextBuffer.set(new Uint8Array(encryptedData.ciphertext), encryptedData.iv.byteLength);
        const contentToUploadBase64 = arrayBufferToBase64(ivAndCiphertextBuffer.buffer);
        
        const fileHash = await calculateSha256(plainContentArrayBuffer);
        logEntry.file_hash = fileHash;
        const hashedFilePath = `${authenticatedUsername}/${fileHash}`; 
        const owner = env.GITHUB_REPO_OWNER; const repo = env.GITHUB_REPO_NAME; const targetBranch = env.TARGET_BRANCH || "main";

        const fileCommitMessage = `Chore: Upload content ${fileHash} for ${authenticatedUsername} (${originalFilePath})`;
        const existingHashedFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePath, targetBranch);
        if (!existingHashedFile) { 
            const uploadResult = await githubService.createFileOrUpdateFile(env, owner, repo, hashedFilePath, targetBranch, contentToUploadBase64, fileCommitMessage, null);
            if (uploadResult.error) { 
                logEntry.error_message = `GitHub upload failed: ${uploadResult.message}`;
                isServerError = (uploadResult.status >= 500); // GitHub 5xx 错误是服务器问题
                responseToReturn = errorResponse(env, logEntry.error_message, uploadResult.status || 500, "GITHUB_UPLOAD_ERROR");
                throw new Error("GitHubUploadError");
            }
        }
        
        if (!indexData.files) indexData.files = {};
        indexData.files[originalFilePath] = fileHash; 
        const indexCommitMessage = `Feat: Update index for ${authenticatedUsername}, add '${originalFilePath}'`;
        const indexUpdated = await updateUserIndex(env, authenticatedUsername, indexData, indexSha, targetBranch, indexCommitMessage);
        if (!indexUpdated) { 
            logEntry.error_message = "GitHub index update failed.";
            isServerError = true; // 索引更新失败通常是程序或 GitHub 问题
            responseToReturn = errorResponse(env, logEntry.error_message, 500, "INDEX_UPDATE_FAILED");
            throw new Error("IndexUpdateFailed");
        }

        logEntry.status = 'success';
        responseToReturn = jsonResponse({
            message: `File '${originalFilePath}' (as '${fileHash}') encrypted and uploaded successfully for user '${authenticatedUsername}'.`,
            // ... (其他响应字段和之前一样)
            username: authenticatedUsername,
            originalPath: originalFilePath,
            filePathInRepo: hashedFilePath,
            fileHash: fileHash,
            indexPath: `${authenticatedUsername}/index.json`
        }, 201);
        const kvTimestampTtl = parseInt(env.KV_TIMESTAMP_TTL_SECONDS || "86400", 10);
        ctx.waitUntil(kvService.updateLastUploadTimestamp(env, authenticatedUsername, currentTimeForRateLimit, kvTimestampTtl ));

    } catch (errorCaught) {
        // 如果 responseToReturn 未设置，说明是意外 JS 错误
        if (!responseToReturn) {
            isServerError = true; // 意外错误视为服务器错误
            logEntry.error_message = `Unexpected server error: ${errorCaught.message ? errorCaught.message.substring(0,200) : 'Unknown JS error'}`;
            responseToReturn = errorResponse(env, "An unexpected server error occurred during upload.", 500, "UNEXPECTED_UPLOAD_ERROR");
            if (env.LOGGING_ENABLED === "true") console.error(`[FileUpload Catch] User: ${authenticatedUsername}, Path: ${originalFilePath}, Error:`, errorCaught);
        }
        // isServerError 标志现在决定是否推送到 GitHub
        if (isServerError) {
            const errorToLog = errorCaught instanceof Error ? errorCaught : new Error(logEntry.error_message || "Unknown upload error");
            errorToLog.rayId = request.headers.get('cf-ray');
            ctx.waitUntil(logErrorToGitHub(env, 'FileUploadServerError', errorToLog, `User: ${authenticatedUsername}, File: ${originalFilePath}`));
        }
    } finally {
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));
        if (env.LOGGING_ENABLED === "true") console.log(`[FileUpload] User: ${authenticatedUsername} - END - Path: ${originalFilePath}. Status: ${logEntry.status}. Duration: ${logEntry.duration_ms}ms`);
    }
    return responseToReturn;

export async function handleFileDownload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件下载，包括认证、从索引查找、解密、耗时记录和日志记录。
    const startTime = Date.now(); 

    if (!authenticatedUsername || !originalFilePath) {
        // 早期的参数错误，可能不方便记录完整日志，但至少返回错误
        return errorResponse(env, "Authenticated username and original file path are required for download.", 400);
    }
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleFileDownload] User: ${authenticatedUsername} - START - Download for: ${originalFilePath}`);
    }
    
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";
    let responseToReturn; // 用于存储最终要返回的响应
    
    let logEntry = {
        user_id: authenticatedUsername, 
        action_type: 'download', 
        original_file_path: originalFilePath,
        file_hash: null, 
        file_size_bytes: null, // 下载时记录解密后的大小
        status: 'failure', // 默认为失败
        duration_ms: null, 
        error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'), 
        user_agent: request.headers.get('user-agent')
    };
    let responseToReturn;
    let isServerError = false;

    try {
        // ---- 1. 获取用户文件加密密钥 ----
        const userFileEncryptionKey = await getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) {
            logEntry.error_message = "Encryption key retrieval failed for user.";
            responseToReturn = errorResponse(env, `Could not retrieve encryption key for user '${authenticatedUsername}'.`, 403);
            throw new Error(logEntry.error_message); // 进入 finally 记录日志
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - Encryption key retrieved.`);
        }

        // ---- 2. 获取用户索引 ----
        const { indexData } = await getUserIndex(env, authenticatedUsername, targetBranch);
        // 检查索引文件本身是否存在，以区分空索引和用户不存在
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);

        if (!indexFileExists) {
            logEntry.error_message = "User index file not found on GitHub.";
            responseToReturn = errorResponse(env, `User '${authenticatedUsername}' or their index file not found.`, 404);
            throw new Error(logEntry.error_message);
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - User index retrieved. Files in index: ${Object.keys(indexData.files || {}).length}`);
        }

        // ---- 3. 从索引查找文件哈希 ----
        const fileHash = (indexData && indexData.files) ? indexData.files[originalFilePath] : null;
        logEntry.file_hash = fileHash; // 更新日志条目

        if (!fileHash) {
            logEntry.error_message = `File '${originalFilePath}' not found in user index.`;
            responseToReturn = errorResponse(env, logEntry.error_message, 404);
            throw new Error(logEntry.error_message);
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - File hash for '${originalFilePath}' is '${fileHash}'.`);
        }

        // ---- 4. 下载加密的哈希文件 ----
        const hashedFilePath = `${authenticatedUsername}/${fileHash}`; // 文件名是明文哈希
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - Attempting to download physical file from GitHub: owner='${owner}', repo='${repo}', path='${hashedFilePath}', branch='${targetBranch}'`);
        }
        const encryptedFileData = await githubService.getFileContentAndSha(env, owner, repo, hashedFilePath, targetBranch);

        if (!encryptedFileData || !encryptedFileData.content_base64) {
            logEntry.error_message = `Encrypted physical file content for '${originalFilePath}' (hash: ${fileHash}) not found at '${hashedFilePath}'. Index may be out of sync.`;
            if (env.LOGGING_ENABLED === "true") {
                 console.error(`[handleFileDownload] User: ${authenticatedUsername} - ${logEntry.error_message}. GitHub response for getFileContentAndSha:`, encryptedFileData);
            }
            responseToReturn = errorResponse(env, logEntry.error_message, 404);
            throw new Error(logEntry.error_message);
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - Encrypted file data retrieved. Size: ${encryptedFileData.size} bytes.`);
        }
        
        // ---- 5. 解密文件内容 ----
        const ivAndCiphertextBuffer = base64ToArrayBuffer(encryptedFileData.content_base64);
        if (ivAndCiphertextBuffer.byteLength < AES_GCM_IV_LENGTH_BYTES) {
            logEntry.error_message = "Encrypted file data is too short to contain IV.";
            responseToReturn = errorResponse(env, "Invalid encrypted file data format.", 500);
            throw new Error(logEntry.error_message);
        }
        const iv = new Uint8Array(ivAndCiphertextBuffer.slice(0, AES_GCM_IV_LENGTH_BYTES));
        const ciphertext = ivAndCiphertextBuffer.slice(AES_GCM_IV_LENGTH_BYTES);

        const plainContentArrayBuffer = await decryptDataAesGcm(ciphertext, iv, userFileEncryptionKey);

        if (!plainContentArrayBuffer) {
            logEntry.error_message = "File decryption failed (key mismatch or data corruption).";
            responseToReturn = errorResponse(env, logEntry.error_message, 500);
            throw new Error(logEntry.error_message);
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - File decrypted successfully. Decrypted size: ${plainContentArrayBuffer.byteLength} bytes.`);
        }
        
        // ---- 所有操作成功 ----
        logEntry.status = 'success';
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength; // 解密后的文件大小
        
        const downloadFilename = originalFilePath.split('/').pop() || fileHash; // 使用原始文件名（不含路径）进行下载
        responseToReturn = new Response(plainContentArrayBuffer, {
            headers: {
                'Content-Type': 'application/octet-stream', // 通用二进制
                'Content-Disposition': `attachment; filename="${encodeURIComponent(downloadFilename)}"`,
            }
        });
        
    } catch (errorCaught) {
        // 如果 responseToReturn 尚未被设置（意味着错误发生在能生成标准错误响应之前，或者是一个意外错误）
        // 或者错误是从try块中通过 throw new Error(logEntry.error_message) 传递过来的
        if (!responseToReturn || !(responseToReturn instanceof Response)) { 
            if (env.LOGGING_ENABLED === "true") {
                console.error(`[handleFileDownload Catch] User: ${authenticatedUsername} - Error for '${originalFilePath}':`, errorCaught.message, errorCaught.stack);
            }
            // 确保 logEntry.error_message 有值
            if (!logEntry.error_message) {
                 logEntry.error_message = `Server error during download: ${errorCaught.message ? errorCaught.message.substring(0, 255) : 'Unknown error'}`;
            }
            // 根据已知错误类型决定状态码
            let statusCode = 500; // Default to 500 for unexpected errors
            if (logEntry.error_message.includes("not found in user index") || 
                logEntry.error_message.includes("User index file not found") ||
                logEntry.error_message.includes("Encrypted physical file content for") && logEntry.error_message.includes("not found")) {
                statusCode = 404;
            } else if (logEntry.error_message.includes("Encryption key retrieval failed")) {
                statusCode = 403;
            } else if (logEntry.error_message.includes("decryption failed") || logEntry.error_message.includes("Invalid encrypted file data format")) {
                statusCode = 500; // 保持500，因为这可能是服务器端问题或数据损坏
            }
            responseToReturn = errorResponse(env, logEntry.error_message, statusCode);
        }
        // 日志条目的 status 默认为 'failure'，除非在try块中被明确设为 'success'
    } finally {
        logEntry.duration_ms = Date.now() - startTime; 
        ctx.waitUntil(logFileActivity(env, logEntry)); 
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - END - Download for: ${originalFilePath}. Status: ${logEntry.status}. Duration: ${logEntry.duration_ms}ms`);
        }
    }
    return responseToReturn; 
}
export async function handleFileDelete(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能: 处理文件删除，包括认证、索引更新、物理文件删除（如果无引用）、耗时记录和日志记录。
    const startTime = Date.now();

    if (!authenticatedUsername || !originalFilePath) {
        return errorResponse(env, "Authenticated username and original file path are required for delete.", 400);
    }
     if (originalFilePath.endsWith('/')) { // 不能删除目录本身
        return errorResponse(env, "Cannot delete a directory-like path. Specify a file to delete its entry.", 400);
    }

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleFileDelete] User: ${authenticatedUsername} - START - Delete for: ${originalFilePath}`);
    }

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";
    let responseToReturn;
    
    let logEntry = {
        user_id: authenticatedUsername, 
        action_type: 'delete', 
        original_file_path: originalFilePath,
        file_hash: null, 
        status: 'failure', 
        duration_ms: null,
        error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'), 
        user_agent: request.headers.get('user-agent')
    };

    try {
        const { indexData, sha: indexSha } = await getUserIndex(env, authenticatedUsername, targetBranch);
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);

        if (!indexFileExists) {
            logEntry.error_message = "User index file not found. Nothing to delete.";
            responseToReturn = errorResponse(env, `Index for user '${authenticatedUsername}' not found. Nothing to delete.`, 404);
            throw new Error(logEntry.error_message);
        }
        
        const fileHashToDelete = (indexData && indexData.files) ? indexData.files[originalFilePath] : null;
        logEntry.file_hash = fileHashToDelete;

        if (!fileHashToDelete) {
            logEntry.error_message = `File '${originalFilePath}' not found in user index.`;
            responseToReturn = errorResponse(env, logEntry.error_message, 404);
            throw new Error(logEntry.error_message);
        }

        // 从内存中的 indexData 删除条目
        delete indexData.files[originalFilePath];
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDelete] User: ${authenticatedUsername} - Removed '${originalFilePath}' (hash: ${fileHashToDelete}) from local index data.`);
        }
        
        // 更新 GitHub 上的 index.json
        const indexCommitMessage = `Feat: Update index for ${authenticatedUsername}, remove '${originalFilePath}'`;
        const indexUpdated = await updateUserIndex(env, authenticatedUsername, indexData, indexSha, targetBranch, indexCommitMessage);
        if (!indexUpdated) {
            logEntry.error_message = "Failed to update user index on GitHub after removing entry.";
            // 重要：如果索引更新失败，不应该继续删除物理文件，以避免数据不一致
            responseToReturn = errorResponse(env, `Failed to update user index for '${originalFilePath}'. Physical file was not deleted to maintain consistency.`, 500);
            throw new Error(logEntry.error_message);
        }

        // 检查该哈希是否仍被其他原始文件名引用
        let isHashStillReferenced = false;
        if (indexData.files) { // 确保 indexData.files 存在
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
                    // 即使物理文件删除失败，索引条目已删除，操作部分成功
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
        responseToReturn = jsonResponse({
            message: `File '${originalFilePath}' removed from index successfully for user '${authenticatedUsername}'.${physicalFileDeleteOutcomeMessage}`
        }, 200);

    } catch (errorCaught) {
        if (!responseToReturn || !(responseToReturn instanceof Response)) {
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDelete Catch] User: ${authenticatedUsername} - Error for '${originalFilePath}':`, errorCaught.message, errorCaught.stack);
            if (!logEntry.error_message) {
                logEntry.error_message = `Server error during delete: ${errorCaught.message ? errorCaught.message.substring(0, 255) : 'Unknown error'}`;
            }
            let statusCode = 500;
            if (logEntry.error_message.includes("not found in user index") || logEntry.error_message.includes("User index file not found")) {
                statusCode = 404;
            }
            responseToReturn = errorResponse(env, logEntry.error_message, statusCode);
        }
    } finally {
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDelete] User: ${authenticatedUsername} - END - Delete for: ${originalFilePath}. Status: ${logEntry.status}. Duration: ${logEntry.duration_ms}ms`);
        }
    }
    return responseToReturn;
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