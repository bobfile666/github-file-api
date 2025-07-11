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
async function getUserIndex(env, username, targetBranch) {
    // 功能：获取指定用户的 index.json 内容。
    // (此函数已在先前回答中提供，包含日志和错误处理，确保 base64ToArrayBuffer 从 crypto.js 导入)
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[getUserIndex] User: ${username} - Fetching index: ${indexPath} on branch ${targetBranch}`);
    }
    const indexFile = await githubService.getFileContentAndSha(env, owner, repo, indexPath, targetBranch);

    if (indexFile && indexFile.content_base64) {
        try {
            const decodedContent = new TextDecoder().decode(base64ToArrayBuffer(indexFile.content_base64));
            const indexData = JSON.parse(decodedContent);
            if (env.LOGGING_ENABLED === "true") {
                console.log(`[getUserIndex] User: ${username} - Index found. SHA: ${indexFile.sha}. Files count: ${Object.keys(indexData.files || {}).length}`);
            }
            return { indexData: indexData.files ? indexData : { files: {} }, sha: indexFile.sha, error: null };
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") {
                console.error(`[getUserIndex] User: ${username} - Error parsing index.json:`, e.message, "Content causing error:", indexFile.content_base64 ? indexFile.content_base64.substring(0,100) : "N/A");
            }
            const parseError = new Error(`Failed to parse index.json for user ${username}. Content might be corrupted.`);
            parseError.status = 500; 
            parseError.isServerError = true; 
            parseError.details = { originalError: e.message, contentPreview: indexFile.content_base64 ? indexFile.content_base64.substring(0,100) : "N/A" };
            // 返回错误对象而不是抛出，让调用者明确处理
            return { indexData: { files: {} }, sha: indexFile.sha, error: parseError };
        }
    }
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[getUserIndex] User: ${username} - Index file not found or content empty. Returning new index structure.`);
    }
    return { indexData: { files: {} }, sha: null, error: null };
}

async function updateUserIndex(env, username, indexData, currentSha, targetBranch, commitMessage) {
    // 功能：更新或创建用户的 index.json 文件。
    // (此函数已在先前讨论中提供并完善，确保 arrayBufferToBase64 从 crypto.js 导入)
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
    if (!success) {
        const updateError = new Error(`GitHub: Failed to update user index for ${username}. API status: ${result?.status}, message: ${result?.message}`);
        updateError.status = result?.status === 409 ? 409 : (result?.status || 500);
        updateError.isServerError = updateError.status >= 500 || updateError.status === 409; 
        updateError.details = result;
        if (env.LOGGING_ENABLED === "true") {
            console.error(`[updateUserIndex] User: ${username} - Failed to update index. Error thrown. GitHub API response:`, result);
        }
        throw updateError;
    }
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[updateUserIndex] User: ${username} - Index ${currentSha ? 'updated' : 'created'} successfully. New SHA: ${result.content?.sha}`);
    }
    return result; 
}


// --- 导出的请求处理函数 ---

export async function handleFileUpload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件上传，增加物理文件上传后的验证步骤。
    const startTime = Date.now();
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleFileUpload] User: ${authenticatedUsername} - START - Upload for: ${originalFilePath}`);
    }

    let logEntry = {
        user_id: authenticatedUsername, action_type: 'upload', original_file_path: originalFilePath,
        file_hash: null, file_size_bytes: 0, status: 'failure', duration_ms: null,
        error_message: null, source_ip: request.headers.get('cf-connecting-ip'), user_agent: request.headers.get('user-agent')
    };

    try {
        if (!authenticatedUsername || !originalFilePath) {
            logEntry.error_message = "Authenticated username and original file path are required.";
            const err = new Error(logEntry.error_message); err.status = 400; err.isClientError = true;
            throw err;
        }
        const UPLOAD_INTERVAL_SECONDS = parseInt(env.UPLOAD_INTERVAL_SECONDS || "10", 10);
        const currentTimeForRateLimit = Date.now();
        const lastUploadTimeMs = await kvService.getLastUploadTimestamp(env, authenticatedUsername);
        if (lastUploadTimeMs && (currentTimeForRateLimit - lastUploadTimeMs) < (UPLOAD_INTERVAL_SECONDS * 1000)) {
            const waitSeconds = Math.ceil(((UPLOAD_INTERVAL_SECONDS * 1000) - (currentTimeForRateLimit - lastUploadTimeMs)) / 1000);
            logEntry.error_message = `Rate limited. Wait ${waitSeconds}s.`;
            logEntry.status = 'failure_rate_limited';
            const err = new Error(logEntry.error_message); err.status = 429; err.isClientError = true;
            throw err;
        }
        const plainContentArrayBuffer = await request.arrayBuffer();
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength;
        if (plainContentArrayBuffer.byteLength === 0) {
            logEntry.error_message = "Cannot upload an empty file.";
            const err = new Error(logEntry.error_message); err.status = 400; err.isClientError = true;
            throw err;
        }
        const indexResult = await getUserIndex(env, authenticatedUsername, env.TARGET_BRANCH || "main");
        if (indexResult.error) throw indexResult.error; 
        const { indexData, sha: indexSha } = indexResult;
        if (indexData && indexData.files && indexData.files[originalFilePath]) {
            logEntry.error_message = `File with the name '${originalFilePath}' already exists.`;
            const err = new Error(logEntry.error_message); err.status = 409; err.isClientError = true;
            throw err;
        }
        const userFileEncryptionKey = await getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) { /* ... throw 403 client error ... */ }
        const encryptedData = await encryptDataAesGcm(plainContentArrayBuffer, userFileEncryptionKey);
        const ivAndCiphertextBuffer = new Uint8Array(encryptedData.iv.byteLength + encryptedData.ciphertext.byteLength);
        ivAndCiphertextBuffer.set(encryptedData.iv, 0);
        ivAndCiphertextBuffer.set(new Uint8Array(encryptedData.ciphertext), encryptedData.iv.byteLength);
        const contentToUploadBase64 = arrayBufferToBase64(ivAndCiphertextBuffer.buffer);
        const fileHash = await calculateSha256(plainContentArrayBuffer);
        logEntry.file_hash = fileHash;
        const hashedFilePath = `${authenticatedUsername}/${fileHash}`; 
        const owner = env.GITHUB_REPO_OWNER; const repo = env.GITHUB_REPO_NAME; const targetBranch = env.TARGET_BRANCH || "main";
        const fileCommitMessage = `Chore: Upload content ${fileHash} for ${authenticatedUsername} (orig: ${originalFilePath})`;

        // 5. 上传物理文件 (哈希文件) - 逻辑修正
        const existingHashedFileMeta = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePath, targetBranch);
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileUpload DEBUG] existingHashedFileMeta for ${hashedFilePath}:`, JSON.stringify(existingHashedFileMeta));
        }
        
        let physicalFileShaOnGitHub = existingHashedFileMeta?.sha; // 如果存在，则获取SHA
        let newFileCreatedOrVerifiedOnGitHub = false;

        if (existingHashedFileMeta && existingHashedFileMeta.error && existingHashedFileMeta.status !== 404) {
            // 检查物理文件是否存在时发生非404错误 (例如API限流, 权限问题)
            logEntry.error_message = `GitHub API error checking physical file ${hashedFilePath}: ${existingHashedFileMeta.error} (Status: ${existingHashedFileMeta.status})`;
            const err = new Error(logEntry.error_message); 
            err.status = existingHashedFileMeta.status || 503; 
            err.isServerError = true; 
            err.details = existingHashedFileMeta.details;
            throw err;
        }

        if (!existingHashedFileMeta || !existingHashedFileMeta.exists) { 
            // 文件不存在 (明确的404 或 getFileShaFromPath 因其他原因返回了非错误但不存在的状态)
            if (env.LOGGING_ENABLED === "true") {
                console.log(`[handleFileUpload] User: ${authenticatedUsername} - Physical hash file ${hashedFilePath} does NOT exist (exists: ${existingHashedFileMeta?.exists}). Attempting to CREATE...`);
            }
            const uploadResult = await githubService.createFileOrUpdateFile(env, owner, repo, hashedFilePath, targetBranch, contentToUploadBase64, fileCommitMessage, null);
            
            if (uploadResult.error || !uploadResult.content?.sha) {
                logEntry.error_message = `GitHub physical file UPLOAD FAILED: ${uploadResult.message || 'Unknown error during creation or SHA missing'}`;
                const err = new Error(logEntry.error_message); 
                err.status = uploadResult.status || 500; 
                err.isServerError = true; 
                err.details = uploadResult.details || uploadResult;
                throw err;
            }
            physicalFileShaOnGitHub = uploadResult.content.sha;
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileUpload] User: ${authenticatedUsername} - Physical file ${hashedFilePath} CREATED. SHA from upload: ${physicalFileShaOnGitHub}`);

            // ---- 上传后立即验证 ----
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileUpload] User: ${authenticatedUsername} - VERIFYING physical file ${hashedFilePath} after upload.`);
            const verificationCheck = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePath, targetBranch);
            if (!verificationCheck || !verificationCheck.exists || verificationCheck.sha !== physicalFileShaOnGitHub) {
                logEntry.error_message = `GitHub physical file upload VERIFICATION FAILED for ${hashedFilePath}. Expected SHA ${physicalFileShaOnGitHub}, verification result: ${JSON.stringify(verificationCheck)}`;
                const err = new Error(logEntry.error_message);
                err.status = 500; 
                err.isServerError = true;
                err.details = { verificationResult: verificationCheck, expectedSha: physicalFileShaOnGitHub };
                if (env.LOGGING_ENABLED === "true") console.error(`[handleFileUpload] ${err.message}`, err.details);
                // 考虑是否要尝试删除刚上传的"可能损坏"的文件
                // ctx.waitUntil(githubService.deleteGitHubFile(env, owner, repo, hashedFilePath, targetBranch, physicalFileShaOnGitHub, "Rollback: Delete unverified physical file upload"));
                throw err;
            }
            newFileCreatedOrVerifiedOnGitHub = true;
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileUpload] User: ${authenticatedUsername} - Physical file ${hashedFilePath} VERIFIED on GitHub post-upload.`);
            // -----------------------------------------
        } else { // 文件已存在 (existingHashedFileMeta.exists is true)
             newFileCreatedOrVerifiedOnGitHub = true; // 标记为已验证通过（因为它已存在）
            if (env.LOGGING_ENABLED === "true") {
                console.log(`[handleFileUpload] User: ${authenticatedUsername} - Physical hash file ${hashedFilePath} ALREADY EXISTS (SHA: ${physicalFileShaOnGitHub}). Assuming content is identical.`);
            }
        }
        
        // 6. 更新索引 (只有在物理文件操作成功或确认已存在后才执行)
        if (!newFileCreatedOrVerifiedOnGitHub) {
            // 这个情况理论上不应该发生，因为如果物理文件检查/创建失败，前面应该已经抛出错误了
            logEntry.error_message = "Internal logic error: Physical file was not confirmed on GitHub before attempting index update.";
            const err = new Error(logEntry.error_message); err.status = 500; err.isServerError = true;
            throw err;
        }

        if (!indexData.files) indexData.files = {};
        indexData.files[originalFilePath] = fileHash; 
        const indexCommitMessage = `Feat: Index update for ${authenticatedUsername}, add '${originalFilePath}' (hash: ${fileHash})`;
        const updatedIndexResult = await updateUserIndex(env, authenticatedUsername, indexData, indexSha, targetBranch, indexCommitMessage); 

        // 7. 成功
        logEntry.status = 'success';
        ctx.waitUntil(kvService.updateLastUploadTimestamp(env, authenticatedUsername, currentTimeForRateLimit, parseInt(env.KV_TIMESTAMP_TTL_SECONDS || "86400", 10) ));
        
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));
        if (env.LOGGING_ENABLED === "true") {
            const actionTakenMsg = newFileCreatedOrVerifiedOnGitHub && physicalFileShaOnGitHub !== existingHashedFileMeta?.sha ? "created and verified" : "already existed / verified";
            console.log(`[handleFileUpload] User: ${authenticatedUsername} - END - Success for: ${originalFilePath}. Physical file ${actionTakenMsg}. Duration: ${logEntry.duration_ms}ms. Index SHA: ${updatedIndexResult.content?.sha}`);
        }
        
        return jsonResponse({
            message: `File '${originalFilePath}' (as '${fileHash}') processed successfully for user '${authenticatedUsername}'. Physical file ${newFileCreatedOrVerifiedOnGitHub && physicalFileShaOnGitHub !== existingHashedFileMeta?.sha ? "created" : "already existed"}.`,
            username: authenticatedUsername,
            originalPath: originalFilePath, 
            filePathInRepo: hashedFilePath, 
            fileHash: fileHash,
            indexPath: `${authenticatedUsername}/index.json`,
            indexSha: updatedIndexResult.content?.sha 
        }, 201);
    } catch (error) {
        // (catch 块逻辑和之前一样，确保区分客户端/服务器错误并可能重抛)
        if (!logEntry.error_message && error.message) {
            logEntry.error_message = error.message.substring(0,255);
        }
        logEntry.status = logEntry.status === 'failure_rate_limited' ? logEntry.status : 'failure';
        
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));

        if (env.LOGGING_ENABLED === "true") {
            console.error(`[handleFileUpload Catch] User: ${authenticatedUsername} - Error for '${originalFilePath}':`, 
                          error.message, 
                          error.status ? `Status: ${error.status}` : '',
                          error.details || '', 
                          error.stack);
        }
        
        const statusCode = error.status || 500;
        if (error.isServerError || statusCode >= 500) {
            throw error; 
        } else { 
            return errorResponse(env, error.message || "An error occurred during file upload.", statusCode, null, error.details);
        }
    }
}
export async function handleFileDownload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件下载，包括认证、从索引查找、解密、耗时记录、问题日志检查和记录。
    const startTime = Date.now(); 
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleFileDownload] User: ${authenticatedUsername} - START - Download for: ${originalFilePath}`);
    }
    
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";
    const problemLogFileName = "_problematic_index_entries.jsonl"; // 和维护任务中使用的文件名一致
    let responseToReturn; 
    
    let logEntry = {
        user_id: authenticatedUsername, action_type: 'download', original_file_path: originalFilePath,
        file_hash: null, file_size_bytes: null, status: 'failure', duration_ms: null, 
        error_message: null, source_ip: request.headers.get('cf-connecting-ip'), user_agent: request.headers.get('user-agent')
    };

    try {
        if (!authenticatedUsername || !originalFilePath) {
            logEntry.error_message = "Username and file path are required for download.";
            const err = new Error(logEntry.error_message); err.status = 400; err.isClientError = true;
            throw err;
        }

        // 1. 获取用户密钥
        const userFileEncryptionKey = await getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) {
            logEntry.error_message = "Encryption key retrieval failed for user.";
            const err = new Error(logEntry.error_message); err.status = 403; err.isClientError = true;
            throw err;
        }

        // 2. 获取索引并查找文件哈希
        const indexResult = await getUserIndex(env, authenticatedUsername, targetBranch);
        if (indexResult.error) { // 如果 getUserIndex 内部解析失败并返回错误对象
             const err = new Error(indexResult.error.message || "Failed to process user index.");
             err.status = indexResult.error.status || 500;
             err.isServerError = indexResult.error.isServerError !== undefined ? indexResult.error.isServerError : true;
             err.details = indexResult.error.details;
             throw err;
        }
        const { indexData } = indexResult;
        
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileCheckResult = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);
        if (!indexFileCheckResult.exists && !indexFileCheckResult.error) { // 索引文件本身明确不存在
            logEntry.error_message = "User index file not found.";
            const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true;
            throw err;
        }
        if (indexFileCheckResult.error && indexFileCheckResult.status !== 404) { // 获取索引文件元数据时出错
            logEntry.error_message = `Error accessing user index file: ${indexFileCheckResult.error}`;
            const err = new Error(logEntry.error_message); err.status = indexFileCheckResult.status || 500; err.isServerError = true;
            err.details = indexFileCheckResult.details;
            throw err;
        }
        
        const fileHash = (indexData && indexData.files) ? indexData.files[originalFilePath] : null;
        logEntry.file_hash = fileHash;
        if (!fileHash) {
            logEntry.error_message = `File '${originalFilePath}' not found in user index.`;
            const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true;
            throw err;
        }

        // 3. 下载加密的哈希文件
        const hashedFilePath = `${authenticatedUsername}/${fileHash}`;
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - Attempting to download physical file: ${hashedFilePath}`);
        }
        const encryptedFileCheckResult = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePath, targetBranch);

        if (!encryptedFileCheckResult.exists) { // 物理文件不存在
            logEntry.error_message = `Encrypted physical file (hash: ${fileHash}) not found at '${hashedFilePath}'. Index/Storage inconsistency.`;
            if (env.LOGGING_ENABLED === "true") {
                 console.warn(`[handleFileDownload] User: ${authenticatedUsername} - ${logEntry.error_message}. GitHub check result:`, encryptedFileCheckResult);
            }
            
            let problemAlreadyLoggedUserMessage = "";
            try { // 尝试读取和检查问题日志文件，这个操作本身不应阻塞主流程或因失败而中断下载失败的响应
                const problemLogs = await githubService.getProblemLogEntries(env, owner, repo, targetBranch, authenticatedUsername, problemLogFileName);
                if (problemLogs && problemLogs.some(p => p.fileHash === fileHash && p.originalPath === originalFilePath && (p.type === "BrokenIndexLink" || p.type === "BrokenIndexLinkOnDownload"))) {
                    problemAlreadyLoggedUserMessage = " This issue was previously recorded by maintenance.";
                    if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDownload] User: ${authenticatedUsername} - Broken link for ${originalFilePath} (hash ${fileHash}) was already in problem log.`);
                } else {
                    const problemEntry = {
                        timestamp: new Date().toISOString(), type: "BrokenIndexLinkOnDownload", originalPath: originalFilePath,
                        fileHash: fileHash, expectedPhysicalPath: hashedFilePath,
                        reason: `Physical file not found (404 or other error: ${encryptedFileCheckResult.error || '404'}) during download attempt.`,
                        actionTaken: "Logged issue to user's problem file."
                    };
                    ctx.waitUntil(githubService.appendToProblemLogFile(env, owner, repo, targetBranch, authenticatedUsername, problemEntry, problemLogFileName));
                    problemAlreadyLoggedUserMessage = " This issue has been logged for review.";
                    if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDownload] User: ${authenticatedUsername} - Logged new broken link for ${originalFilePath} (hash ${fileHash}) to problem log.`);
                }
            } catch (problemLogError) {
                if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDownload] User: ${authenticatedUsername} - Error accessing/updating problem log for ${originalFilePath}:`, problemLogError);
                problemAlreadyLoggedUserMessage = " Error while checking/updating issue log.";
            }
            
            const err = new Error(logEntry.error_message + problemAlreadyLoggedUserMessage); 
            err.status = 503; // Service Unavailable - 文件暂时无法提供
            err.isServerError = true; // 标记为服务器问题
            err.details = { 
                messageForUser: `File '${originalFilePath}' is currently unavailable due to a data consistency issue.${problemAlreadyLoggedUserMessage} Please try again later or contact support. (Ref: Hash ${fileHash})`,
                githubCheckResult: encryptedFileCheckResult
            };
            throw err;
        }

        // 如果 getFileShaFromPath 成功，我们仍然需要文件内容，所以再次调用 getFileContentAndSha
        const encryptedFileData = await githubService.getFileContentAndSha(env, owner, repo, hashedFilePath, targetBranch);
         if (!encryptedFileData || !encryptedFileData.content_base64) { // 再次检查，以防万一
            logEntry.error_message = `Failed to retrieve content for existing physical file (hash: ${fileHash}).`;
            const err = new Error(logEntry.error_message); err.status = 500; err.isServerError = true;
            err.details = {path: hashedFilePath, githubResponse: encryptedFileData};
            throw err;
        }

        // 4. 解密
        const ivAndCiphertextBuffer = base64ToArrayBuffer(encryptedFileData.content_base64);
        if (ivAndCiphertextBuffer.byteLength < AES_GCM_IV_LENGTH_BYTES) { /* ... throw 500 server error ... */ }
        const iv = new Uint8Array(ivAndCiphertextBuffer.slice(0, AES_GCM_IV_LENGTH_BYTES));
        const ciphertext = ivAndCiphertextBuffer.slice(AES_GCM_IV_LENGTH_BYTES);
        const plainContentArrayBuffer = await decryptDataAesGcm(ciphertext, iv, userFileEncryptionKey);
        if (!plainContentArrayBuffer) {
            logEntry.error_message = "File decryption failed (key mismatch or data corruption).";
            const err = new Error(logEntry.error_message); err.status = 500; err.isServerError = true;
            throw err;
        }
        
        logEntry.status = 'success';
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength;
        
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));
        if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDownload] User: ${authenticatedUsername} - END - Success for: ${originalFilePath}. Duration: ${logEntry.duration_ms}ms`);

        const downloadFilename = originalFilePath.split('/').pop() || fileHash;
        return new Response(plainContentArrayBuffer, {
            headers: { /* ... (Content-Type, Content-Disposition) ... */ }
        });

    } catch (error) {
        // (catch 和 finally 块的错误处理、日志记录逻辑和之前一样)
        if (!logEntry.error_message && error.message) logEntry.error_message = error.message.substring(0,255);
        logEntry.status = 'failure';
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));

        if (env.LOGGING_ENABLED === "true") {
             console.error(`[handleFileDownload Catch] User: ${authenticatedUsername} - Error for '${originalFilePath}':`, error.message, error.details || error.stack);
        }
        
        const statusCode = error.status || 500;
        // 使用 error.details.messageForUser 如果存在，否则根据错误类型决定客户端消息
        const clientErrorMessage = (error.details?.messageForUser) || 
                                   ((error.isClientError || statusCode < 500) && !error.isServerError && error.message) || 
                                   `An error occurred during file download. Please contact support if the issue persists. (Ref: ${request.headers.get('cf-ray') || 'N/A'})`;
        
        if (error.isServerError || statusCode >= 500) {
            throw error; 
        } else { 
            return errorResponse(env, clientErrorMessage, statusCode, null, error.details);
        }
    }
}
export async function handleFileDelete(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件删除，包括认证、索引更新、物理文件删除（如果无引用）、耗时记录和日志记录。
    const startTime = Date.now();
    if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDelete] User: ${authenticatedUsername} - START - Delete for: ${originalFilePath}`);
    
    let logEntry = { 
        user_id: authenticatedUsername, action_type: 'delete', original_file_path: originalFilePath,
        file_hash: null, status: 'failure', duration_ms: null, error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'), user_agent: request.headers.get('user-agent')
    };

    try {
        if (!authenticatedUsername || !originalFilePath || originalFilePath.endsWith('/')) {
            logEntry.error_message = "Username and specific file path (not directory) are required.";
            const err = new Error(logEntry.error_message); err.status = 400; err.isClientError = true;
            throw err;
        }

        const owner = env.GITHUB_REPO_OWNER; const repo = env.GITHUB_REPO_NAME; const targetBranch = env.TARGET_BRANCH || "main";

        const indexResult = await getUserIndex(env, authenticatedUsername, targetBranch);
        if (indexResult.error) throw indexResult.error;
        let { indexData, sha: indexSha } = indexResult; // Make indexData mutable if needed
        
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);
        if (!indexFileExists) {
            logEntry.error_message = "User index file not found. Nothing to delete.";
            const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true;
            throw err;
        }
        
        const fileHashToDelete = (indexData && indexData.files) ? indexData.files[originalFilePath] : null;
        logEntry.file_hash = fileHashToDelete;
        if (!fileHashToDelete) {
            logEntry.error_message = `File '${originalFilePath}' not found in user index.`;
            const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true;
            throw err;
        }

        // Create a new files object without the deleted file to avoid mutating indexData directly if it's shared
        const updatedFiles = { ... (indexData.files || {}) };
        delete updatedFiles[originalFilePath];
        const updatedIndexData = { files: updatedFiles };


        const indexCommitMessage = `Feat: Update index for ${authenticatedUsername}, remove '${originalFilePath}'`;
        // Pass the SHA of the index file being updated
        const indexUpdateResult = await updateUserIndex(env, authenticatedUsername, updatedIndexData, indexSha, targetBranch, indexCommitMessage);
        // indexSha should be the SHA of the index file we just read via getUserIndex.
        // If index.json didn't exist, indexSha would be null, and updateUserIndex would create it.

        let isHashStillReferenced = false;
        if (updatedIndexData.files) { 
            for (const key in updatedIndexData.files) {
                if (updatedIndexData.files[key] === fileHashToDelete) {
                    isHashStillReferenced = true;
                    break;
                }
            }
        }
        
        let physicalFileDeleteOutcomeMessage = `(Index entry for '${originalFilePath}' removed.)`;
        if (!isHashStillReferenced) {
            const hashedFilePathToDelete = `${authenticatedUsername}/${fileHashToDelete}`;
            const physicalFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePathToDelete, targetBranch);
            if (physicalFile && physicalFile.sha) {
                const ghDeleteResult = await githubService.deleteGitHubFile(env, owner, repo, hashedFilePathToDelete, targetBranch, physicalFile.sha, `Chore: Delete unreferenced content ${fileHashToDelete} for ${authenticatedUsername}`);
                if (ghDeleteResult.error) {
                    physicalFileDeleteOutcomeMessage += ` (Warning: Failed to delete physical file ${fileHashToDelete}: ${ghDeleteResult.message})`;
                    // This is a server-side inconsistency if the physical file deletion fails.
                    // We've already updated the index. We should log this inconsistency.
                    const delErr = new Error(`Physical file ${fileHashToDelete} deletion failed after index update: ${ghDeleteResult.message}`);
                    delErr.isServerError = true; delErr.status = 500; delErr.details = ghDeleteResult;
                    // We won't throw here to let the primary operation (index update) be reported as success,
                    // but the error will be in the message and should be monitored.
                    // A more robust system might try to revert the index change or queue for retry.
                    if (env.LOGGING_ENABLED === "true") console.warn(delErr.message, delErr.details);
                    logEntry.error_message = (logEntry.error_message ? logEntry.error_message + "; " : "") + delErr.message; // Append warning
                } else {
                    physicalFileDeleteOutcomeMessage += ` (Physical file ${fileHashToDelete} also deleted)`;
                }
            } else {
                physicalFileDeleteOutcomeMessage += ` (Physical file for hash ${fileHashToDelete} not found or already deleted)`;
            }
        } else {
            physicalFileDeleteOutcomeMessage += ` (Physical file ${fileHashToDelete} kept as it's still referenced)`;
        }
        
        logEntry.status = 'success'; // Primary operation (index update) was successful
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));
        if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDelete] User: ${authenticatedUsername} - END - Success for: ${originalFilePath}. Duration: ${logEntry.duration_ms}ms`);
        
        return jsonResponse({ message: `File '${originalFilePath}' processed for deletion. ${physicalFileDeleteOutcomeMessage}`.trim() }, 200);

    } catch (error) {
        if (!logEntry.error_message && error.message) logEntry.error_message = error.message.substring(0,255);
        logEntry.status = 'failure';
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));

        if (env.LOGGING_ENABLED === "true") {
            console.error(`[handleFileDelete Catch] User: ${authenticatedUsername} - Error for '${originalFilePath}':`, error.message, error.details || error.stack);
        }
        
        const statusCode = error.status || 500;
        if (error.isServerError || statusCode >= 500) {
            throw error;
        } else { // Client error
            return errorResponse(env, error.message || "An error occurred during file deletion.", statusCode, null, error.details);
        }
    }
}

export async function handleFileList(request, env, ctx, authenticatedUsername, originalDirectoryPath = '') {
    // 功能：处理文件列表请求，包括认证、耗时记录和日志记录。
    const startTime = Date.now();
    if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername} - START - List for path: '${originalDirectoryPath || "/"}'`);
    
    let logEntry = { 
        user_id: authenticatedUsername, action_type: 'list', original_file_path: originalDirectoryPath || '/', 
        status: 'failure', duration_ms: null, error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'), user_agent: request.headers.get('user-agent')
    };
    
    try {
        if (!authenticatedUsername && authenticatedUsername !== "") { // Allow "" for a global list if ever needed, but typical use requires username
            logEntry.error_message = "Authenticated username is required.";
            const err = new Error(logEntry.error_message); err.status = 400; err.isClientError = true;
            throw err;
        }

        const owner = env.GITHUB_REPO_OWNER; const repo = env.GITHUB_REPO_NAME; const targetBranch = env.TARGET_BRANCH || "main";

        const indexResult = await getUserIndex(env, authenticatedUsername, targetBranch);
        if (indexResult.error) throw indexResult.error;
        const { indexData } = indexResult;
        
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);

        if (!indexFileExists) {
            if ((originalDirectoryPath === '' || originalDirectoryPath === '/')) {
                logEntry.status = 'success'; 
                logEntry.duration_ms = Date.now() - startTime;
                ctx.waitUntil(logFileActivity(env, logEntry));
                return jsonResponse({ path: '/', files: [] }, 200);
            }
            logEntry.error_message = "User index file not found.";
            const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true;
            throw err;
        }
        
        const userFiles = (indexData && indexData.files) ? indexData.files : {};
        if (Object.keys(userFiles).length === 0) {
            const currentPathNormalized = (originalDirectoryPath === '' || originalDirectoryPath === '/') ? '/' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
            logEntry.status = 'success';
            logEntry.duration_ms = Date.now() - startTime;
            ctx.waitUntil(logFileActivity(env, logEntry));
            return jsonResponse({ path: currentPathNormalized, files: [] }, 200);
        }

        const requestedPathPrefix = (originalDirectoryPath === '/' || originalDirectoryPath === '') ? '' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
        
        const filesInDirectory = [];
        const directoriesInDirectory = new Set();

        for (const originalPath in userFiles) {
            if (originalPath.startsWith(requestedPathPrefix)) {
                const remainingPath = originalPath.substring(requestedPathPrefix.length);
                const parts = remainingPath.split('/');
                if (parts.length === 1 && parts[0] !== '') { 
                    filesInDirectory.push({ name: parts[0], path: originalPath, type: "file", hash: userFiles[originalPath] });
                } else if (parts.length > 1 && parts[0] !== '') { 
                    directoriesInDirectory.add(parts[0]);
                }
            }
        }
        const directoryEntries = Array.from(directoriesInDirectory).map(dirName => ({ name: dirName, path: requestedPathPrefix + dirName, type: "dir" }));
        const allEntries = [...directoryEntries, ...filesInDirectory];
        allEntries.sort((a,b) => { 
            if (a.type === 'dir' && b.type === 'file') return -1;
            if (a.type === 'file' && b.type === 'dir') return 1;
            return a.name.localeCompare(b.name);
        });
        
        logEntry.status = 'success';
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));
        if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername} - END - Listed ${allEntries.length} items for path '${requestedPathPrefix || "/"}'. Duration: ${logEntry.duration_ms}ms`);
        
        return jsonResponse({ path: requestedPathPrefix || '/', files: allEntries }, 200);

    } catch (error) {
        if (!logEntry.error_message && error.message) logEntry.error_message = error.message.substring(0,255);
        logEntry.status = 'failure';
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));

        if (env.LOGGING_ENABLED === "true") {
            console.error(`[handleFileList Catch] User: ${authenticatedUsername} - Error for path '${originalDirectoryPath}':`, error.message, error.details || error.stack);
        }
        
        const statusCode = error.status || 500;
        if (error.isServerError || statusCode >= 500) {
            throw error;
        } else { // Client error
            return errorResponse(env, error.message || "An error occurred during file listing.", statusCode, null, error.details);
        }
    }
}