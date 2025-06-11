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
    // (代码和之前一样，确保包含日志和错误处理)
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
            return { indexData: indexData.files ? indexData : { files: {} }, sha: indexFile.sha };
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") {
                console.error(`[getUserIndex] User: ${username} - Error parsing index.json:`, e.message, "Content causing error:", indexFile.content_base64 ? indexFile.content_base64.substring(0,100) : "N/A");
            }
            // 即使解析失败，也返回 SHA，以便可以覆盖这个损坏的索引
            const parseError = new Error(`Failed to parse index.json for user ${username}. Content might be corrupted.`);
            parseError.status = 500; // 标记为服务器端问题，因为索引损坏了
            parseError.isServerError = true;
            // 抛出错误让上层处理，或者返回一个明确的错误结构
            // 为了让调用者能处理，这里我们返回一个可识别的错误或特定值
            // 或者，如果决定总是尝试修复，返回空索引和 SHA
            // throw parseError; // 或者：
            return { indexData: { files: {} }, sha: indexFile.sha, error: parseError }; // 让调用者决定如何处理
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
    
    const dataToWrite = { files: indexData.files || {} }; // 确保写入的是包含 files 属性的对象
    const contentBase64 = arrayBufferToBase64(new TextEncoder().encode(JSON.stringify(dataToWrite, null, 2)));

    if (env.LOGGING_ENABLED === "true") {
        console.log(`[updateUserIndex] User: ${username} - Attempting to ${currentSha ? 'update' : 'create'} index. SHA: ${currentSha || 'N/A'}. Commit: "${commitMessage}"`);
    }

    const result = await githubService.createFileOrUpdateFile(env, owner, repo, indexPath, targetBranch, contentBase64, commitMessage, currentSha);
    
    const success = result && !result.error && (result.status === 200 || result.status === 201);
    if (env.LOGGING_ENABLED === "true") {
        if (success) {
            console.log(`[updateUserIndex] User: ${username} - Index ${currentSha ? 'updated' : 'created'} successfully. New SHA: ${result.content?.sha}`);
        } else {
            console.error(`[updateUserIndex] User: ${username} - Failed to update index. GitHub API response:`, result);
        }
    }
    if (!success) {
        const updateError = new Error(`GitHub: Failed to update user index for ${username}. API status: ${result?.status}, message: ${result?.message}`);
        updateError.status = result?.status === 409 ? 409 : 500; // 409 conflict (e.g. bad SHA), otherwise 500
        updateError.isServerError = updateError.status >= 500 || updateError.status === 409; // 409 可能是因为并发编辑，也算程序问题
        updateError.details = result;
        throw updateError;
    }
    return result; // 返回完整结果，包含新的 SHA 等
}


// --- 导出的请求处理函数 ---

export async function handleFileDownload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件下载，包括认证、从索引查找、解密、耗时记录和日志记录。
    const startTime = Date.now(); 

    if (!authenticatedUsername || !originalFilePath) {
        // 这是一个明确的客户端请求错误，不应该上报到 GitHub 错误日志
        return errorResponse(env, "Authenticated username and original file path are required for download.", 400);
    }
    if (env.LOGGING_ENABLED === "true") {
        console.log(`[handleFileDownload] User: ${authenticatedUsername} - START - Download for: ${originalFilePath}`);
    }
    
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";
    let responseToReturn; 
    
    let logEntry = {
        user_id: authenticatedUsername, 
        action_type: 'download', 
        original_file_path: originalFilePath,
        file_hash: null, 
        file_size_bytes: null, 
        status: 'failure', 
        duration_ms: null, 
        error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'), 
        user_agent: request.headers.get('user-agent')
    };

    try {
        // 1. 获取用户文件加密密钥
        const userFileEncryptionKey = await getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) {
            logEntry.error_message = "Encryption key retrieval failed for user.";
            // 403 表示禁止访问，可能是用户配置问题或权限问题，视为客户端可处理的错误类型
            const err = new Error(logEntry.error_message); 
            err.status = 403; 
            err.isClientError = true; // 标记为客户端可预期的错误
            throw err;
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - Encryption key retrieved.`);
        }

        // 2. 获取用户索引
        const indexResult = await getUserIndex(env, authenticatedUsername, targetBranch);
        // getUserIndex 内部如果解析失败会抛出 isServerError=true 的错误
        if (indexResult.error) throw indexResult.error; 
        const { indexData } = indexResult;
        
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);
        if (!indexFileExists) {
            logEntry.error_message = "User index file not found on GitHub.";
            const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true;
            throw err;
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - User index retrieved. Files in index: ${Object.keys(indexData.files || {}).length}`);
        }

        // 3. 从索引查找文件哈希
        const fileHash = (indexData && indexData.files) ? indexData.files[originalFilePath] : null;
        logEntry.file_hash = fileHash; 

        if (!fileHash) {
            logEntry.error_message = `File '${originalFilePath}' not found in user index.`;
            const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true;
            throw err;
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - File hash for '${originalFilePath}' is '${fileHash}'.`);
        }

        // 4. 下载加密的哈希文件
        const hashedFilePath = `${authenticatedUsername}/${fileHash}`;
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - Attempting to download physical file from GitHub: owner='${owner}', repo='${repo}', path='${hashedFilePath}', branch='${targetBranch}'`);
        }
        const encryptedFileData = await githubService.getFileContentAndSha(env, owner, repo, hashedFilePath, targetBranch);

        if (!encryptedFileData || !encryptedFileData.content_base64) {
            logEntry.error_message = `Encrypted physical file (hash: ${fileHash}) not found at '${hashedFilePath}'. Index/Storage inconsistency.`;
            // 这是一个服务器端问题，因为索引指向了不存在的文件
            const err = new Error(logEntry.error_message); 
            err.status = 404; // 虽然是 404，但因为是数据不一致，标记为服务器错误
            err.isServerError = true; 
            err.details = { expectedPath: hashedFilePath, githubResponseStatus: encryptedFileData?.status };
            throw err;
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - Encrypted file data retrieved. Size: ${encryptedFileData.size} bytes.`);
        }
        
        // 5. 解密文件内容
        const ivAndCiphertextBuffer = base64ToArrayBuffer(encryptedFileData.content_base64);
        if (ivAndCiphertextBuffer.byteLength < AES_GCM_IV_LENGTH_BYTES) {
            logEntry.error_message = "Invalid encrypted file data: too short to contain IV.";
            const err = new Error(logEntry.error_message); err.status = 500; err.isServerError = true;
            err.details = { fileSize: ivAndCiphertextBuffer.byteLength, expectedMinSize: AES_GCM_IV_LENGTH_BYTES };
            throw err;
        }
        const iv = new Uint8Array(ivAndCiphertextBuffer.slice(0, AES_GCM_IV_LENGTH_BYTES));
        const ciphertext = ivAndCiphertextBuffer.slice(AES_GCM_IV_LENGTH_BYTES);

        const plainContentArrayBuffer = await decryptDataAesGcm(ciphertext, iv, userFileEncryptionKey);

        if (!plainContentArrayBuffer) {
            logEntry.error_message = "File decryption failed (key mismatch or data corruption).";
            const err = new Error(logEntry.error_message); err.status = 500; err.isServerError = true;
            throw err;
        }
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - File decrypted successfully. Decrypted size: ${plainContentArrayBuffer.byteLength} bytes.`);
        }
        
        // ---- 所有操作成功 ----
        logEntry.status = 'success';
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength; 
        
        const downloadFilename = originalFilePath.split('/').pop() || fileHash;
        responseToReturn = new Response(plainContentArrayBuffer, {
            headers: {
                'Content-Type': 'application/octet-stream', 
                'Content-Disposition': `attachment; filename="${encodeURIComponent(downloadFilename)}"`,
            }
        });
        
    } catch (error) { //捕获所有在try块中主动抛出的错误或意外错误
        // 如果 responseToReturn 已被设置（例如在try块中已知错误类型并已创建response），则不再重复创建
        if (!responseToReturn || !(responseToReturn instanceof Response)) {
            if (env.LOGGING_ENABLED === "true") {
                console.error(`[handleFileDownload Catch] User: ${authenticatedUsername} - Error for '${originalFilePath}':`, error.message, error.stack, error.details || '');
            }
            // 确保 logEntry.error_message 有值
            if (!logEntry.error_message) { // 如果是意外错误，error.message就是主要信息
                 logEntry.error_message = `Server error during download: ${error.message ? error.message.substring(0, 255) : 'Unknown error'}`;
            }
            
            // 根据错误对象上附加的 status 和 isClientError/isServerError 来决定响应
            const statusCode = error.status || 500;
            const clientErrorMessage = (error.isClientError && statusCode < 500) ? error.message : "An error occurred during file download.";
            
            responseToReturn = errorResponse(env, clientErrorMessage, statusCode, null, error.details);
        }
        
        // 决定是否将此错误上报到GitHub (通过重新抛出给index.js的顶层catch)
        // 只有当错误被认为是服务器端问题时才抛出
        if (error.isServerError || (error.status && error.status >= 500)) {
             logEntry.duration_ms = Date.now() - startTime; // 记录耗时并记录日志
             ctx.waitUntil(logFileActivity(env, logEntry));
             if (env.LOGGING_ENABLED === "true") {
                console.log(`[handleFileDownload] User: ${authenticatedUsername} - END (Error) - Download for: ${originalFilePath}. Status: ${logEntry.status}. Duration: ${logEntry.duration_ms}ms`);
             }
            throw error; // 重新抛出给全局错误处理器记录到 GitHub
        }
        // 对于客户端错误，日志已准备好，将在 finally 中记录，然后返回上面创建的 responseToReturn
    } finally {
        // 确保即使 try 块中成功并直接 return，或者 catch 块中处理后，都会记录日志
        if (!logEntry.duration_ms) { // 如果 try 块成功，duration_ms 可能还没设置
             logEntry.duration_ms = Date.now() - startTime;
        }
        // 确保 logEntry 的状态在成功时被设置
        if (responseToReturn && responseToReturn.ok && logEntry.status === 'failure') {
            logEntry.status = 'success'; // 如果成功，但前面意外标记为 failure，修正它
        }
        ctx.waitUntil(logFileActivity(env, logEntry)); 
        if (env.LOGGING_ENABLED === "true" && responseToReturn) { // 只有当 responseToReturn 已定义时才记录结束日志
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - END (Finally) - Download for: ${originalFilePath}. Status: ${logEntry.status}. Duration: ${logEntry.duration_ms}ms`);
        }
    }
    return responseToReturn; 
}


export async function handleFileDownload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件下载，包括认证、从索引查找、解密、耗时记录和日志记录。
    const startTime = Date.now();
    if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDownload] User: ${authenticatedUsername} - START - Download for: ${originalFilePath}`);

    let logEntry = { /* ... (初始化和之前一样) ... */ 
        user_id: authenticatedUsername, action_type: 'download', original_file_path: originalFilePath,
        file_hash: null, file_size_bytes: null, status: 'failure', duration_ms: null,
        error_message: null, source_ip: request.headers.get('cf-connecting-ip'), user_agent: request.headers.get('user-agent')
    };

    try {
        if (!authenticatedUsername || !originalFilePath) {
            logEntry.error_message = "Username and file path are required.";
            const err = new Error(logEntry.error_message); err.status = 400; err.isClientError = true;
            throw err;
        }

        // 1. 获取用户密钥
        const userFileEncryptionKey = await getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) {
            logEntry.error_message = "Encryption key retrieval failed.";
            const err = new Error(logEntry.error_message); err.status = 403; err.isClientError = true; // 或 500 如果认为是配置问题
            throw err;
        }

        // 2. 获取索引并查找文件哈希
        const indexResult = await getUserIndex(env, authenticatedUsername, env.TARGET_BRANCH || "main");
        if (indexResult.error) throw indexResult.error; // 来自 getUserIndex 的错误
        const { indexData } = indexResult;
        
        // 检查索引文件本身是否存在
        const owner = env.GITHUB_REPO_OWNER; const repo = env.GITHUB_REPO_NAME; const targetBranch = env.TARGET_BRANCH || "main";
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);
        if (!indexFileExists) {
            logEntry.error_message = "User index file not found.";
            const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true;
            throw err;
        }
        
        const fileHash = (indexData && indexData.files) ? indexData.files[originalFilePath] : null;
        logEntry.file_hash = fileHash;
        if (!fileHash) {
            logEntry.error_message = `File '${originalFilePath}' not found in user index.`;
            const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true;
            throw err;
        }

        // 3. 下载加密文件
        const hashedFilePath = `${authenticatedUsername}/${fileHash}`;
        const encryptedFileData = await githubService.getFileContentAndSha(env, owner, repo, hashedFilePath, targetBranch);
        if (!encryptedFileData || !encryptedFileData.content_base64) {
            logEntry.error_message = `Encrypted physical file (hash: ${fileHash}) not found. Index/Storage inconsistency.`;
            const err = new Error(logEntry.error_message); err.status = 404; err.isServerError = true; // 索引和物理文件不一致是服务器问题
            err.details = { expectedPath: hashedFilePath, githubResponse: encryptedFileData };
            throw err;
        }
        
        // 4. 解密
        const ivAndCiphertextBuffer = base64ToArrayBuffer(encryptedFileData.content_base64);
        if (ivAndCiphertextBuffer.byteLength < AES_GCM_IV_LENGTH_BYTES) { /* ... throw error ... */ logEntry.error_message = "Invalid encrypted file data (too short)."; const err = new Error(logEntry.error_message); err.status = 500; err.isServerError = true; throw err;}
        const iv = new Uint8Array(ivAndCiphertextBuffer.slice(0, AES_GCM_IV_LENGTH_BYTES));
        const ciphertext = ivAndCiphertextBuffer.slice(AES_GCM_IV_LENGTH_BYTES);
        const plainContentArrayBuffer = await decryptDataAesGcm(ciphertext, iv, userFileEncryptionKey);
        if (!plainContentArrayBuffer) {
            logEntry.error_message = "File decryption failed (key mismatch or data corruption).";
            const err = new Error(logEntry.error_message); err.status = 500; err.isServerError = true;
            throw err;
        }
        
        // 5. 成功
        logEntry.status = 'success';
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength;
        
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));
        if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDownload] User: ${authenticatedUsername} - END - Success for: ${originalFilePath}. Duration: ${logEntry.duration_ms}ms`);

        const downloadFilename = originalFilePath.split('/').pop() || fileHash;
        return new Response(plainContentArrayBuffer, {
            headers: { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${encodeURIComponent(downloadFilename)}"` }
        });

    } catch (error) {
        logEntry.error_message = logEntry.error_message || (error.message ? error.message.substring(0,255) : "Download failed due to an unknown error.");
        logEntry.status = 'failure';
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));

        if (env.LOGGING_ENABLED === "true") {
             console.error(`[handleFileDownload Catch] User: ${authenticatedUsername} - Error for '${originalFilePath}':`, error.message, error.details || error.stack);
        }
        
        const statusCode = error.status || 500;
        const clientErrorMessage = (statusCode < 500 && !error.isServerError) ? error.message : "An error occurred during file download.";
        
        if (statusCode >= 500 || error.isServerError) {
            throw error; // 重新抛出给全局错误处理器记录到 GitHub
        } else {
            return errorResponse(env, clientErrorMessage, statusCode, null, error.details);
        }
    }
}


export async function handleFileDelete(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件删除，包括认证、索引更新、物理文件删除（如果无引用）、耗时记录和日志记录。
    const startTime = Date.now();
    if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDelete] User: ${authenticatedUsername} - START - Delete for: ${originalFilePath}`);
    
    let logEntry = { /* ... (初始化) ... */ 
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

        const owner = env.GITHUB_REPO_OWNER;
        const repo = env.GITHUB_REPO_NAME;
        const targetBranch = env.TARGET_BRANCH || "main";

        // 1. 获取索引
        const indexResult = await getUserIndex(env, authenticatedUsername, targetBranch);
        if (indexResult.error) throw indexResult.error;
        const { indexData, sha: indexSha } = indexResult;
        
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);
        if (!indexFileExists) { /* ... throw 404 client error ... */ logEntry.error_message = "User index file not found."; const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true; throw err; }

        const fileHashToDelete = (indexData && indexData.files) ? indexData.files[originalFilePath] : null;
        logEntry.file_hash = fileHashToDelete;
        if (!fileHashToDelete) { /* ... throw 404 client error ... */ logEntry.error_message = `File '${originalFilePath}' not found in index.`; const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true; throw err; }

        // 2. 从内存中删除索引条目并更新 GitHub 上的 index.json
        delete indexData.files[originalFilePath];
        const indexCommitMessage = `Feat: Update index for ${authenticatedUsername}, remove '${originalFilePath}'`;
        const updateResult = await updateUserIndex(env, authenticatedUsername, indexData, indexSha, targetBranch, indexCommitMessage); // Throws on failure
        // updateUserIndex 现在返回 GitHub 的完整响应对象或抛出错误
        const newIndexSha = updateResult.content?.sha;


        // 3. 检查哈希是否仍被引用，如果否，则删除物理文件
        let isHashStillReferenced = false;
        if (indexData.files) { for (const key in indexData.files) if (indexData.files[key] === fileHashToDelete) { isHashStillReferenced = true; break; } }
        
        let physicalFileDeleteOutcomeMessage = `(Index entry for '${originalFilePath}' removed.)`;
        if (!isHashStillReferenced) {
            const hashedFilePathToDelete = `${authenticatedUsername}/${fileHashToDelete}`;
            const physicalFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePathToDelete, targetBranch);
            if (physicalFile && physicalFile.sha) {
                const ghDeleteResult = await githubService.deleteGitHubFile(env, owner, repo, hashedFilePathToDelete, targetBranch, physicalFile.sha, `Chore: Delete unreferenced content ${fileHashToDelete} for ${authenticatedUsername}`);
                if (ghDeleteResult.error) {
                    physicalFileDeleteOutcomeMessage += ` (Warning: Failed to delete physical file ${fileHashToDelete}: ${ghDeleteResult.message})`;
                    // 这可以被认为是一个服务器端问题，因为索引更新了但物理文件删除失败
                    logEntry.error_message = `Partial success: Index updated, but physical file ${fileHashToDelete} deletion failed: ${ghDeleteResult.message}`;
                    // 不立即抛出，允许主操作成功，但日志会记录此警告。
                    // 或者可以决定这是一个需要上报的服务器错误。
                } else {
                    physicalFileDeleteOutcomeMessage += ` (Physical file ${fileHashToDelete} also deleted)`;
                }
            } else {
                physicalFileDeleteOutcomeMessage += ` (Physical file for hash ${fileHashToDelete} not found or already deleted)`;
            }
        } else {
            physicalFileDeleteOutcomeMessage += ` (Physical file ${fileHashToDelete} kept as it's still referenced)`;
        }
        
        // 4. 成功
        logEntry.status = 'success';
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));
        if (env.LOGGING_ENABLED === "true") console.log(`[handleFileDelete] User: ${authenticatedUsername} - END - Success for: ${originalFilePath}. Duration: ${logEntry.duration_ms}ms`);
        
        return jsonResponse({ message: `File '${originalFilePath}' deleted successfully. ${physicalFileDeleteOutcomeMessage}`.trim() }, 200);

    } catch (error) {
        logEntry.error_message = logEntry.error_message || (error.message ? error.message.substring(0,255) : "Delete failed due to an unknown error.");
        logEntry.status = 'failure';
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));

        if (env.LOGGING_ENABLED === "true") {
            console.error(`[handleFileDelete Catch] User: ${authenticatedUsername} - Error for '${originalFilePath}':`, error.message, error.details || error.stack);
        }
        
        const statusCode = error.status || 500;
        const clientErrorMessage = (statusCode < 500 && !error.isServerError) ? error.message : "An error occurred during file deletion.";
        
        if (statusCode >= 500 || error.isServerError) {
            throw error;
        } else {
            return errorResponse(env, clientErrorMessage, statusCode, null, error.details);
        }
    }
}


export async function handleFileList(request, env, ctx, authenticatedUsername, originalDirectoryPath = '') {
    // 功能：处理文件列表请求，包括认证、耗时记录和日志记录。
    const startTime = Date.now();
    if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername} - START - List for path: '${originalDirectoryPath || "/"}'`);

    let logEntry = { /* ... (初始化) ... */ 
        user_id: authenticatedUsername, action_type: 'list', original_file_path: originalDirectoryPath || '/', 
        status: 'failure', duration_ms: null, error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'), user_agent: request.headers.get('user-agent')
    };
    
    try {
        if (!authenticatedUsername) {
            logEntry.error_message = "Authenticated username is required.";
            const err = new Error(logEntry.error_message); err.status = 400; err.isClientError = true;
            throw err;
        }

        const owner = env.GITHUB_REPO_OWNER;
        const repo = env.GITHUB_REPO_NAME;
        const targetBranch = env.TARGET_BRANCH || "main";

        // 1. 获取索引
        const indexResult = await getUserIndex(env, authenticatedUsername, targetBranch);
        if (indexResult.error) throw indexResult.error; // 来自 getUserIndex 的错误，可能是解析错误
        const { indexData } = indexResult;
        
        const indexPath = `${authenticatedUsername}/index.json`;
        const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);

        if (!indexFileExists) { // 索引文件物理上不存在
            if ((originalDirectoryPath === '' || originalDirectoryPath === '/')) {
                logEntry.status = 'success'; // 列出空用户的根目录是成功的
                logEntry.duration_ms = Date.now() - startTime;
                ctx.waitUntil(logFileActivity(env, logEntry));
                if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername} - END - Index file does not exist. Empty list for root. Duration: ${logEntry.duration_ms}ms`);
                return jsonResponse({ path: '/', files: [] }, 200);
            }
            logEntry.error_message = "User index file not found.";
            const err = new Error(logEntry.error_message); err.status = 404; err.isClientError = true;
            throw err;
        }
        
        const userFiles = (indexData && indexData.files) ? indexData.files : {};
        if (Object.keys(userFiles).length === 0) { // 索引存在但为空
            const currentPathNormalized = (originalDirectoryPath === '' || originalDirectoryPath === '/') ? '/' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
            logEntry.status = 'success';
            logEntry.duration_ms = Date.now() - startTime;
            ctx.waitUntil(logFileActivity(env, logEntry));
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername} - END - Index empty. Empty list for path ${currentPathNormalized}. Duration: ${logEntry.duration_ms}ms`);
            return jsonResponse({ path: currentPathNormalized, files: [] }, 200);
        }

        // 2. 过滤和格式化列表
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
        allEntries.sort((a,b) => { /* ... (排序逻辑和之前一样) ... */ 
            if (a.type === 'dir' && b.type === 'file') return -1;
            if (a.type === 'file' && b.type === 'dir') return 1;
            return a.name.localeCompare(b.name);
        });
        
        // 3. 成功
        logEntry.status = 'success';
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));
        if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername} - END - Listed ${allEntries.length} items for path '${requestedPathPrefix || "/"}'. Duration: ${logEntry.duration_ms}ms`);
        
        return jsonResponse({ path: requestedPathPrefix || '/', files: allEntries }, 200);

    } catch (error) {
        logEntry.error_message = logEntry.error_message || (error.message ? error.message.substring(0,255) : "List failed due to an unknown error.");
        logEntry.status = 'failure';
        logEntry.duration_ms = Date.now() - startTime;
        ctx.waitUntil(logFileActivity(env, logEntry));

        if (env.LOGGING_ENABLED === "true") {
            console.error(`[handleFileList Catch] User: ${authenticatedUsername} - Error for path '${originalDirectoryPath}':`, error.message, error.details || error.stack);
        }
        
        const statusCode = error.status || 500;
        const clientErrorMessage = (statusCode < 500 && !error.isServerError) ? error.message : "An error occurred during file listing.";
        
        if (statusCode >= 500 || error.isServerError) {
            throw error;
        } else {
            return errorResponse(env, clientErrorMessage, statusCode, null, error.details);
        }
    }
}

// 在文件顶部确保导入：
// import { AES_GCM_IV_LENGTH_BYTES, base64ToArrayBuffer, arrayBufferToBase64, calculateSha256, encryptDataAesGcm, decryptDataAesGcm } from '../utils/crypto.js';