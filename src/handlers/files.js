// src/handlers/files.js
// 描述：处理所有与文件操作相关的核心逻辑
import * as githubService from '../services/github.js';
import { jsonResponse, errorResponse } from '../utils/response.js';
import { 
    calculateSha256, 
    arrayBufferToBase64, 
    base64ToArrayBuffer,
    encryptDataAesGcm,
    decryptDataAesGcm, // decryptDataAesGcm 在此函数中未使用，但保留以保持模块完整性
    // importRawToCryptoKey, // 这个更可能在 d1Database.js 中使用
    // exportCryptoKeyToRaw,
} from '../utils/crypto.js'; 
import { getUserSymmetricKey } from '../services/d1Database.js'; // 导入获取用户密钥的函数
import * as kvService from '../services/kvStore.js'; // 引入 KV 服务
import { logUploadActivity } from '../services/d1Database.js'; // 引入日志服务

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
    // 功能：获取指定用户的 index.json 内容
    // 参数：env, username, targetBranch
    // 返回：{indexData: object, sha: string|null} 或默认空索引
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
            if (env.LOGGING_ENABLED === "true") console.error(`Error parsing index.json for user ${username}:`, e.message);
            return { indexData: { files: {} }, sha: null }; 
        }
    }
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
    // 功能：更新或创建用户的 index.json 文件
    // 参数：env, username, indexData, currentSha, targetBranch, commitMessage
    // 返回：true 如果成功，false 如果失败
    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const indexPath = `${username}/index.json`;
    const contentBase64 = arrayBufferToBase64(new TextEncoder().encode(JSON.stringify(indexData, null, 2)));

    const result = await githubService.createFileOrUpdateFile(env, owner, repo, indexPath, targetBranch, contentBase64, commitMessage, currentSha);
    // 确保 result.error 不存在，且状态码是成功创建或更新
    return result && !result.error && (result.status === 200 || result.status === 201);
}


export async function handleFileUpload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件上传，包括速率限制、加密、GitHub 存储、索引更新、KV 时间戳更新和日志记录。
    // 参数：request, env, ctx, authenticatedUsername (来自令牌), originalFilePath (来自 URL)
    // 返回：Response 对象
    
    if (!authenticatedUsername || !originalFilePath) {
        return errorResponse(env, "Authenticated username and original file path are required.", 400);
    }

    // ---- 1. 执行速率限制检查 ----
    const UPLOAD_INTERVAL_SECONDS = 10;
    const currentTimeMs = Date.now();
    const lastUploadTimeMs = await kvService.getLastUploadTimestamp(env, authenticatedUsername);

    if (lastUploadTimeMs && (currentTimeMs - lastUploadTimeMs) < (UPLOAD_INTERVAL_SECONDS * 1000)) {
        const waitSeconds = Math.ceil(((UPLOAD_INTERVAL_SECONDS * 1000) - (currentTimeMs - lastUploadTimeMs)) / 1000);
        // 注意：日志记录也可以在这里添加一个“速率受限”的条目，如果需要的话
        return errorResponse(env, `Too many upload requests. Please wait ${waitSeconds} seconds.`, 429);
    }
    // -------------------------

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";
    let logEntry = { // 初始化日志条目
        user_id: authenticatedUsername,
        original_file_path: originalFilePath,
        file_hash: null, // 稍后填充
        file_size_bytes: 0, // 稍后填充
        status: 'failure', // 默认为失败
        error_message: null,
        source_ip: request.headers.get('cf-connecting-ip'),
        user_agent: request.headers.get('user-agent')
    };

    try {
        const plainContentArrayBuffer = await request.arrayBuffer();
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength;

        if (plainContentArrayBuffer.byteLength === 0) {
            logEntry.error_message = "Cannot upload an empty file.";
            ctx.waitUntil(logUploadActivity(env, logEntry)); // 记录失败日志
            return errorResponse(env, logEntry.error_message, 400);
        }

        // ---- 2. 获取用户文件加密密钥 ----
        const userFileEncryptionKey = await getUserSymmetricKey(env, authenticatedUsername);
        if (!userFileEncryptionKey) {
            logEntry.error_message = `Encryption key not found for user.`;
            ctx.waitUntil(logUploadActivity(env, logEntry));
            return errorResponse(env, `Could not retrieve encryption key for user '${authenticatedUsername}'. Setup may be incomplete.`, 403);
        }
        // ---------------------------------

        // ---- 3. 加密文件内容 ----
        let encryptedData;
        try {
            encryptedData = await encryptDataAesGcm(plainContentArrayBuffer, userFileEncryptionKey);
        } catch (e) {
            if (env.LOGGING_ENABLED === "true") console.error(`Encryption failed for user ${authenticatedUsername}, file ${originalFilePath}:`, e.message);
            logEntry.error_message = "File encryption failed.";
            ctx.waitUntil(logUploadActivity(env, logEntry));
            return errorResponse(env, logEntry.error_message, 500);
        }
        const ivAndCiphertextBuffer = new Uint8Array(encryptedData.iv.byteLength + encryptedData.ciphertext.byteLength);
        ivAndCiphertextBuffer.set(encryptedData.iv, 0);
        ivAndCiphertextBuffer.set(new Uint8Array(encryptedData.ciphertext), encryptedData.iv.byteLength);
        const contentToUploadBase64 = arrayBufferToBase64(ivAndCiphertextBuffer.buffer);
        // ---------------------------

        // ---- 4. 计算原始文件内容的哈希 (用于索引和文件名) ----
        const fileHash = await calculateSha256(plainContentArrayBuffer);
        logEntry.file_hash = fileHash; // 更新日志条目
        const hashedFilePath = `${authenticatedUsername}/${fileHash}`; 

        if (env.LOGGING_ENABLED === "true") {
            console.log(`User '${authenticatedUsername}', Uploading (encrypted): original='${originalFilePath}', hash='${fileHash}', targetPath='${hashedFilePath}'`);
        }

        // ---- 5. 获取当前用户索引和其 SHA ----
        const { indexData, sha: indexSha } = await getUserIndex(env, authenticatedUsername, targetBranch);

        // ---- 6. 上传已加密的物理文件到 GitHub ----
        const fileCommitMessage = `Chore: Upload encrypted content ${fileHash} for user ${authenticatedUsername} (file: ${originalFilePath})`;
        const existingHashedFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePath, targetBranch);
        
        if (!existingHashedFile) { // 如果哈希文件不存在，则创建
            const uploadResult = await githubService.createFileOrUpdateFile(env, owner, repo, hashedFilePath, targetBranch, contentToUploadBase64, fileCommitMessage, null);
            if (uploadResult.error) {
                logEntry.error_message = `GitHub: Failed to upload encrypted file ${hashedFilePath}: ${uploadResult.message}`;
                ctx.waitUntil(logUploadActivity(env, logEntry));
                return errorResponse(env, logEntry.error_message, uploadResult.status || 500);
            }
            if (env.LOGGING_ENABLED === "true") console.log(`Encrypted file ${hashedFilePath} created.`);
        } else {
            if (env.LOGGING_ENABLED === "true") console.log(`Encrypted file for hash ${fileHash} already exists. Skipping physical upload.`);
            // 注意：如果允许不同原始文件指向相同内容（相同哈希），这里是正确的。
            // 如果每个原始文件即使内容相同也需要独立存储（不太可能，因为文件名是哈希），逻辑会不同。
        }
        
        // ---- 7. 更新索引 ----
        indexData.files[originalFilePath] = fileHash; 
        const indexCommitMessage = `Feat: Update index for ${authenticatedUsername}, maps '${originalFilePath}' to '${fileHash}'`;
        const indexUpdated = await updateUserIndex(env, authenticatedUsername, indexData, indexSha, targetBranch, indexCommitMessage);

        if (!indexUpdated) {
            logEntry.error_message = "GitHub: Failed to update user index after file upload.";
            // 物理文件可能已上传，这是一个需要关注的不一致状态
            if (env.LOGGING_ENABLED === "true") console.error(logEntry.error_message + ` Physical file ${hashedFilePath} might be orphaned.`);
            ctx.waitUntil(logUploadActivity(env, logEntry));
            return errorResponse(env, "Encrypted file content possibly uploaded, but failed to update user index.", 500);
        }

        // ---- 8. 所有操作成功，更新KV中的速率限制时间戳 ----
        ctx.waitUntil(kvService.updateLastUploadTimestamp(env, authenticatedUsername, currentTimeMs, UPLOAD_INTERVAL_SECONDS * 60 * 24 )); // TTL 24 hours for example
        
        // ---- 9. 记录成功日志 ----
        logEntry.status = 'success';
        ctx.waitUntil(logUploadActivity(env, logEntry));

        return jsonResponse({
            message: `File '${originalFilePath}' (as '${fileHash}') encrypted and processed successfully for user '${authenticatedUsername}'.`,
            username: authenticatedUsername,
            originalPath: originalFilePath,
            filePathInRepo: hashedFilePath,
            fileHash: fileHash,
            indexPath: `${authenticatedUsername}/index.json`
        }, 201); // 201 Created (或 200 OK 如果是更新索引中的现有条目，但物理文件已存在)

    } catch (error) {
        // 捕获此函数内未被明确处理的意外错误
        if (env.LOGGING_ENABLED === "true") console.error(`Unexpected error in handleFileUpload for user ${authenticatedUsername}, file ${originalFilePath}:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message}`;
        ctx.waitUntil(logUploadActivity(env, logEntry)); // 尝试记录这个意外错误
        return errorResponse(env, "An unexpected server error occurred during file upload.", 500);
    }
}

export async function handleFileDownload(request, env, ctx, username, originalFilePath) {
    if (!username || !originalFilePath) {
        return errorResponse(env, "Username and original file path are required.", 400);
    }

    const owner = env.GITHUB_REPO_OWNER;
    const repo = env.GITHUB_REPO_NAME;
    const targetBranch = env.TARGET_BRANCH || "main";

    // ---- 新增：获取用户文件加密密钥 ----
    const userFileEncryptionKey = await getUserSymmetricKey(env, username); // 来自 d1Database.js
    if (!userFileEncryptionKey) {
        return errorResponse(env, `Could not retrieve encryption key for user '${username}'.`, 403);
    }
    // ---------------------------------

    // 1. 获取用户索引
    const { indexData } = await getUserIndex(env, username, targetBranch);
     if (!indexData || Object.keys(indexData.files).length === 0 && !(await githubService.getFileShaFromPath(env, owner, repo, `${username}/index.json`, targetBranch))) {
         return errorResponse(env, `User '${username}' or their index not found.`, 404);
    }

    // 2. 从索引查找文件哈希 (这是明文内容的哈希)
    const fileHash = indexData.files[originalFilePath];
    if (!fileHash) {
        return errorResponse(env, `File '${originalFilePath}' not found in index for user '${username}'.`, 404);
    }

    // 3. 下载加密的哈希文件
    const hashedFilePath = `${username}/${fileHash}`; // 文件名是明文哈希
    const encryptedFileData = await githubService.getFileContentAndSha(env, owner, repo, hashedFilePath, targetBranch);

    if (!encryptedFileData || !encryptedFileData.content_base64) {
        return errorResponse(env, `Encrypted file content for '${originalFilePath}' (hash: ${fileHash}) not found. Index may be out of sync.`, 404);
    }
    
    // ---- 新增：解密文件内容 ----
    const ivAndCiphertextBuffer = base64ToArrayBuffer(encryptedFileData.content_base64);
    const iv = new Uint8Array(ivAndCiphertextBuffer.slice(0, 12)); // 假设 IV 长度为 12 (AES_GCM_IV_LENGTH_BYTES)
    const ciphertext = ivAndCiphertextBuffer.slice(12);

    let plainContentArrayBuffer;
    try {
        plainContentArrayBuffer = await decryptDataAesGcm(ciphertext, iv, userFileEncryptionKey);
    } catch (e) {
        console.error(`Decryption failed for user ${username}, file ${originalFilePath} (hash ${fileHash}):`, e.message);
        return errorResponse(env, "File decryption failed. Key mismatch or corrupted data.", 500);
    }

    if (!plainContentArrayBuffer) {
        return errorResponse(env, "File decryption resulted in null. Key mismatch or corrupted data.", 500);
    }
    // ---------------------------
    
    const downloadFilename = originalFilePath.split('/').pop() || fileHash;

    return new Response(plainContentArrayBuffer, { // 返回解密后的明文
        headers: {
            'Content-Type': 'application/octet-stream',
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

    const { indexData, sha: indexSha } = await getUserIndex(env, username, targetBranch);
    if (!indexData || !indexSha) {
        return errorResponse(env, `Index for user '${username}' not found. Nothing to delete.`, 404);
    }

    const fileHashToDelete = indexData.files[originalFilePath];
    if (!fileHashToDelete) {
        return errorResponse(env, `File '${originalFilePath}' not found in index for user '${username}'.`, 404);
    }

    delete indexData.files[originalFilePath];
    if (env.LOGGING_ENABLED === "true") {
        console.log(`User '${username}', Removed '${originalFilePath}' (hash: ${fileHashToDelete}) from index.`);
    }
    
    const indexCommitMessage = `Feat: Update index for ${username}, remove '${originalFilePath}'`;
    const indexUpdated = await updateUserIndex(env, username, indexData, indexSha, targetBranch, indexCommitMessage);
    if (!indexUpdated) {
        return errorResponse(env, `Failed to update user index after removing entry for '${originalFilePath}'. Physical file not deleted.`, 500);
    }

    let isHashStillReferenced = false;
    for (const key in indexData.files) {
        if (indexData.files[key] === fileHashToDelete) {
            isHashStillReferenced = true;
            break;
        }
    }

    let physicalFileDeleteMessage = "";
    if (!isHashStillReferenced) {
        const hashedFilePathToDelete = `${username}/${fileHashToDelete}`; // 文件名是明文哈希
        if (env.LOGGING_ENABLED === "true") {
            console.log(`Hash ${fileHashToDelete} no longer referenced by user ${username}. Attempting to delete physical file.`);
        }
        const physicalFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePathToDelete, targetBranch);
        if (physicalFile && physicalFile.sha) {
            const deleteResult = await githubService.deleteGitHubFile(env, owner, repo, hashedFilePathToDelete, targetBranch, physicalFile.sha, `Chore: Delete unreferenced content ${fileHashToDelete} for ${username}`);
            if (deleteResult.error) {
                physicalFileDeleteMessage = ` (Warning: Failed to delete physical file ${fileHashToDelete}: ${deleteResult.message})`;
            } else {
                physicalFileDeleteMessage = ` (Physical file ${fileHashToDelete} also deleted)`;
            }
        } else {
            physicalFileDeleteMessage = ` (Physical file for hash ${fileHashToDelete} not found or already deleted)`;
        }
    } else {
        physicalFileDeleteMessage = ` (Physical file ${fileHashToDelete} kept as it's still referenced by user ${username})`;
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
    const owner = env.GITHUB_REPO_OWNER; // Needed for checking if index file itself exists
    const repo = env.GITHUB_REPO_NAME;   // Needed for checking if index file itself exists

    const { indexData } = await getUserIndex(env, username, targetBranch);
    
    // 改进：检查索引文件本身是否存在，而不仅仅是内容是否为空
    const indexPath = `${username}/index.json`;
    const indexFileExists = await githubService.getFileShaFromPath(env, owner, repo, indexPath, targetBranch);

    if (!indexFileExists) { // 如果索引文件物理上不存在
         if (originalDirectoryPath === '' || originalDirectoryPath === '/') {
            if (env.LOGGING_ENABLED === "true") console.log(`Index file for user ${username} does not exist. Returning empty list for root.`);
            return jsonResponse({ path: '/', files: [] }, 200);
        }
        return errorResponse(env, `User '${username}' or their index file not found.`, 404);
    }
    
    // 如果索引文件存在，但内容为空（例如，indexData.files 是空的）
    if (!indexData || Object.keys(indexData.files).length === 0) {
        if (originalDirectoryPath === '' || originalDirectoryPath === '/') {
            return jsonResponse({ path: '/', files: [] }, 200);
        }
         // 如果请求特定子目录但索引为空，则目录不存在 (或者说没有文件在该目录下)
        return jsonResponse({ path: originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/', files: [] }, 200);
    }


    const requestedPathPrefix = originalDirectoryPath === '/' ? '' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
    const finalPrefix = (originalDirectoryPath === '' || originalDirectoryPath === '/') ? '' : requestedPathPrefix;

    const filesInDirectory = [];
    const directoriesInDirectory = new Set();

    for (const originalPath in indexData.files) {
        if (originalPath.startsWith(finalPrefix)) {
            const remainingPath = originalPath.substring(finalPrefix.length);
            const parts = remainingPath.split('/');
            if (parts.length === 1 && parts[0] !== '') { 
                filesInDirectory.push({
                    name: parts[0],
                    path: originalPath,
                    type: "file",
                    hash: indexData.files[originalPath]
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

    return jsonResponse({ path: finalPrefix || '/', files: allEntries }, 200);
}