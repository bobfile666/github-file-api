// src/handlers/files.js
// 描述：处理所有与文件操作相关的核心逻辑 (简化版 - 无认证、无加密)
import * as githubService from '../services/github.js';
import { jsonResponse, errorResponse } from '../utils/response.js';
import { 
    calculateSha256, 
    arrayBufferToBase64, 
    base64ToArrayBuffer,
    encryptDataAesGcm, // 新增导入
    decryptDataAesGcm, // 新增导入
    importRawToCryptoKey, // 新增导入 (用于从 D1 获取的原始密钥创建 CryptoKey)
    exportCryptoKeyToRaw, // (可能用于存储新生成的密钥)
    // MEK 相关的解密函数将通过 d1Database.js 间接使用
} from '../utils/crypto.js'; 
import { getUserSymmetricKey, DUMMY_USER_KEY_RAW } from '../services/d1Database.js'; // 引入（或将要创建的）d1Database.js 中的函数

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

    const plainContentArrayBuffer = await request.arrayBuffer(); // 这是明文内容
    if (plainContentArrayBuffer.byteLength === 0) {
        return errorResponse(env, "Cannot upload an empty file.", 400);
    }

    // ---- 新增：获取用户文件加密密钥 ----
    const userFileEncryptionKey = await getUserSymmetricKey(env, username); // 从 d1Database.js 获取
    if (!userFileEncryptionKey) {
        // 这可能意味着用户不存在，或者密钥配置有问题
        // 后续认证流程会更早处理用户不存在的情况
        return errorResponse(env, `Could not retrieve encryption key for user '${username}'. User may not exist or setup is incomplete.`, 403);
    }
    // ---------------------------------

    // ---- 新增：加密文件内容 ----
    let encryptedData;
    try {
        encryptedData = await encryptDataAesGcm(plainContentArrayBuffer, userFileEncryptionKey);
    } catch (e) {
        console.error(`Encryption failed for user ${username}, file ${originalFilePath}:`, e.message);
        return errorResponse(env, "File encryption failed.", 500);
    }
    // 将 IV 和密文合并存储，例如 IV 在前
    const ivAndCiphertextBuffer = new Uint8Array(encryptedData.iv.byteLength + encryptedData.ciphertext.byteLength);
    ivAndCiphertextBuffer.set(encryptedData.iv, 0);
    ivAndCiphertextBuffer.set(new Uint8Array(encryptedData.ciphertext), encryptedData.iv.byteLength);
    const contentToUploadBase64 = arrayBufferToBase64(ivAndCiphertextBuffer.buffer);
    // ---------------------------

    // 1. 计算原始文件内容的哈希 (用于索引和文件名)
    const fileHash = await calculateSha256(plainContentArrayBuffer); // 哈希的是明文内容
    const hashedFilePath = `${username}/${fileHash}`; 

    if (env.LOGGING_ENABLED === "true") {
        console.log(`User '${username}', Uploading (encrypted): original='${originalFilePath}', hash='${fileHash}', targetPath='${hashedFilePath}'`);
    }

    // 2. 获取当前用户索引和其 SHA
    const { indexData, sha: indexSha } = await getUserIndex(env, username, targetBranch);

    // 3. 上传已加密的物理文件
    const fileCommitMessage = `Chore: Upload encrypted content ${fileHash} for user ${username}`;
    const existingHashedFile = await githubService.getFileShaFromPath(env, owner, repo, hashedFilePath, targetBranch);
    const existingHashedFileSha = existingHashedFile ? existingHashedFile.sha : null;
    
    let physicalFileUploaded = false;
    if (!existingHashedFileSha) { // 如果哈希文件不存在 (基于明文哈希)，则上传加密内容
        const uploadResult = await githubService.createFileOrUpdateFile(env, owner, repo, hashedFilePath, targetBranch, contentToUploadBase64, fileCommitMessage, null);
        if (uploadResult.error) {
            return errorResponse(env, `Failed to upload encrypted file ${hashedFilePath}: ${uploadResult.message}`, uploadResult.status || 500);
        }
        physicalFileUploaded = true;
        if (env.LOGGING_ENABLED === "true") console.log(`Encrypted file ${hashedFilePath} created.`);
    } else {
        // 如果哈希文件已存在，意味着具有相同明文内容的文件之前已被上传。
        // 理论上，加密后的内容也应该是一样的（如果 IV 生成方式确定或 IV 也被存储）。
        // 这里我们假设如果明文哈希相同，则加密后的内容也无需重复上传。
        physicalFileUploaded = true; // 视为已存在或已处理
        if (env.LOGGING_ENABLED === "true") console.log(`Encrypted file for hash ${fileHash} likely already exists.`);
    }
    
    // 4. 更新索引 (索引中存储的是明文内容的哈希)
    indexData.files[originalFilePath] = fileHash; 
    const indexCommitMessage = `Feat: Update index for ${username}, maps '${originalFilePath}' to '${fileHash}' (encrypted)`;
    const indexUpdated = await updateUserIndex(env, username, indexData, indexSha, targetBranch, indexCommitMessage);

    if (!indexUpdated) {
        return errorResponse(env, "Encrypted file content possibly uploaded, but failed to update user index.", 500);
    }

    // TODO: 集成日志记录和速率限制更新 (将在后续步骤完成)

    return jsonResponse({
        message: `File '${originalFilePath}' (as '${fileHash}') encrypted and processed successfully for user '${username}'.`,
        username: username,
        originalPath: originalFilePath,
        filePathInRepo: hashedFilePath, // 路径是基于明文哈希的
        fileHash: fileHash, // 哈希是明文内容的哈希
        indexPath: `${username}/index.json`
    }, 201);
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