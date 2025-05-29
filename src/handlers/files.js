// src/handlers/files.js (续)
export async function handleFileDownload(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能：处理文件下载，包括认证、从索引查找、解密和日志记录。
    // 参数：request, env, ctx, authenticatedUsername, originalFilePath
    // 返回：Promise<Response>
    
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
        logEntry.file_size_bytes = plainContentArrayBuffer.byteLength; // 解密后的文件大小
        ctx.waitUntil(logFileActivity(env, logEntry));
        
        const downloadFilename = originalFilePath.split('/').pop() || fileHash; // 取原始路径的最后一部分作为文件名
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDownload] User: ${authenticatedUsername} - Successfully decrypted and serving ${originalFilePath}`);
        }
        return new Response(plainContentArrayBuffer, {
            headers: {
                'Content-Type': 'application/octet-stream', // 客户端应根据MIME类型自行处理
                'Content-Disposition': `attachment; filename="${encodeURIComponent(downloadFilename)}"`, // 确保文件名编码正确
            }
        });

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDownload] User: ${authenticatedUsername} - Unexpected error for ${originalFilePath}:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message.substring(0, 255)}`;
        ctx.waitUntil(logFileActivity(env, logEntry));
        return errorResponse(env, "An unexpected server error occurred during file download.", 500);
    }
}

// src/handlers/files.js (续)
export async function handleFileDelete(request, env, ctx, authenticatedUsername, originalFilePath) {
    // 功能: 处理文件删除，包括认证、索引更新、物理文件删除（如果无引用）和日志记录。
    // 参数: request, env, ctx, authenticatedUsername, originalFilePath
    // 返回: Promise<Response>

    if (!authenticatedUsername || !originalFilePath) {
        return errorResponse(env, "Authenticated username and original file path are required for delete.", 400);
    }
     if (originalFilePath.endsWith('/')) { // 防止删除目录的意图传递到这里
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

        // 从索引中移除条目 (在 indexData 对象上操作)
        delete indexData.files[originalFilePath];
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileDelete] User: ${authenticatedUsername} - Removed '${originalFilePath}' (hash: ${fileHashToDelete}) from local index data.`);
        }
        
        // 更新 GitHub 上的索引文件
        const indexCommitMessage = `Feat: Update index for ${authenticatedUsername}, remove '${originalFilePath}'`;
        const indexUpdated = await updateUserIndex(env, authenticatedUsername, indexData, indexSha, targetBranch, indexCommitMessage);
        if (!indexUpdated) {
            logEntry.error_message = "Failed to update user index on GitHub after removing entry.";
            if (env.LOGGING_ENABLED === "true") console.error(`[handleFileDelete] User: ${authenticatedUsername} - ${logEntry.error_message}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            // 索引更新失败，不继续删除物理文件，因为状态不一致
            return errorResponse(env, `Failed to update user index for '${originalFilePath}'. Physical file not deleted to maintain consistency.`, 500);
        }

        // 检查该哈希是否仍被其他原始文件名引用 (在更新后的 indexData 中检查)
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
                    if (env.LOGGING_ENABLED === "true") console.warn(`[handleFileDelete] User: ${authenticatedUsername} - ${physicalFileDeleteOutcomeMessage}`);
                    // 即使物理文件删除失败，索引已经更新，可能需要管理员介入清理孤儿文件
                    // 但对于用户而言，文件已从索引中移除
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

// src/handlers/files.js (续)
export async function handleFileList(request, env, ctx, authenticatedUsername, originalDirectoryPath = '') {
    // 功能：处理文件列表请求，包括认证和日志记录（可选）。
    // 参数：request, env, ctx, authenticatedUsername, originalDirectoryPath
    // 返回：Promise<Response>

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
            // 如果索引文件根本不存在，对于根目录列表，返回空是合理的。
            if ((originalDirectoryPath === '' || originalDirectoryPath === '/')) {
                logEntry.status = 'success'; 
                // (可选) 即使是空列表也记录成功日志
                // ctx.waitUntil(logFileActivity(env, logEntry)); 
                if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername} - Index file does not exist. Returning empty list for root.`);
                return jsonResponse({ path: '/', files: [] }, 200);
            }
            logEntry.error_message = "User index file not found.";
            if (env.LOGGING_ENABLED === "true") console.warn(`[handleFileList] User: ${authenticatedUsername} - ${logEntry.error_message} for path ${originalDirectoryPath}`);
            ctx.waitUntil(logFileActivity(env, logEntry));
            return errorResponse(env, `User '${authenticatedUsername}' or their index file not found.`, 404);
        }
        
        // 确保 indexData.files 存在，即使它是空的
        const userFiles = (indexData && indexData.files) ? indexData.files : {};

        if (Object.keys(userFiles).length === 0) {
            // 索引文件存在但为空
            const currentPathNormalized = (originalDirectoryPath === '' || originalDirectoryPath === '/') ? '/' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
            logEntry.status = 'success';
            // ctx.waitUntil(logFileActivity(env, logEntry));
            if (env.LOGGING_ENABLED === "true") console.log(`[handleFileList] User: ${authenticatedUsername} - Index is empty. Returning empty list for path ${currentPathNormalized}`);
            return jsonResponse({ path: currentPathNormalized, files: [] }, 200);
        }

        const requestedPathPrefix = originalDirectoryPath === '/' ? '' : (originalDirectoryPath.endsWith('/') ? originalDirectoryPath : originalDirectoryPath + '/');
        // 如果请求根目录 ("" 或 "/"), prefix 应为空字符串以匹配所有一级条目
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
                        path: originalPath, // 完整的原始路径
                        type: "file",
                        hash: userFiles[originalPath]
                        // 未来可以考虑从 GitHub 获取文件大小和修改时间，但这会增加 API 调用
                    });
                } else if (parts.length > 1 && parts[0] !== '') { 
                    directoriesInDirectory.add(parts[0]);
                }
            }
        }
        
        const directoryEntries = Array.from(directoriesInDirectory).map(dirName => ({
            name: dirName,
            path: finalPrefix + dirName, // 目录的路径
            type: "dir"
        }));

        const allEntries = [...directoryEntries, ...filesInDirectory];
        allEntries.sort((a, b) => {
            if (a.type === 'dir' && b.type === 'file') return -1;
            if (a.type === 'file' && b.type === 'dir') return 1;
            return a.name.localeCompare(b.name);
        });

        logEntry.status = 'success';
        // (可选) 列表操作成功通常不强制记录日志，除非有特定审计需求
        // ctx.waitUntil(logFileActivity(env, logEntry)); 
        if (env.LOGGING_ENABLED === "true") {
            console.log(`[handleFileList] User: ${authenticatedUsername} - Listed ${allEntries.length} items for path '${finalPrefix || "/"}'`);
        }
        return jsonResponse({ path: finalPrefix || '/', files: allEntries }, 200);

    } catch (error) {
        if (env.LOGGING_ENABLED === "true") console.error(`[handleFileList] User: ${authenticatedUsername} - Unexpected error for path ${originalDirectoryPath}:`, error.message, error.stack);
        logEntry.error_message = `Server error: ${error.message.substring(0, 255)}`;
        ctx.waitUntil(logFileActivity(env, logEntry));
        return errorResponse(env, "An unexpected server error occurred during file listing.", 500);
    }
}