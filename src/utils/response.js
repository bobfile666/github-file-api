// src/utils/response.js
// 描述：提供标准化的 JSON 响应和错误响应的辅助函数。

/**
 * 创建一个成功的 JSON 响应。
 * @param {any} data - 要包含在响应主体中的数据。
 * @param {number} [status=200] - HTTP 状态码。
 * @param {HeadersInit} [headers={}] - 自定义响应头。
 * @returns {Response}
 */
export function jsonResponse(data, status = 200, headers = {}) {
    const defaultHeaders = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*', // 基础的 CORS，生产环境可能需要更严格配置
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Commit-Message, X-API-Key', // 包含你可能用到的自定义头
    };
    return new Response(JSON.stringify(data), {
        status,
        headers: { ...defaultHeaders, ...headers },
    });
}

/**
 * 创建一个错误的 JSON 响应。
 * @param {object} env - Worker 的环境变量对象，用于检查 LOGGING_ENABLED。
 * @param {string} message - 错误消息。
 * @param {number} [status=500] - HTTP 状态码。
 * @param {string} [errorCode] - (可选) 应用特定的错误代码。
 * @param {object} [additionalDetails=null] - (可选) 附加的错误详情，不会直接在响应中暴露给用户，但可能用于日志。
 * @returns {Response}
 */
export function errorResponse(env, message, status = 500, errorCode, additionalDetails = null) {
    // 功能：创建标准化的错误 JSON 响应。
    // 参数：env, message, status, errorCode (可选), additionalDetails (可选，用于内部日志)
    // 返回：Response 对象
    const errorPayload = { error: { message, status } };
    if (errorCode) {
        errorPayload.error.code = errorCode;
    }

    // 控制台日志记录 (所有错误，无论 4xx 或 5xx，如果 LOGGING_ENABLED)
    if (env && env.LOGGING_ENABLED === "true") {
        let logMessage = `[ErrorResponse] Status=${status}, Message='${message}'${errorCode ? `, Code=${errorCode}` : ''}`;
        if (additionalDetails) {
            try {
                logMessage += `, Details: ${JSON.stringify(additionalDetails).substring(0, 300)}`; // 限制详情长度
            } catch (e) { /* ignore stringify error */ }
        }
        // 根据状态码使用不同日志级别
        if (status >= 500) {
            console.error(logMessage);
        } else if (status >= 400) {
            console.warn(logMessage);
        } else {
            console.log(logMessage); // 其他情况（不常见）
        }
    } else if (!env && status >= 400) { // 如果 env 未定义但有错误，至少记录一个警告
        console.warn(`[ErrorResponse NO ENV] Status=${status}, Message='${message}'`);
    }

    const defaultHeaders = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*', 
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Commit-Message, X-API-Key, X-Admin-API-Key',
    };
    return new Response(JSON.stringify(errorPayload), {
        status,
        headers: defaultHeaders, // 确保 CORS 头在错误响应中也存在
    });
}