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
 * @returns {Response}
 */
export function errorResponse(env, message, status = 500, errorCode) {
    const errorPayload = { error: { message, status } };
    if (errorCode) {
        errorPayload.error.code = errorCode;
    }

    // 只有在 LOGGING_ENABLED 为 "true" 时才记录到控制台
    if (env && env.LOGGING_ENABLED === "true") {
        console.error(`Error Response: Status=${status}, Message='${message}'${errorCode ? `, Code=${errorCode}` : ''}`);
    } else if (!env) {
        // 如果 env 没有被正确传递，也记录一个控制台错误，帮助调试
        console.error(`Error Response (env not provided): Status=${status}, Message='${message}'${errorCode ? `, Code=${errorCode}` : ''}`);
    }

    return jsonResponse(errorPayload, status);
}