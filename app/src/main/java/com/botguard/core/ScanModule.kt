package com.botguard.core

import com.botguard.core.model.Finding
import com.botguard.core.model.ScanContext
import com.botguard.core.model.ScanPriority

/**
 * 检测模块接口。每个模块负责一类审计维度。
 */
interface ScanModule {
    /** 模块 ID，如 "A5" */
    val id: String
    /** 模块名称，如 "行为审计" */
    val name: String
    /** 执行优先级 */
    val priority: ScanPriority

    /**
     * 执行检测，返回所有命中的 Finding。
     * suspend 函数，由 ScannerEngine 在 Dispatchers.IO 上调度。
     * @param context 扫描上下文
     * @return 检测发现列表（空列表表示未发现异常）
     */
    suspend fun scan(context: ScanContext): List<Finding>
}
