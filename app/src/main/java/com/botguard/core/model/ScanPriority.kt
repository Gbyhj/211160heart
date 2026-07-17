package com.botguard.core.model

/**
 * 扫描模块优先级，决定执行顺序。
 */
enum class ScanPriority(val order: Int) {
    HIGHEST(0),
    HIGH(1),
    MEDIUM(2),
    LOW(3);
}
