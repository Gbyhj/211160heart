package com.botguard.core.model

/**
 * 五级风险等级，对应不同响应动作。
 */
enum class RiskLevel(val weight: Int, val label: String, val color: Long) {
    SAFE(0, "安全", 0xFF4CAF50),
    LOW(1, "低风险", 0xFFFF9800),
    MEDIUM(2, "中风险", 0xFFFF5722),
    HIGH(3, "高风险", 0xFFF44336),
    CRITICAL(4, "严重", 0xFFB71C1C);

    companion object {
        fun fromScore(score: Int): RiskLevel = when {
            score >= 80 -> CRITICAL
            score >= 60 -> HIGH
            score >= 40 -> MEDIUM
            score >= 20 -> LOW
            else -> SAFE
        }
    }
}
