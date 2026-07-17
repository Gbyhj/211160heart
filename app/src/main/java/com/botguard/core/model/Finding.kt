package com.botguard.core.model

/**
 * 单项检测结果。
 *
 * @param id              检测项 ID，如 "A5-01"
 * @param moduleId        所属模块 ID，如 "A5"
 * @param title           检测项标题
 * @param description     详细描述
 * @param riskLevel       风险等级
 * @param attAckId        MITRE ATT&CK 技术编号（注意大小写：attAckId）
 * @param confidence      置信度 0.0–1.0
 * @param evidence        支撑证据键值对
 * @param recommendedActions 建议处理动作
 * @param iocHit          是否命中 IoC 情报
 * @param iocFamily       命中的僵尸网络家族（如 "Vo1d"），未命中为 null
 */
data class Finding(
    val id: String,
    val moduleId: String,
    val title: String,
    val description: String,
    val riskLevel: RiskLevel,
    val attAckId: String? = null,
    val confidence: Double = 0.8,
    val evidence: Map<String, String> = emptyMap(),
    val recommendedActions: List<String> = emptyList(),
    val iocHit: Boolean = false,
    val iocFamily: String? = null,
)
