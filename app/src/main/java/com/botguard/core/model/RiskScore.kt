package com.botguard.core.model

/**
 * 风险评分模型。
 * 综合分 = severityWeight * 25 + confidence * 20 + urgency * 15 + iocBonus + chainBonus
 */
data class RiskScore(
    val totalScore: Int,        // 0–100
    val severityWeight: Int,    // 0–4 (RiskLevel.weight)
    val confidence: Double,     // 0.0–1.0
    val urgency: Int,           // 0–3
    val iocBonus: Int,          // IoC 命中加成
    val chainBonus: Int,        // ATT&CK 链加成
) {
    val riskLevel: RiskLevel get() = RiskLevel.fromScore(totalScore)

    companion object {
        /**
         * 从一组 Finding 计算综合风险评分。
         */
        fun calculate(findings: List<Finding>): RiskScore {
            if (findings.isEmpty()) {
                return RiskScore(0, 0, 0.0, 0, 0, 0)
            }
            val maxSeverity = findings.maxOf { it.riskLevel.weight }
            val avgConfidence = findings.map { it.confidence }.average()
            val iocHits = findings.count { it.iocHit }
            val iocBonus = if (iocHits > 0) minOf(iocHits * 8, 24) else 0
            // ATT&CK 链：命中不同模块的技术越多，链越长
            val distinctModules = findings.map { it.moduleId }.distinct().size
            val chainBonus = if (distinctModules >= 3) 15 else if (distinctModules >= 2) 8 else 0
            // 紧迫性：CRITICAL/HIGH 数量
            val urgent = findings.count { it.riskLevel.weight >= 3 }
            val urgency = minOf(urgent, 3)

            val total = minOf(
                (maxSeverity * 25) + (avgConfidence * 20).toInt() + (urgency * 15) + iocBonus + chainBonus,
                100
            )
            return RiskScore(total, maxSeverity, avgConfidence, urgency, iocBonus, chainBonus)
        }
    }
}
