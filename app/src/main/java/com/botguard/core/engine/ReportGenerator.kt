package com.botguard.core.engine

import com.botguard.core.model.Finding
import com.botguard.core.model.RiskLevel
import com.botguard.core.model.RiskScore
import com.botguard.core.model.ScanResult
import org.json.JSONArray
import org.json.JSONObject

/**
 * 报告生成器。支持纯文本和 JSON 两种格式。
 */
class ReportGenerator {

    /** 生成文本报告 */
    fun generateText(result: ScanResult): String {
        val sb = StringBuilder()
        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine("           BotGuard 僵尸网络自检报告")
        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine()
        sb.appendLine("扫描时间: ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.CHINA).format(java.util.Date(result.timestamp))}")
        sb.appendLine("扫描耗时: ${result.scanDurationMs}ms")
        sb.appendLine("运行模式: ${result.runMode}")
        sb.appendLine("扫描模块: ${result.modulesScanned}")
        sb.appendLine()
        sb.appendLine("─── 设备信息 ───")
        sb.appendLine("厂商: ${result.deviceInfo.manufacturer}")
        sb.appendLine("型号: ${result.deviceInfo.model}")
        sb.appendLine("系统: Android ${result.deviceInfo.release} (SDK ${result.deviceInfo.sdk})")
        sb.appendLine("安全补丁: ${result.deviceInfo.securityPatch}")
        sb.appendLine()
        sb.appendLine("─── 风险评分 ───")
        sb.appendLine("综合得分: ${result.riskScore.totalScore}/100 → ${result.riskScore.riskLevel.label}")
        sb.appendLine("严重: ${result.criticalCount}  高: ${result.highCount}  中: ${result.mediumCount}  低: ${result.lowCount}")
        if (result.iocHits > 0) {
            sb.appendLine("IoC 命中: ${result.iocHits}  家族: ${result.iocFamilies.joinToString(", ")}")
        }
        sb.appendLine()

        if (result.findings.isEmpty()) {
            sb.appendLine("✓ 未发现异常，设备状态良好。")
        } else {
            sb.appendLine("─── 检测发现 (${result.findings.size} 项) ───")
            for (f in result.findings) {
                val icon = when (f.riskLevel) {
                    RiskLevel.CRITICAL -> "🔴"
                    RiskLevel.HIGH -> "🟠"
                    RiskLevel.MEDIUM -> "🟡"
                    RiskLevel.LOW -> "🔵"
                    RiskLevel.SAFE -> "🟢"
                }
                sb.appendLine()
                sb.appendLine("$icon [${f.id}] ${f.title} (${f.riskLevel.label})")
                sb.appendLine("  ${f.description}")
                if (f.attAckId != null) sb.appendLine("  ATT&CK: ${f.attAckId}")
                if (f.iocHit) sb.appendLine("  ⚠ IoC 命中: ${f.iocFamily ?: "未知家族"}")
                if (f.evidence.isNotEmpty()) {
                    sb.appendLine("  证据:")
                    f.evidence.forEach { (k, v) -> sb.appendLine("    $k: $v") }
                }
                if (f.recommendedActions.isNotEmpty()) {
                    sb.appendLine("  建议:")
                    f.recommendedActions.forEach { sb.appendLine("    • $it") }
                }
            }
        }
        sb.appendLine()
        sb.appendLine("═══════════════════════════════════════════")
        sb.appendLine("本报告由 BotGuard 生成，仅供本地参考。")
        sb.appendLine("═══════════════════════════════════════════")
        return sb.toString()
    }

    /** 生成 JSON 报告 */
    fun generateJson(result: ScanResult): String {
        val json = JSONObject()
        json.put("tool", "BotGuard")
        json.put("version", "2.0.0")
        json.put("timestamp", result.timestamp)
        json.put("scan_duration_ms", result.scanDurationMs)
        json.put("run_mode", result.runMode.name)

        val dev = JSONObject()
        dev.put("manufacturer", result.deviceInfo.manufacturer)
        dev.put("model", result.deviceInfo.model)
        dev.put("brand", result.deviceInfo.brand)
        dev.put("sdk", result.deviceInfo.sdk)
        dev.put("release", result.deviceInfo.release)
        dev.put("security_patch", result.deviceInfo.securityPatch)
        json.put("device", dev)

        val score = JSONObject()
        score.put("total", result.riskScore.totalScore)
        score.put("level", result.riskScore.riskLevel.name)
        score.put("severity_weight", result.riskScore.severityWeight)
        score.put("confidence", result.riskScore.confidence)
        score.put("ioc_bonus", result.riskScore.iocBonus)
        score.put("chain_bonus", result.riskScore.chainBonus)
        json.put("risk_score", score)

        json.put("total_findings", result.totalFindings)
        json.put("critical", result.criticalCount)
        json.put("high", result.highCount)
        json.put("medium", result.mediumCount)
        json.put("low", result.lowCount)
        json.put("ioc_hits", result.iocHits)

        val findingsArr = JSONArray()
        for (f in result.findings) {
            val fObj = JSONObject()
            fObj.put("id", f.id)
            fObj.put("module", f.moduleId)
            fObj.put("title", f.title)
            fObj.put("description", f.description)
            fObj.put("risk_level", f.riskLevel.name)
            fObj.put("att_ack_id", f.attAckId)
            fObj.put("confidence", f.confidence)
            fObj.put("ioc_hit", f.iocHit)
            fObj.put("ioc_family", f.iocFamily)
            val evObj = JSONObject()
            f.evidence.forEach { (k, v) -> evObj.put(k, v) }
            fObj.put("evidence", evObj)
            fObj.put("recommended_actions", JSONArray(f.recommendedActions))
            findingsArr.put(fObj)
        }
        json.put("findings", findingsArr)

        return json.toString(2)
    }

    /**
     * 生成详版报告（Phase 2 情报增强）。
     * 在简版基础上增加：逐模块检测明细、ATT&CK 技术映射汇总、去重修复指南。
     * 供 ResultScreen「详细报告」视图与导出使用。
     */
    fun generateDetailed(result: ScanResult): String {
        val sb = StringBuilder()
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.CHINA)
        sb.appendLine("╔════════════════════════════════════════════════════════╗")
        sb.appendLine("           BotGuard 详细检测报告 (Detailed Report)")
        sb.appendLine("╚════════════════════════════════════════════════════════╝")
        sb.appendLine()
        sb.appendLine("扫描时间: ${fmt.format(java.util.Date(result.timestamp))}   耗时: ${result.scanDurationMs}ms")
        sb.appendLine("运行模式: ${result.runMode}   模块数: ${result.modulesScanned}")
        sb.appendLine("设备: ${result.deviceInfo.manufacturer} ${result.deviceInfo.model} (Android ${result.deviceInfo.release}, SDK ${result.deviceInfo.sdk})")
        sb.appendLine()
        sb.appendLine("─── 风险总览 ───")
        sb.appendLine("综合评分: ${result.riskScore.totalScore}/100 → ${result.riskScore.riskLevel.label}")
        sb.appendLine("严重 ${result.criticalCount} / 高 ${result.highCount} / 中 ${result.mediumCount} / 低 ${result.lowCount}")
        if (result.iocHits > 0) {
            sb.appendLine("IoC 命中: ${result.iocHits} 处，涉及家族: ${result.iocFamilies.joinToString(", ")}")
        }
        sb.appendLine("评分构成: 严重度加权=${result.riskScore.severityWeight} 情报加成=${result.riskScore.iocBonus} 链完整性加成=${result.riskScore.chainBonus} 置信度=${String.format("%.2f", result.riskScore.confidence)}")
        sb.appendLine()

        if (result.findings.isEmpty()) {
            sb.appendLine("✓ 所有检测项通过，未发现异常。")
        } else {
            // 按模块分组
            sb.appendLine("─── 逐模块检测明细 ───")
            val byModule = result.findings.groupBy { it.moduleId }.toSortedMap()
            for ((moduleId, finds) in byModule) {
                sb.appendLine()
                sb.appendLine("【${MODULE_NAMES[moduleId] ?: moduleId} ($moduleId)】 共 ${finds.size} 项")
                for (f in finds.sortedByDescending { it.riskLevel.ordinal }) {
                    sb.appendLine("  ● [${f.id}] ${f.riskLevel.label}  ${f.title}")
                    sb.appendLine("    ${f.description}")
                    if (f.attAckId != null) sb.appendLine("    ATT&CK: ${f.attAckId}")
                    if (f.iocHit) sb.appendLine("    ⚠ IoC 命中家族: ${f.iocFamily ?: "未知"}")
                    if (f.evidence.isNotEmpty()) {
                        sb.appendLine("    证据:")
                        f.evidence.forEach { (k, v) -> sb.appendLine("      - $k: $v") }
                    }
                }
            }

            // ATT&CK 技术映射汇总
            sb.appendLine()
            sb.appendLine("─── ATT&CK 技术映射汇总 ───")
            val attackMap = result.findings.mapNotNull { f -> f.attAckId?.let { it to f.riskLevel } }
                .groupBy({ it.first }, { it.second })
                .toSortedMap()
            if (attackMap.isEmpty()) {
                sb.appendLine("  (无 ATT&CK 映射)")
            } else {
                attackMap.forEach { (tech, levels) ->
                    val top = levels.maxByOrNull { it.ordinal }!!
                    sb.appendLine("  $tech  ←  ${levels.size} 项发现，最高风险: ${top.label}")
                }
            }

            // 去重修复指南
            sb.appendLine()
            sb.appendLine("─── 修复建议指南 ───")
            val actions = result.findings.flatMap { it.recommendedActions }.toSet()
            if (actions.isEmpty()) {
                sb.appendLine("  (无特定修复建议)")
            } else {
                actions.forEachIndexed { i, a -> sb.appendLine("  ${i + 1}. $a") }
            }
        }

        if (result.errors.isNotEmpty()) {
            sb.appendLine()
            sb.appendLine("─── 扫描异常 (${result.errors.size}) ───")
            result.errors.forEach { e ->
                sb.appendLine("  [${e.moduleId}] ${e.moduleName}: ${e.errorMessage}")
            }
        }

        sb.appendLine()
        sb.appendLine("════════════════════════════════════════════════════════")
        sb.appendLine("本报告由 BotGuard v2 生成，仅供本地安全参考。")
        sb.appendLine("════════════════════════════════════════════════════════")
        return sb.toString()
    }

    companion object {
        /** 模块 ID → 中文名称 */
        private val MODULE_NAMES = mapOf(
            "A2" to "应用安全",
            "A3" to "持久化与保活",
            "A5" to "行为异常",
            "A6" to "Root 与注入环境",
            "A7" to "网络审计",
        )
    }
}
