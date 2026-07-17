package com.botguard.core.engine

import com.botguard.core.model.DeviceInfo
import com.botguard.core.model.Finding
import com.botguard.core.model.RiskLevel
import com.botguard.core.model.RiskScore
import com.botguard.core.model.RunMode
import com.botguard.core.model.ScanResult
import com.google.common.truth.Truth.assertThat
import org.json.JSONObject
import org.junit.Test

/**
 * ReportGenerator 单元测试 — 报告生成与 JSON 格式完整性。
 *
 * 覆盖：
 * - 空结果文本报告
 * - 有发现文本报告
 * - JSON 格式结构完整性
 * - JSON 字段验证
 * - IoC 命中在报告中的展示
 */
class ReportGeneratorTest {

    private val generator = ReportGenerator()

    private fun createScanResult(
        findings: List<Finding> = emptyList(),
        riskScore: RiskScore = RiskScore.calculate(findings),
    ): ScanResult {
        return ScanResult(
            findings = findings,
            riskScore = riskScore,
            deviceInfo = DeviceInfo(
                manufacturer = "TestCorp",
                model = "TestModel",
                brand = "TestBrand",
                sdk = 34,
                release = "14",
                fingerprint = "test/fingerprint",
                securityPatch = "2024-07-01",
            ),
            scanDurationMs = 1234L,
            modulesScanned = 5,
            runMode = RunMode.NO_ROOT,
        )
    }

    // ════════════════════════════════════════════════════════
    //  文本报告测试
    // ════════════════════════════════════════════════════════

    @Test
    fun `text report for empty findings contains no anomaly message`() {
        val result = createScanResult(emptyList())
        val text = generator.generateText(result)
        assertThat(text).contains("BotGuard")
        assertThat(text).contains("未发现异常")
    }

    @Test
    fun `text report includes finding titles`() {
        val findings = listOf(
            Finding(
                id = "A5-01", moduleId = "A5",
                title = "ADB 调试已开启",
                description = "测试描述",
                riskLevel = RiskLevel.LOW,
                confidence = 0.9,
                attAckId = "T1417",
            )
        )
        val result = createScanResult(findings)
        val text = generator.generateText(result)
        assertThat(text).contains("ADB 调试已开启")
        assertThat(text).contains("T1417")
    }

    @Test
    fun `text report includes IoC hit info`() {
        val findings = listOf(
            Finding(
                id = "A7-01", moduleId = "A7",
                title = "C2 连接",
                description = "检测到 C2",
                riskLevel = RiskLevel.CRITICAL,
                confidence = 0.97,
                iocHit = true,
                iocFamily = "Vo1d",
            )
        )
        val result = createScanResult(findings)
        val text = generator.generateText(result)
        assertThat(text).contains("Vo1d")
        assertThat(text).contains("IoC")
    }

    @Test
    fun `text report includes risk score`() {
        val result = createScanResult(emptyList())
        val text = generator.generateText(result)
        assertThat(text).contains("风险评分")
        assertThat(text).contains("/100")
    }

    // ════════════════════════════════════════════════════════
    //  JSON 报告测试
    // ════════════════════════════════════════════════════════

    @Test
    fun `json report has required top-level fields`() {
        val result = createScanResult(emptyList())
        val json = JSONObject(generator.generateJson(result))
        assertThat(json.has("tool")).isTrue()
        assertThat(json.has("version")).isTrue()
        assertThat(json.has("timestamp")).isTrue()
        assertThat(json.has("scan_duration_ms")).isTrue()
        assertThat(json.has("run_mode")).isTrue()
        assertThat(json.has("device")).isTrue()
        assertThat(json.has("risk_score")).isTrue()
        assertThat(json.has("findings")).isTrue()
    }

    @Test
    fun `json report tool is BotGuard`() {
        val result = createScanResult(emptyList())
        val json = JSONObject(generator.generateJson(result))
        assertThat(json.getString("tool")).isEqualTo("BotGuard")
    }

    @Test
    fun `json report includes device info`() {
        val result = createScanResult(emptyList())
        val json = JSONObject(generator.generateJson(result))
        val device = json.getJSONObject("device")
        assertThat(device.getString("manufacturer")).isEqualTo("TestCorp")
        assertThat(device.getString("model")).isEqualTo("TestModel")
        assertThat(device.getInt("sdk")).isEqualTo(34)
    }

    @Test
    fun `json report includes risk score fields`() {
        val result = createScanResult(emptyList())
        val json = JSONObject(generator.generateJson(result))
        val score = json.getJSONObject("risk_score")
        assertThat(score.has("total")).isTrue()
        assertThat(score.has("level")).isTrue()
        assertThat(score.has("severity_weight")).isTrue()
        assertThat(score.has("confidence")).isTrue()
        assertThat(score.has("ioc_bonus")).isTrue()
        assertThat(score.has("chain_bonus")).isTrue()
    }

    @Test
    fun `json report with findings includes finding details`() {
        val findings = listOf(
            Finding(
                id = "A5-01", moduleId = "A5",
                title = "Test Finding",
                description = "Test description",
                riskLevel = RiskLevel.HIGH,
                confidence = 0.85,
                attAckId = "T1417",
                iocHit = true,
                iocFamily = "Kimwolf",
                evidence = mapOf("key" to "value"),
                recommendedActions = listOf("action1", "action2"),
            )
        )
        val result = createScanResult(findings)
        val json = JSONObject(generator.generateJson(result))
        val findingsArr = json.getJSONArray("findings")
        assertThat(findingsArr.length()).isEqualTo(1)

        val f = findingsArr.getJSONObject(0)
        assertThat(f.getString("id")).isEqualTo("A5-01")
        assertThat(f.getString("module")).isEqualTo("A5")
        assertThat(f.getString("title")).isEqualTo("Test Finding")
        assertThat(f.getString("risk_level")).isEqualTo("HIGH")
        assertThat(f.getDouble("confidence")).isWithin(0.001).of(0.85)
        assertThat(f.getBoolean("ioc_hit")).isTrue()
        assertThat(f.getString("ioc_family")).isEqualTo("Kimwolf")
        assertThat(f.getString("att_ack_id")).isEqualTo("T1417")

        val evidence = f.getJSONObject("evidence")
        assertThat(evidence.getString("key")).isEqualTo("value")

        val actions = f.getJSONArray("recommended_actions")
        assertThat(actions.length()).isEqualTo(2)
        assertThat(actions.getString(0)).isEqualTo("action1")
    }

    @Test
    fun `json report with empty findings has empty array`() {
        val result = createScanResult(emptyList())
        val json = JSONObject(generator.generateJson(result))
        val findingsArr = json.getJSONArray("findings")
        assertThat(findingsArr.length()).isEqualTo(0)
    }

    @Test
    fun `json report counts match findings`() {
        val findings = listOf(
            Finding(id = "1", moduleId = "A", title = "t", description = "d",
                riskLevel = RiskLevel.CRITICAL, confidence = 0.9),
            Finding(id = "2", moduleId = "B", title = "t", description = "d",
                riskLevel = RiskLevel.HIGH, confidence = 0.9),
            Finding(id = "3", moduleId = "C", title = "t", description = "d",
                riskLevel = RiskLevel.MEDIUM, confidence = 0.9),
        )
        val result = createScanResult(findings)
        val json = JSONObject(generator.generateJson(result))
        assertThat(json.getInt("total_findings")).isEqualTo(3)
        assertThat(json.getInt("critical")).isEqualTo(1)
        assertThat(json.getInt("high")).isEqualTo(1)
        assertThat(json.getInt("medium")).isEqualTo(1)
        assertThat(json.getInt("low")).isEqualTo(0)
    }

    // ════════════════════════════════════════════════════════
    //  详版报告测试（Phase 2 情报增强）
    // ════════════════════════════════════════════════════════

    @Test
    fun `detailed report for empty findings contains no anomaly message`() {
        val result = createScanResult(emptyList())
        val text = generator.generateDetailed(result)
        assertThat(text).contains("BotGuard")
        assertThat(text).contains("未发现异常")
    }

    @Test
    fun `detailed report groups findings by module and maps ATT&CK`() {
        val findings = listOf(
            Finding(
                id = "A7-01", moduleId = "A7",
                title = "C2 连接命中",
                description = "命中 C2",
                riskLevel = RiskLevel.CRITICAL,
                confidence = 0.97,
                attAckId = "T1041",
                iocHit = true, iocFamily = "Vo1d",
            ),
            Finding(
                id = "A3-01", moduleId = "A3",
                title = "设备管理器激活",
                description = "持久化",
                riskLevel = RiskLevel.HIGH,
                confidence = 0.8,
                attAckId = "T1402",
            ),
        )
        val result = createScanResult(findings)
        val text = generator.generateDetailed(result)
        // 模块分组中文名
        assertThat(text).contains("网络审计")
        assertThat(text).contains("持久化与保活")
        // ATT&CK 汇总段
        assertThat(text).contains("ATT&CK 技术映射汇总")
        assertThat(text).contains("T1041")
        assertThat(text).contains("T1402")
        // 修复建议段
        assertThat(text).contains("修复建议指南")
    }

    @Test
    fun `detailed report includes module risk summary and errors section`() {
        val findings = listOf(
            Finding(id = "A5-01", moduleId = "A5", title = "ADB 开启",
                description = "d", riskLevel = RiskLevel.LOW, confidence = 0.9),
        )
        val result = createScanResult(findings).copy(
            errors = listOf(
                com.botguard.core.model.ModuleError("A7", "网络审计", "timeout")
            )
        )
        val text = generator.generateDetailed(result)
        assertThat(text).contains("逐模块检测明细")
        assertThat(text).contains("扫描异常")
        assertThat(text).contains("timeout")
    }
}
