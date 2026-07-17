package com.botguard.core.model

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * RiskScore 评分引擎单元测试。
 *
 * 覆盖：
 * - 空列表
 * - 全 SAFE
 * - CRITICAL 命中
 * - IoC 加分
 * - 链完整性加分
 * - 上限 100
 * - 边界值
 */
class RiskScoreTest {

    // ════════════════════════════════════════════════════════
    //  基础测试
    // ════════════════════════════════════════════════════════

    @Test
    fun `empty findings returns zero score`() {
        val score = RiskScore.calculate(emptyList())
        assertThat(score.totalScore).isEqualTo(0)
        assertThat(score.severityWeight).isEqualTo(0)
        assertThat(score.confidence).isEqualTo(0.0)
        assertThat(score.urgency).isEqualTo(0)
        assertThat(score.iocBonus).isEqualTo(0)
        assertThat(score.chainBonus).isEqualTo(0)
        assertThat(score.riskLevel).isEqualTo(RiskLevel.SAFE)
    }

    @Test
    fun `single LOW finding produces LOW risk`() {
        val findings = listOf(
            Finding(
                id = "TEST-01", moduleId = "T1",
                title = "Test", description = "Test finding",
                riskLevel = RiskLevel.LOW,
                confidence = 0.5,
            )
        )
        val score = RiskScore.calculate(findings)
        assertThat(score.severityWeight).isEqualTo(1)
        assertThat(score.iocBonus).isEqualTo(0)
        assertThat(score.chainBonus).isEqualTo(0) // only 1 module
        assertThat(score.riskLevel).isAtLeast(RiskLevel.LOW)
    }

    @Test
    fun `single CRITICAL finding produces HIGH or CRITICAL risk`() {
        val findings = listOf(
            Finding(
                id = "TEST-01", moduleId = "T1",
                title = "Critical", description = "Critical finding",
                riskLevel = RiskLevel.CRITICAL,
                confidence = 0.95,
            )
        )
        val score = RiskScore.calculate(findings)
        assertThat(score.severityWeight).isEqualTo(4)
        // 4*25 + 0.95*20 + 0 + 0 + 0 = 100 + 19 = 119 → capped at 100
        assertThat(score.totalScore).isAtMost(100)
        assertThat(score.riskLevel).isAtLeast(RiskLevel.HIGH)
    }

    // ════════════════════════════════════════════════════════
    //  IoC 加分测试
    // ════════════════════════════════════════════════════════

    @Test
    fun `ioc hit adds bonus to score`() {
        val withoutIoc = listOf(
            Finding(
                id = "T-01", moduleId = "T1",
                title = "Test", description = "No IoC",
                riskLevel = RiskLevel.MEDIUM,
                confidence = 0.7,
                iocHit = false,
            )
        )
        val withIoc = listOf(
            Finding(
                id = "T-01", moduleId = "T1",
                title = "Test", description = "With IoC",
                riskLevel = RiskLevel.MEDIUM,
                confidence = 0.7,
                iocHit = true,
                iocFamily = "Vo1d",
            )
        )
        val scoreWithout = RiskScore.calculate(withoutIoc)
        val scoreWith = RiskScore.calculate(withIoc)
        assertThat(scoreWith.iocBonus).isGreaterThan(0)
        assertThat(scoreWithout.iocBonus).isEqualTo(0)
        assertThat(scoreWith.totalScore).isGreaterThan(scoreWithout.totalScore)
    }

    @Test
    fun `multiple ioc hits cap at 24 bonus`() {
        val findings = (1..10).map { i ->
            Finding(
                id = "T-$i", moduleId = "T1",
                title = "IoC $i", description = "IoC hit",
                riskLevel = RiskLevel.HIGH,
                confidence = 0.9,
                iocHit = true,
                iocFamily = "Family$i",
            )
        }
        val score = RiskScore.calculate(findings)
        // 10 IoC hits × 8 = 80, but capped at 24
        assertThat(score.iocBonus).isEqualTo(24)
    }

    // ════════════════════════════════════════════════════════
    //  链完整性加分测试
    // ════════════════════════════════════════════════════════

    @Test
    fun `findings from 2 modules add chain bonus 8`() {
        val findings = listOf(
            Finding(id = "T-01", moduleId = "A5", title = "T1", description = "d",
                riskLevel = RiskLevel.MEDIUM, confidence = 0.7),
            Finding(id = "T-02", moduleId = "A2", title = "T2", description = "d",
                riskLevel = RiskLevel.MEDIUM, confidence = 0.7),
        )
        val score = RiskScore.calculate(findings)
        assertThat(score.chainBonus).isEqualTo(8)
    }

    @Test
    fun `findings from 3 or more modules add chain bonus 15`() {
        val findings = listOf(
            Finding(id = "T-01", moduleId = "A5", title = "T1", description = "d",
                riskLevel = RiskLevel.MEDIUM, confidence = 0.7),
            Finding(id = "T-02", moduleId = "A2", title = "T2", description = "d",
                riskLevel = RiskLevel.MEDIUM, confidence = 0.7),
            Finding(id = "T-03", moduleId = "A3", title = "T3", description = "d",
                riskLevel = RiskLevel.MEDIUM, confidence = 0.7),
        )
        val score = RiskScore.calculate(findings)
        assertThat(score.chainBonus).isEqualTo(15)
    }

    @Test
    fun `findings from single module add no chain bonus`() {
        val findings = listOf(
            Finding(id = "T-01", moduleId = "A5", title = "T1", description = "d",
                riskLevel = RiskLevel.MEDIUM, confidence = 0.7),
            Finding(id = "T-02", moduleId = "A5", title = "T2", description = "d",
                riskLevel = RiskLevel.MEDIUM, confidence = 0.7),
        )
        val score = RiskScore.calculate(findings)
        assertThat(score.chainBonus).isEqualTo(0)
    }

    // ════════════════════════════════════════════════════════
    //  上限测试
    // ════════════════════════════════════════════════════════

    @Test
    fun `total score never exceeds 100`() {
        val findings = listOf(
            Finding(id = "T-01", moduleId = "A5", title = "T1", description = "d",
                riskLevel = RiskLevel.CRITICAL, confidence = 1.0,
                iocHit = true, iocFamily = "Vo1d"),
            Finding(id = "T-02", moduleId = "A2", title = "T2", description = "d",
                riskLevel = RiskLevel.CRITICAL, confidence = 1.0,
                iocHit = true, iocFamily = "Kimwolf"),
            Finding(id = "T-03", moduleId = "A3", title = "T3", description = "d",
                riskLevel = RiskLevel.CRITICAL, confidence = 1.0,
                iocHit = true, iocFamily = "Anubis"),
        )
        val score = RiskScore.calculate(findings)
        assertThat(score.totalScore).isAtMost(100)
        assertThat(score.riskLevel).isEqualTo(RiskLevel.CRITICAL)
    }

    // ════════════════════════════════════════════════════════
    //  紧迫性测试
    // ════════════════════════════════════════════════════════

    @Test
    fun `urgency counts CRITICAL and HIGH findings`() {
        val findings = listOf(
            Finding(id = "T-01", moduleId = "A5", title = "T1", description = "d",
                riskLevel = RiskLevel.CRITICAL, confidence = 0.9),
            Finding(id = "T-02", moduleId = "A2", title = "T2", description = "d",
                riskLevel = RiskLevel.HIGH, confidence = 0.9),
            Finding(id = "T-03", moduleId = "A3", title = "T3", description = "d",
                riskLevel = RiskLevel.MEDIUM, confidence = 0.9),
        )
        val score = RiskScore.calculate(findings)
        // 2 urgent findings (CRITICAL + HIGH), urgency = min(2, 3) = 2
        assertThat(score.urgency).isEqualTo(2)
    }

    @Test
    fun `urgency caps at 3`() {
        val findings = (1..5).map { i ->
            Finding(id = "T-$i", moduleId = "A${i}", title = "T$i", description = "d",
                riskLevel = RiskLevel.CRITICAL, confidence = 0.9)
        }
        val score = RiskScore.calculate(findings)
        assertThat(score.urgency).isEqualTo(3)
    }

    // ════════════════════════════════════════════════════════
    //  RiskLevel 边界测试
    // ════════════════════════════════════════════════════════

    @Test
    fun `RiskLevel fromScore boundaries`() {
        assertThat(RiskLevel.fromScore(0)).isEqualTo(RiskLevel.SAFE)
        assertThat(RiskLevel.fromScore(19)).isEqualTo(RiskLevel.SAFE)
        assertThat(RiskLevel.fromScore(20)).isEqualTo(RiskLevel.LOW)
        assertThat(RiskLevel.fromScore(39)).isEqualTo(RiskLevel.LOW)
        assertThat(RiskLevel.fromScore(40)).isEqualTo(RiskLevel.MEDIUM)
        assertThat(RiskLevel.fromScore(59)).isEqualTo(RiskLevel.MEDIUM)
        assertThat(RiskLevel.fromScore(60)).isEqualTo(RiskLevel.HIGH)
        assertThat(RiskLevel.fromScore(79)).isEqualTo(RiskLevel.HIGH)
        assertThat(RiskLevel.fromScore(80)).isEqualTo(RiskLevel.CRITICAL)
        assertThat(RiskLevel.fromScore(100)).isEqualTo(RiskLevel.CRITICAL)
    }

    @Test
    fun `RiskLevel weights are ordered`() {
        assertThat(RiskLevel.SAFE.weight).isLessThan(RiskLevel.LOW.weight)
        assertThat(RiskLevel.LOW.weight).isLessThan(RiskLevel.MEDIUM.weight)
        assertThat(RiskLevel.MEDIUM.weight).isLessThan(RiskLevel.HIGH.weight)
        assertThat(RiskLevel.HIGH.weight).isLessThan(RiskLevel.CRITICAL.weight)
    }
}
