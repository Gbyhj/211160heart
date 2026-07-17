package com.botguard.core.model

import android.os.Build

/**
 * 模块执行错误记录。
 */
data class ModuleError(
    val moduleId: String,
    val moduleName: String,
    val errorMessage: String,
)

/**
 * 完整扫描结果。
 */
data class ScanResult(
    val findings: List<Finding>,
    val riskScore: RiskScore,
    val deviceInfo: DeviceInfo,
    val scanDurationMs: Long,
    val modulesScanned: Int,
    val runMode: RunMode,
    val errors: List<ModuleError> = emptyList(),
    val timestamp: Long = System.currentTimeMillis(),
) {
    val totalFindings: Int get() = findings.size
    val criticalCount: Int get() = findings.count { it.riskLevel == RiskLevel.CRITICAL }
    val highCount: Int get() = findings.count { it.riskLevel == RiskLevel.HIGH }
    val mediumCount: Int get() = findings.count { it.riskLevel == RiskLevel.MEDIUM }
    val lowCount: Int get() = findings.count { it.riskLevel == RiskLevel.LOW }
    val iocHits: Int get() = findings.count { it.iocHit }
    val iocFamilies: List<String> get() = findings.mapNotNull { it.iocFamily }.distinct()
}

data class DeviceInfo(
    val manufacturer: String = Build.MANUFACTURER,
    val model: String = Build.MODEL,
    val brand: String = Build.BRAND,
    val sdk: Int = Build.VERSION.SDK_INT,
    val release: String = Build.VERSION.RELEASE,
    val fingerprint: String = Build.FINGERPRINT,
    val securityPatch: String = Build.VERSION.SECURITY_PATCH ?: "unknown",
)
