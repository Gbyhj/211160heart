package com.botguard.detection

import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.util.Log
import com.botguard.core.ScanModule
import com.botguard.core.model.Finding
import com.botguard.core.model.RiskLevel
import com.botguard.core.model.ScanContext
import com.botguard.core.model.ScanPriority
import com.botguard.intel.IocMatcher

/**
 * A5 行为审计模块 — 检测设备行为层面的异常。
 *
 * 8 项检测，全部支持 NO_ROOT 模式：
 * A5-01 ADB 调试开启
 * A5-02 无线 ADB 开启
 * A5-03 开发者选项开启
 * A5-04 未知来源安装开启
 * A5-05 异常 CPU 负载（/proc/stat）
 * A5-06 电池温度异常
 * A5-07 异常后台进程（含 IoC 进程名匹配）
 * A5-08 屏幕锁未设置
 */
class BehaviorModule(
    private val iocMatcher: IocMatcher,
) : ScanModule {
    override val id = "A5"
    override val name = "行为审计"
    override val priority = ScanPriority.HIGHEST

    override suspend fun scan(ctx: ScanContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        findings.addAll(checkAdb(ctx))
        findings.addAll(checkWirelessAdb(ctx))
        findings.addAll(checkDeveloperOptions(ctx))
        findings.addAll(checkUnknownSources(ctx))
        findings.addAll(checkCpuLoad(ctx))
        findings.addAll(checkBatteryTemp(ctx))
        findings.addAll(checkBackgroundProcesses(ctx))
        findings.addAll(checkScreenLock(ctx))
        return findings
    }

    /** A5-01: ADB 调试是否开启 */
    private fun checkAdb(ctx: ScanContext): List<Finding> {
        val enabled = try {
            Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (e: Exception) { false }
        if (!enabled) return emptyList()
        return listOf(Finding(
            id = "A5-01", moduleId = id,
            title = "ADB 调试已开启",
            description = "ADB 调试允许通过 USB 连接控制设备。僵尸网络家族 Kimwolf 利用 ADB 端口 5555 进行传播。",
            riskLevel = RiskLevel.LOW,
            attAckId = "T1417",
            confidence = 0.9,
            evidence = mapOf("adb_enabled" to "true"),
            recommendedActions = listOf("在开发者选项中关闭 USB 调试", "如无需开发，关闭开发者选项"),
        ))
    }

    /** A5-02: 无线 ADB 是否开启（Android 11+） */
    private fun checkWirelessAdb(ctx: ScanContext): List<Finding> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return emptyList()
        val enabled = try {
            Settings.Global.getInt(ctx.contentResolver, "adb_wifi_enabled", 0) == 1
        } catch (e: Exception) { false }
        if (!enabled) return emptyList()
        return listOf(Finding(
            id = "A5-02", moduleId = id,
            title = "无线 ADB 已开启",
            description = "无线 ADB 允许通过网络远程调试设备，若设备暴露在公网或局域网中可被攻击者利用。",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1417.001",
            confidence = 0.85,
            evidence = mapOf("wireless_adb" to "true"),
            recommendedActions = listOf("关闭无线调试", "确保设备不暴露在不可信网络中"),
        ))
    }

    /** A5-03: 开发者选项是否开启 */
    private fun checkDeveloperOptions(ctx: ScanContext): List<Finding> {
        val enabled = try {
            Settings.Global.getInt(
                ctx.contentResolver,
                Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
            ) == 1
        } catch (e: Exception) { false }
        if (!enabled) return emptyList()
        return listOf(Finding(
            id = "A5-03", moduleId = id,
            title = "开发者选项已开启",
            description = "开发者选项开启了多种调试和安装途径。部分僵尸网络利用开发者选项中的 USB 调试进行传播。",
            riskLevel = RiskLevel.LOW,
            attAckId = "T1407",
            confidence = 0.7,
            evidence = mapOf("developer_options" to "true"),
            recommendedActions = listOf("如非开发用途，建议关闭开发者选项"),
        ))
    }

    /** A5-04: 可安装未知来源 APK 的应用（Android 8+ 使用 REQUEST_INSTALL_PACKAGES 权限） */
    private fun checkUnknownSources(ctx: ScanContext): List<Finding> {
        val pm = ctx.packageManager
        val allApps = ctx.getInstalledApplications()
        val installers = allApps.mapNotNull { ai ->
                val pkg = ai.packageName
                if (!iocMatcher.isSystemApp(pkg) &&
                    ai.flags and ApplicationInfo.FLAG_SYSTEM == 0) {
                    try {
                        val pi = pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
                        val hasPermission = pi.requestedPermissions?.any { perm ->
                            perm == "android.permission.REQUEST_INSTALL_PACKAGES"
                        } == true
                        if (hasPermission) pkg else null
                    } catch (e: Exception) { null }
                } else null
            }
        if (installers.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A5-04", moduleId = id,
            title = "发现 ${installers.size} 个应用可安装未知来源 APK",
            description = "以下第三方应用拥有 REQUEST_INSTALL_PACKAGES 权限，可侧载安装 APK。僵尸网络常通过此途径传播: ${installers.take(10).joinToString()}",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1407.002",
            confidence = 0.75,
            evidence = mapOf("installer_apps" to installers.take(20).joinToString(", ")),
            recommendedActions = listOf("在设置 → 应用 → 特殊权限中检查", "撤销不需要的应用的安装权限"),
        ))
    }

    /** A5-05: 异常 CPU 负载（读取 /proc/loadavg，获取近期平均负载） */
    private fun checkCpuLoad(ctx: ScanContext): List<Finding> {
        val loadavg = ctx.readProcLoadavg()
        if (loadavg.isBlank()) return emptyList()
        // /proc/loadavg 格式: "0.52 0.45 0.39 2/845 12345"
        val parts = loadavg.trim().split(Regex("\\s+"))
        if (parts.size < 2) return emptyList()
        try {
            val oneMin = parts[0].toFloat()
            val fiveMin = parts[1].toFloat()
            val cpuCount = ctx.readCpuCount().coerceAtLeast(1)
            // 负载率 = 1分钟平均负载 / CPU核心数
            val usageRatio = oneMin / cpuCount
            val usagePercent = (usageRatio * 100).toInt().coerceIn(0, 100)
            if (usageRatio > 0.85f) {
                return listOf(Finding(
                    id = "A5-05", moduleId = id,
                    title = "异常 CPU 负载 (1分钟平均 ${"%.2f".format(oneMin)}, ${cpuCount}核)",
                    description = "1分钟平均负载 ${"%.2f".format(oneMin)}（${cpuCount}核 CPU），负载率约 ${usagePercent}%。可能存在后台挖矿或 DDoS 攻击行为。",
                    riskLevel = RiskLevel.MEDIUM,
                    attAckId = "T1496",
                    confidence = 0.65,
                    evidence = mapOf(
                        "loadavg_1min" to "%.2f".format(oneMin),
                        "loadavg_5min" to "%.2f".format(fiveMin),
                        "cpu_cores" to "$cpuCount",
                        "usage_ratio" to "%.2f".format(usageRatio),
                    ),
                    recommendedActions = listOf("检查是否有异常高耗电应用", "使用系统电池管理查看耗电排行"),
                ))
            }
        } catch (e: Exception) {
            Log.w("BehaviorModule", "解析 /proc/loadavg 失败: $loadavg", e)
        }
        return emptyList()
    }

    /** A5-06: 电池温度异常 */
    private fun checkBatteryTemp(ctx: ScanContext): List<Finding> {
        try {
            val tempFile = java.io.File("/sys/class/power_supply/battery/temp")
            if (tempFile.exists()) {
                val temp = tempFile.bufferedReader().use { it.readLine().trim().toInt() }
                if (temp > 420) {
                    return listOf(Finding(
                        id = "A5-06", moduleId = id,
                        title = "电池温度异常 (${temp / 10.0}°C)",
                        description = "电池温度 ${temp / 10.0}°C 偏高，可能存在后台持续高负载的恶意行为（如挖矿、DDoS）。",
                        riskLevel = RiskLevel.MEDIUM,
                        attAckId = "T1496",
                        confidence = 0.5,
                        evidence = mapOf("battery_temp" to "${temp / 10.0}°C"),
                        recommendedActions = listOf("检查后台运行的应用", "查看电池耗电排行"),
                    ))
                }
            }
        } catch (e: Exception) { }
        return emptyList()
    }

    /** A5-07: 异常后台进程（含 IoC 进程名匹配，使用 ScanContext 缓存） */
    private fun checkBackgroundProcesses(ctx: ScanContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val procEntries = ctx.getProcEntries()
        val iocHits = mutableListOf<Pair<String, String>>()
        val totalProcs = procEntries.size
        for (entry in procEntries) {
            val family = iocMatcher.matchProcess(entry.processName)
            if (family != null) {
                iocHits.add(entry.processName to family)
            }
        }
        // IoC 命中 — 严重风险
        for ((procName, family) in iocHits) {
            findings.add(Finding(
                id = "A5-07", moduleId = id,
                title = "检测到恶意进程: $procName",
                description = "运行中的进程 $procName 匹配僵尸网络家族 $family 的 IoC。该进程可能是僵尸节点组件。",
                riskLevel = RiskLevel.CRITICAL,
                attAckId = "T1437",
                confidence = 0.95,
                evidence = mapOf("process" to procName, "ioc_family" to family, "pid_dir" to "/proc/"),
                recommendedActions = listOf("立即停止该进程", "卸载关联应用", "全盘扫描设备"),
                iocHit = true,
                iocFamily = family,
            ))
        }
        // 进程数量异常
        if (totalProcs > 150 && iocHits.isEmpty()) {
            findings.add(Finding(
                id = "A5-07", moduleId = id,
                title = "后台进程数量异常 ($totalProcs)",
                description = "当前运行 $totalProcs 个进程，数量偏多。部分僵尸网络会创建大量子进程维持运行。",
                riskLevel = RiskLevel.LOW,
                attAckId = "T1437",
                confidence = 0.4,
                evidence = mapOf("process_count" to "$totalProcs"),
                recommendedActions = listOf("检查是否有不认识的后台应用"),
            ))
        }
        return findings
    }

    /** A5-08: 屏幕锁未设置 */
    private fun checkScreenLock(ctx: ScanContext): List<Finding> {
        val hasLock = try { ctx.keyguardManager.isKeyguardSecure } catch (e: Exception) { false }
        if (hasLock) return emptyList()
        return listOf(Finding(
            id = "A5-08", moduleId = id,
            title = "未设置屏幕锁",
            description = "设备未设置屏幕锁。攻击者若物理接触设备可安装恶意软件并将其变为僵尸节点。",
            riskLevel = RiskLevel.LOW,
            attAckId = "T1413",
            confidence = 0.7,
            evidence = mapOf("screen_lock" to "disabled"),
            recommendedActions = listOf("设置 PIN/图案/指纹屏幕锁"),
        ))
    }
}
