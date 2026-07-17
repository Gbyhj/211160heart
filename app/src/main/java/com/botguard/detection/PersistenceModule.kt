package com.botguard.detection

import android.app.AppOpsManager
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
 * A3 持久化审计模块 — 检测恶意软件常用的持久化机制。
 *
 * 12 项检测：
 * A3-01 设备管理器滥用
 * A3-02 无障碍服务滥用
 * A3-03 开机自启应用
 * A3-04 前台服务保活
 * A3-05 电池优化白名单滥用
 * A3-06 覆盖窗口权限
 * A3-07 通知监听服务
 * A3-08 VPN 服务
 * A3-09 IoC 文件路径命中
 * A3-10 /data/local/tmp 残留
 * A3-11 system 分区修改 (ROOT only)
 * A3-12 init.d 脚本 (ROOT only)
 */
class PersistenceModule(
    private val iocMatcher: IocMatcher,
) : ScanModule {
    override val id = "A3"
    override val name = "持久化审计"
    override val priority = ScanPriority.HIGH

    override suspend fun scan(ctx: ScanContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        findings.addAll(checkDeviceAdmin(ctx))
        findings.addAll(checkAccessibility(ctx))
        findings.addAll(checkBootReceivers(ctx))
        findings.addAll(checkForegroundServices(ctx))
        findings.addAll(checkBatteryWhitelist(ctx))
        findings.addAll(checkOverlayWindow(ctx))
        findings.addAll(checkNotificationListeners(ctx))
        findings.addAll(checkVpn(ctx))
        findings.addAll(checkIocFiles(ctx))
        findings.addAll(checkTmpFiles(ctx))
        if (ctx.runMode.canReadSystemPartition()) {
            findings.addAll(checkSystemPartition(ctx))
            findings.addAll(checkInitScripts(ctx))
        }
        return findings
    }

    /** A3-01: 设备管理器滥用 */
    private fun checkDeviceAdmin(ctx: ScanContext): List<Finding> {
        val dpm = try {
            ctx.appContext.getSystemService(android.content.Context.DEVICE_POLICY_SERVICE)
                as android.app.admin.DevicePolicyManager
        } catch (e: Exception) { return emptyList() }
        val admins = try { dpm.activeAdmins } catch (e: Exception) { null } ?: return emptyList()
        val suspicious = mutableListOf<String>()
        for (cn in admins) {
            val pkg = cn.packageName
            if (!iocMatcher.isSystemApp(pkg)) {
                suspicious.add(pkg)
            }
        }
        if (suspicious.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A3-01", moduleId = id,
            title = "发现 ${suspicious.size} 个非系统设备管理器",
            description = "以下第三方应用拥有设备管理器权限，可阻止卸载并远程锁定/擦除设备: ${suspicious.joinToString()}",
            riskLevel = RiskLevel.HIGH,
            attAckId = "T1407.002",
            confidence = 0.85,
            evidence = mapOf("admin_apps" to suspicious.joinToString(", ")),
            recommendedActions = listOf("在设置 → 安全 → 设备管理应用中检查", "撤销不认识的应用的设备管理权限"),
        ))
    }

    /** A3-02: 无障碍服务滥用 */
    private fun checkAccessibility(ctx: ScanContext): List<Finding> {
        val enabled = try {
            Settings.Secure.getString(
                ctx.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
        } catch (e: Exception) { null } ?: return emptyList()
        if (enabled.isBlank()) return emptyList()
        val services = enabled.split(":").filter { it.isNotBlank() }
        val suspicious = services.filter { svc ->
            val pkg = svc.substringBefore("/")
            !iocMatcher.isSystemApp(pkg)
        }
        if (suspicious.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A3-02", moduleId = id,
            title = "发现 ${suspicious.size} 个非系统无障碍服务",
            description = "以下第三方应用拥有无障碍权限，可读取屏幕内容、模拟点击、拦截短信验证码: ${suspicious.joinToString()}",
            riskLevel = RiskLevel.HIGH,
            attAckId = "T1413",
            confidence = 0.9,
            evidence = mapOf("accessibility_services" to suspicious.joinToString(", ")),
            recommendedActions = listOf("在设置 → 无障碍中检查", "关闭不认识的无障碍服务"),
        ))
    }

    /** A3-03: 开机自启应用 */
    private fun checkBootReceivers(ctx: ScanContext): List<Finding> {
        val pm = ctx.packageManager
        val bootReceivers = try {
            pm.queryBroadcastReceivers(
                android.content.Intent(android.content.Intent.ACTION_BOOT_COMPLETED),
                PackageManager.GET_META_DATA
            )
        } catch (e: Exception) { return emptyList() }
        val suspicious = bootReceivers.mapNotNull { ri ->
            val pkg = ri.activityInfo.packageName
            if (!iocMatcher.isSystemApp(pkg)) pkg else null
        }.distinct()
        if (suspicious.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A3-03", moduleId = id,
            title = "发现 ${suspicious.size} 个第三方开机自启应用",
            description = "以下第三方应用注册了开机自启，僵尸网络常利用此机制在重启后恢复运行: ${suspicious.take(10).joinToString()}",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1407",
            confidence = 0.6,
            evidence = mapOf("boot_apps" to suspicious.take(20).joinToString(", ")),
            recommendedActions = listOf("检查这些应用是否需要开机自启", "禁用不需要的自启"),
        ))
    }

    /** A3-04: 第三方后台进程保活（通过 /proc 遍历，替代已失效的 getRunningServices） */
    private fun checkForegroundServices(ctx: ScanContext): List<Finding> {
        // 获取所有非系统应用包名集合（使用缓存）
        val nonSystemPkgs = ctx.getInstalledApplications()
            .filter { ai ->
                ai.flags and ApplicationInfo.FLAG_SYSTEM == 0 &&
                    !iocMatcher.isSystemApp(ai.packageName)
            }
            .map { it.packageName }
            .toSet()

        if (nonSystemPkgs.isEmpty()) return emptyList()

        // 遍历 /proc 查找正在运行的第三方进程（使用缓存，与 A5-07/A7-08 共享）
        val procEntries = ctx.getProcEntries()
        val runningThirdParty = mutableSetOf<String>()
        for (entry in procEntries) {
            val procName = entry.processName
            val pkg = procName.substringBefore(':')
            if (pkg in nonSystemPkgs) {
                runningThirdParty.add(procName)
            }
        }

        if (runningThirdParty.isEmpty()) return emptyList()
        // 只报告数量较多或包含可疑进程名的情况
        if (runningThirdParty.size <= 3) return emptyList()
        return listOf(Finding(
            id = "A3-04", moduleId = id,
            title = "发现 ${runningThirdParty.size} 个第三方后台进程",
            description = "以下第三方应用正在后台运行进程，可能用于保活或维持恶意行为: ${runningThirdParty.take(10).joinToString()}",
            riskLevel = RiskLevel.LOW,
            attAckId = "T1437",
            confidence = 0.5,
            evidence = mapOf("bg_processes" to runningThirdParty.take(20).joinToString(", ")),
            recommendedActions = listOf("在设置 → 应用 → 运行服务中检查", "强制停止不需要的后台应用"),
        ))
    }

    /** A3-05: 电池优化白名单滥用 */
    private fun checkBatteryWhitelist(ctx: ScanContext): List<Finding> {
        val pm = ctx.powerManager
        val allPackages = ctx.getInstalledApplications()
        val whitelisted = allPackages.mapNotNull { ai ->
            val pkg = ai.packageName
            if (!iocMatcher.isSystemApp(pkg) && pm.isIgnoringBatteryOptimizations(pkg)) pkg else null
        }
        if (whitelisted.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A3-05", moduleId = id,
            title = "发现 ${whitelisted.size} 个应用在电池白名单中",
            description = "以下第三方应用被加入电池优化白名单，可不受限地后台运行: ${whitelisted.take(10).joinToString()}",
            riskLevel = RiskLevel.LOW,
            attAckId = "T1437",
            confidence = 0.4,
            evidence = mapOf("whitelist_apps" to whitelisted.take(20).joinToString(", ")),
            recommendedActions = listOf("在设置 → 电池中检查", "移除不需要的应用的白名单"),
        ))
    }

    /** A3-06: 覆盖窗口权限（使用 AppOpsManager 逐应用检查实际授权状态） */
    private fun checkOverlayWindow(ctx: ScanContext): List<Finding> {
        val pm = ctx.packageManager
        val appOps = ctx.appOpsManager
        val allPackages = ctx.getInstalledApplications()

        val grantedOverlay = allPackages.mapNotNull { ai ->
            val pkg = ai.packageName
            if (!iocMatcher.isSystemApp(pkg) &&
                ai.flags and ApplicationInfo.FLAG_SYSTEM == 0) {
                try {
                    // 1. 检查是否声明了 SYSTEM_ALERT_WINDOW 权限
                    val pi = pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS)
                    val declared = pi.requestedPermissions?.any { perm ->
                        perm == "android.permission.SYSTEM_ALERT_WINDOW"
                    } == true
                    if (!declared) return@mapNotNull null

                    // 2. 使用 AppOpsManager 检查实际授权状态（per-app，非全局）
                    val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        appOps.unsafeCheckOpNoThrow(
                            AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                            ai.uid, pkg
                        )
                    } else {
                        @Suppress("DEPRECATION")
                        appOps.checkOpNoThrow(
                            AppOpsManager.OPSTR_SYSTEM_ALERT_WINDOW,
                            ai.uid, pkg
                        )
                    }
                    if (mode == AppOpsManager.MODE_ALLOWED) pkg else null
                } catch (e: Exception) { null }
            } else null
        }

        if (grantedOverlay.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A3-06", moduleId = id,
            title = "发现 ${grantedOverlay.size} 个应用拥有悬浮窗权限",
            description = "以下应用被授予悬浮窗权限（SYSTEM_ALERT_WINDOW），可用于钓鱼覆盖、按键劫持: ${grantedOverlay.take(10).joinToString()}",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1413",
            confidence = 0.7,
            evidence = mapOf("overlay_apps_granted" to grantedOverlay.take(20).joinToString(", ")),
            recommendedActions = listOf("在设置 → 权限 → 悬浮窗中检查", "撤销不需要的悬浮窗权限"),
        ))
    }

    /** A3-07: 通知监听服务 */
    private fun checkNotificationListeners(ctx: ScanContext): List<Finding> {
        val enabled = try {
            Settings.Secure.getString(ctx.contentResolver, "enabled_notification_listeners")
        } catch (e: Exception) { null } ?: return emptyList()
        if (enabled.isBlank()) return emptyList()
        val components = enabled.split(":").filter { it.isNotBlank() }
        val suspicious = components.filter { cn ->
            val pkg = cn.substringBefore("/")
            !iocMatcher.isSystemApp(pkg)
        }
        if (suspicious.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A3-07", moduleId = id,
            title = "发现 ${suspicious.size} 个第三方通知监听服务",
            description = "以下第三方应用可读取所有通知内容，包括短信验证码、银行通知等: ${suspicious.joinToString()}",
            riskLevel = RiskLevel.HIGH,
            attAckId = "T1413",
            confidence = 0.85,
            evidence = mapOf("notif_listeners" to suspicious.joinToString(", ")),
            recommendedActions = listOf("在设置 → 通知访问中检查", "关闭不认识的通知监听"),
        ))
    }

    /** A3-08: VPN 服务 */
    private fun checkVpn(ctx: ScanContext): List<Finding> {
        val cm = ctx.connectivityManager
        val activeVpn = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                cm.activeNetworkInfo?.type == android.net.ConnectivityManager.TYPE_VPN
            } else false
        } catch (e: Exception) { false }

        // 检查声明 VPN 服务的第三方应用（P2-8: 重构为直接收集包名，而非 boolean 列表）
        val pm = ctx.packageManager
        val vpnApps = ctx.getInstalledApplications().mapNotNull { ai ->
            val pkg = ai.packageName
            if (!iocMatcher.isSystemApp(pkg) &&
                ai.flags and ApplicationInfo.FLAG_SYSTEM == 0) {
                try {
                    val pi = pm.getPackageInfo(pkg, PackageManager.GET_SERVICES)
                    val hasVpnService = pi.services?.any { svc ->
                        svc.permission == "android.permission.BIND_VPN_SERVICE"
                    } == true
                    if (hasVpnService) pkg else null
                } catch (e: Exception) { null }
            } else null
        }

        if (vpnApps.isEmpty() && !activeVpn) return emptyList()
        val desc = buildString {
            if (activeVpn) append("VPN 当前活跃; ")
            append("发现 ${vpnApps.size} 个第三方 VPN 应用")
            if (vpnApps.isNotEmpty()) append(": ${vpnApps.take(5).joinToString()}")
        }
        return listOf(Finding(
            id = "A3-08", moduleId = id,
            title = "VPN 服务检测",
            description = "$desc。僵尸网络可能通过 VPN 拦截所有网络流量。",
            riskLevel = RiskLevel.LOW,
            attAckId = "T1413",
            confidence = 0.3,
            evidence = mapOf(
                "vpn_active" to "$activeVpn",
                "vpn_apps" to vpnApps.take(10).joinToString(", "),
                "vpn_app_count" to "${vpnApps.size}",
            ),
            recommendedActions = listOf("确认 VPN 应用是否为已知可信应用", "如不需要，关闭 VPN 服务"),
        ))
    }

    /** A3-09: IoC 文件路径命中 */
    private fun checkIocFiles(ctx: ScanContext): List<Finding> {
        // 检查 /data/local/tmp/ 下的文件
        val tmpDir = java.io.File("/data/local/tmp")
        val findings = mutableListOf<Finding>()
        tmpDir.listFiles()?.forEach { file ->
            val family = iocMatcher.matchFile(file.absolutePath)
            if (family != null) {
                findings.add(Finding(
                    id = "A3-09", moduleId = id,
                    title = "检测到恶意文件: ${file.name}",
                    description = "文件 ${file.absolutePath} 匹配僵尸网络家族 $family 的 IoC。",
                    riskLevel = RiskLevel.CRITICAL,
                    attAckId = "T1407.002",
                    confidence = 0.95,
                    evidence = mapOf("path" to file.absolutePath, "ioc_family" to family),
                    recommendedActions = listOf("删除此文件", "检查关联应用", "全盘扫描"),
                    iocHit = true, iocFamily = family,
                ))
            }
        }
        // 检查 IoC 中已知的文件路径
        val knownPaths = listOf(
            "/system/bin/vo1d", "/system/xbin/vo1d", "/system/bin/netd_services",
            "/data/local/tmp/kwd", "/data/local/tmp/.kw", "/data/local/tmp/vo1d",
        )
        for (path in knownPaths) {
            val file = java.io.File(path)
            if (file.exists()) {
                val family = iocMatcher.matchFile(path) ?: "Unknown"
                findings.add(Finding(
                    id = "A3-09", moduleId = id,
                    title = "检测到可疑文件: $path",
                    description = "文件 $path 存在，匹配已知僵尸网络文件 IoC (家族: $family)。",
                    riskLevel = RiskLevel.CRITICAL,
                    attAckId = "T1407.002",
                    confidence = 0.9,
                    evidence = mapOf("path" to path, "ioc_family" to family),
                    recommendedActions = listOf("删除此文件", "检查关联应用"),
                    iocHit = true, iocFamily = family,
                ))
            }
        }
        return findings
    }

    /** A3-10: /data/local/tmp 残留文件 */
    private fun checkTmpFiles(ctx: ScanContext): List<Finding> {
        val tmpDir = java.io.File("/data/local/tmp")
        val files = tmpDir.listFiles() ?: return emptyList()
        val suspicious = files.filter { f ->
            val name = f.name
            name.startsWith(".") || name.endsWith(".so") || name.endsWith(".dex") ||
                name.endsWith(".apk") || name.endsWith(".bin") || name.endsWith(".sh")
        }
        if (suspicious.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A3-10", moduleId = id,
            title = "/data/local/tmp 发现 ${suspicious.size} 个可疑文件",
            description = "临时目录中存在可执行/隐藏文件，僵尸网络常在此目录暂存 payload: ${suspicious.take(5).map { it.name }.joinToString()}",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1407.002",
            confidence = 0.6,
            evidence = mapOf("tmp_files" to suspicious.take(10).map { it.name }.joinToString(", ")),
            recommendedActions = listOf("检查这些文件来源", "删除不明文件"),
        ))
    }

    /** A3-11: system 分区修改 (ROOT only) */
    private fun checkSystemPartition(ctx: ScanContext): List<Finding> {
        val suspiciousFiles = mutableListOf<String>()
        val checkPaths = listOf("/system/bin/", "/system/xbin/", "/system/app/", "/system/priv-app/")
        for (dir in checkPaths) {
            val d = java.io.File(dir)
            d.listFiles()?.forEach { f ->
                val family = iocMatcher.matchFile(f.absolutePath)
                if (family != null) suspiciousFiles.add("${f.absolutePath} ($family)")
            }
        }
        if (suspiciousFiles.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A3-11", moduleId = id,
            title = "system 分区发现 ${suspiciousFiles.size} 个 IoC 文件",
            description = "系统分区中被植入恶意文件，设备可能已被持久化感染: ${suspiciousFiles.joinToString()}",
            riskLevel = RiskLevel.CRITICAL,
            attAckId = "T1407.002",
            confidence = 0.95,
            evidence = mapOf("system_files" to suspiciousFiles.joinToString(", ")),
            recommendedActions = listOf("重新刷入官方系统镜像", "不要仅卸载应用，需重建系统分区"),
            iocHit = true,
        ))
    }

    /** A3-12: init.d 脚本 (ROOT only) */
    private fun checkInitScripts(ctx: ScanContext): List<Finding> {
        val initDir = java.io.File("/system/etc/init.d")
        val scripts = initDir.listFiles()?.filter { it.name.endsWith(".sh") || it.name.startsWith("S") } ?: return emptyList()
        if (scripts.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A3-12", moduleId = id,
            title = "发现 ${scripts.size} 个 init.d 启动脚本",
            description = "系统启动脚本目录存在自定义脚本，可能被用于持久化恶意命令: ${scripts.take(5).map { it.name }.joinToString()}",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1407",
            confidence = 0.5,
            evidence = mapOf("scripts" to scripts.take(10).map { it.name }.joinToString(", ")),
            recommendedActions = listOf("检查脚本内容", "删除不明脚本"),
        ))
    }
}
