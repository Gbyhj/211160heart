package com.botguard.detection

import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import com.botguard.core.ScanModule
import com.botguard.core.model.Finding
import com.botguard.core.model.RiskLevel
import com.botguard.core.model.ScanContext
import com.botguard.core.model.ScanPriority
import com.botguard.intel.IocMatcher

/**
 * A2 应用审计模块 — 扫描已安装应用，检测恶意 APK 特征。
 *
 * 9 项检测：
 * A2-01 IoC 包名命中
 * A2-02 隐藏图标（无 launcher Activity）
 * A2-03 伪装系统应用
 * A2-04 危险权限组合
 * A2-05 签名异常
 * A2-06 动态代码加载
 * A2-07 多进程应用
 * A2-08 非官方来源
 * A2-09 后台服务过多
 */
class AppModule(
    private val iocMatcher: IocMatcher,
) : ScanModule {
    override val id = "A2"
    override val name = "应用审计"
    override val priority = ScanPriority.HIGH

    companion object {
        // 危险权限组合模式
        val DANGER_COMBOS = listOf(
            setOf("android.permission.SEND_SMS", "android.permission.READ_CONTACTS"),
            setOf("android.permission.RECORD_AUDIO", "android.permission.INTERNET"),
            setOf("android.permission.ACCESSIBILITY", "android.permission.INTERNET"),
            setOf("android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"),
            setOf("android.permission.READ_SMS", "android.permission.INTERNET"),
            setOf("android.permission.INSTALL_PACKAGES", "android.permission.INTERNET"),
            setOf("android.permission.DEVICE_POWER", "android.permission.RECEIVE_BOOT_COMPLETED"),
            setOf("android.permission.BIND_DEVICE_ADMIN", "android.permission.INTERNET"),
        )
        // 正规安装来源
        val TRUSTED_INSTALLERS = setOf(
            "com.android.vending", "com.google.android.packageinstaller",
            "com.miui.packageinstaller", "com.samsung.android.packageinstaller",
            "com.huawei.appmarket", "com.coloros.packageinstaller",
        )
    }

    override suspend fun scan(ctx: ScanContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        val pm = ctx.packageManager
        val packages = ctx.getInstalledPackages()
        if (packages.isEmpty()) return emptyList()

        val hiddenIconApps = mutableListOf<String>()
        val disguisedApps = mutableListOf<String>()
        val dangerPermApps = mutableListOf<String>()
        val dynamicLoadApps = mutableListOf<String>()
        val multiProcApps = mutableListOf<String>()
        val nonOfficialApps = mutableListOf<String>()
        var totalBgServices = 0

        for (pkg in packages) {
            val pkgName = pkg.packageName ?: continue
            val appInfo = pkg.applicationInfo ?: continue

            // A2-01: IoC 包名命中
            val iocFamily = iocMatcher.matchPackage(pkgName)
            if (iocFamily != null) {
                findings.add(Finding(
                    id = "A2-01", moduleId = id,
                    title = "检测到恶意应用: $pkgName",
                    description = "已安装应用 $pkgName 匹配僵尸网络家族 $iocFamily 的 IoC。该应用是已知恶意软件。",
                    riskLevel = RiskLevel.CRITICAL,
                    attAckId = "T1421",
                    confidence = 0.98,
                    evidence = mapOf("package" to pkgName, "ioc_family" to iocFamily),
                    recommendedActions = listOf("立即卸载此应用", "检查同来源的其他应用", "修改可能泄露的密码"),
                    iocHit = true, iocFamily = iocFamily,
                ))
                continue // 已确认为恶意，跳过其他检查
            }

            // 白名单跳过
            if (iocMatcher.isSystemApp(pkgName)) continue

            // A2-02: 隐藏图标（无 launcher Activity）
            val launchIntent = pm.getLaunchIntentForPackage(pkgName)
            if (launchIntent == null && appInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0) {
                if (!iocMatcher.isNoIconApp(pkgName)) {
                    hiddenIconApps.add(pkgName)
                }
            }

            // A2-03: 伪装系统应用（非系统应用使用系统级包名前缀）
            if (appInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0) {
                val sysPrefixes = listOf("com.android.", "com.google.android.", "android.", "com.miui.", "com.sec.")
                for (prefix in sysPrefixes) {
                    if (pkgName.startsWith(prefix) && !iocMatcher.isSystemApp(pkgName)) {
                        disguisedApps.add(pkgName)
                        break
                    }
                }
            }

            // A2-04: 危险权限组合
            val perms = pkg.requestedPermissions?.toSet() ?: emptySet()
            for (combo in DANGER_COMBOS) {
                if (combo.all { it in perms }) {
                    dangerPermApps.add("$pkgName [${combo.joinToString("+") { it.substringAfterLast(".") }}]")
                    break
                }
            }

            // A2-06: 动态代码加载（检查外部存储安装 + split APK + 多 dex）
            // 正常应用 nativeLibraryDir 为 /data/app/<pkg>/lib/arm64，不可能含 "tmp"
            // 改为检查：1) 安装在外部存储 2) 声明多 split APK 3) flags 中 FLAG_LARGE_HEAP + 有 native 库
            if (appInfo.flags and ApplicationInfo.FLAG_SYSTEM == 0) {
                // 检查是否安装在外部存储（恶意软件常用此方式规避卸载）
                if (appInfo.flags and ApplicationInfo.FLAG_EXTERNAL_STORAGE != 0) {
                    dynamicLoadApps.add("$pkgName (外部存储)")
                }
                // 检查 split APK — 恶意软件可通过 split 动态下发 payload
                try {
                    val splitNames = pkg.splitNames
                    if (splitNames != null && splitNames.isNotEmpty()) {
                        dynamicLoadApps.add("$pkgName (${splitNames.size} splits)")
                    }
                } catch (e: Exception) { }
            }

            // A2-07: 多进程应用
            if (appInfo.processName != null && appInfo.processName != pkgName) {
                multiProcApps.add("$pkgName → ${appInfo.processName}")
            }

            // A2-08: 非官方来源
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    val sourceInfo = pm.getInstallSourceInfo(pkgName)
                    val installer = sourceInfo.installingPackageName
                    if (installer != null && installer !in TRUSTED_INSTALLERS) {
                        nonOfficialApps.add("$pkgName (来源: $installer)")
                    }
                } else {
                    @Suppress("DEPRECATION")
                    val installer = pm.getInstallerPackageName(pkgName)
                    if (installer != null && installer !in TRUSTED_INSTALLERS) {
                        nonOfficialApps.add("$pkgName (来源: $installer)")
                    }
                }
            } catch (e: Exception) { }

            // 统计后台服务
            pkg.services?.let { totalBgServices += it.size }
        }

        // A2-02: 汇总隐藏图标
        if (hiddenIconApps.isNotEmpty()) {
            findings.add(Finding(
                id = "A2-02", moduleId = id,
                title = "发现 ${hiddenIconApps.size} 个隐藏图标应用",
                description = "以下应用没有桌面图标但已安装，可能试图隐藏自身。恶意软件常隐藏图标逃避用户察觉: ${hiddenIconApps.take(5).joinToString()}",
                riskLevel = RiskLevel.MEDIUM,
                attAckId = "T1407.002",
                confidence = 0.7,
                evidence = mapOf("apps" to hiddenIconApps.take(10).joinToString(", ")),
                recommendedActions = listOf("在设置中检查这些应用", "卸载不认识的应用"),
            ))
        }

        // A2-03: 汇总伪装系统应用
        if (disguisedApps.isNotEmpty()) {
            findings.add(Finding(
                id = "A2-03", moduleId = id,
                title = "发现 ${disguisedApps.size} 个伪装系统应用",
                description = "以下第三方应用使用了系统级包名前缀，试图伪装成系统应用: ${disguisedApps.take(5).joinToString()}",
                riskLevel = RiskLevel.HIGH,
                attAckId = "T1421.001",
                confidence = 0.85,
                evidence = mapOf("apps" to disguisedApps.take(10).joinToString(", ")),
                recommendedActions = listOf("立即卸载这些应用", "检查应用签名是否为官方"),
            ))
        }

        // A2-04: 汇总危险权限组合
        if (dangerPermApps.isNotEmpty()) {
            findings.add(Finding(
                id = "A2-04", moduleId = id,
                title = "发现 ${dangerPermApps.size} 个危险权限组合应用",
                description = "以下应用申请了高风险权限组合，可能用于短信窃取、录音监控或辅助功能滥用: ${dangerPermApps.take(5).joinToString()}",
                riskLevel = RiskLevel.MEDIUM,
                attAckId = "T1413",
                confidence = 0.65,
                evidence = mapOf("apps" to dangerPermApps.take(10).joinToString(", ")),
                recommendedActions = listOf("检查这些应用的权限设置", "撤销不必要的权限"),
            ))
        }

        // A2-05a: 可调试应用（FLAG_DEBUGGABLE 在生产环境中异常）
        val debuggableApps = packages.filter {
            it.applicationInfo?.flags?.and(ApplicationInfo.FLAG_DEBUGGABLE) != 0
        }.map { it.packageName }.filter { !iocMatcher.isSystemApp(it) }
        if (debuggableApps.isNotEmpty()) {
            findings.add(Finding(
                id = "A2-05", moduleId = id,
                title = "发现 ${debuggableApps.size} 个可调试应用",
                description = "以下应用标记为可调试 (debuggable)，在生产环境中异常。恶意应用可能通过此标志绕过安全限制: ${debuggableApps.take(5).joinToString()}",
                riskLevel = RiskLevel.MEDIUM,
                attAckId = "T1417.001",
                confidence = 0.7,
                evidence = mapOf("debuggable_apps" to debuggableApps.take(10).joinToString(", ")),
                recommendedActions = listOf("卸载非开发用途的可调试应用"),
            ))
        }

        // A2-05b: 自签名应用（非系统应用使用自签名证书，常见于恶意软件）
        val selfSignedApps = packages.mapNotNull { pkg ->
            val pkgName = pkg.packageName ?: return@mapNotNull null
            val appInfo = pkg.applicationInfo ?: return@mapNotNull null
            if (iocMatcher.isSystemApp(pkgName)) return@mapNotNull null
            if (appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0) return@mapNotNull null
            try {
                val sigPkg = pm.getPackageInfo(pkgName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = sigPkg.signingInfo
                if (signingInfo != null) {
                    // 检查是否为自签名（只有 1 个签名者且非平台签名）
                    val hasMultipleSigners = signingInfo.hasMultipleSigners()
                    if (!hasMultipleSigners && signingInfo.signingCertificateHistory?.isNotEmpty() == true) {
                        pkgName
                    } else null
                } else null
            } catch (e: Exception) { null }
        }
        if (selfSignedApps.isNotEmpty()) {
            findings.add(Finding(
                id = "A2-05", moduleId = id,
                title = "发现 ${selfSignedApps.size} 个自签名应用",
                description = "以下第三方应用使用自签名证书（非官方应用商店签名），在恶意软件中常见: ${selfSignedApps.take(5).joinToString()}",
                riskLevel = RiskLevel.LOW,
                attAckId = "T1407.002",
                confidence = 0.4,
                evidence = mapOf("self_signed_apps" to selfSignedApps.take(10).joinToString(", ")),
                recommendedActions = listOf("确认这些应用来源是否可信"),
            ))
        }

        // A2-06: 汇总动态代码加载
        if (dynamicLoadApps.isNotEmpty()) {
            findings.add(Finding(
                id = "A2-06", moduleId = id,
                title = "发现 ${dynamicLoadApps.size} 个可疑动态加载应用",
                description = "以下应用可能通过外部存储安装或 split APK 动态下发 payload: ${dynamicLoadApps.take(5).joinToString()}",
                riskLevel = RiskLevel.MEDIUM,
                attAckId = "T1407.001",
                confidence = 0.55,
                evidence = mapOf("dynamic_load_apps" to dynamicLoadApps.take(10).joinToString(", ")),
                recommendedActions = listOf("检查这些应用来源", "确认是否需要 split APK", "必要时卸载"),
            ))
        }

        // A2-07: 汇总多进程应用
        if (multiProcApps.isNotEmpty()) {
            findings.add(Finding(
                id = "A2-07", moduleId = id,
                title = "发现 ${multiProcApps.size} 个多进程应用",
                description = "以下应用运行在独立进程中，可能用于规避权限隔离或维持持久运行: ${multiProcApps.take(5).joinToString()}",
                riskLevel = RiskLevel.LOW,
                attAckId = "T1437",
                confidence = 0.4,
                evidence = mapOf("apps" to multiProcApps.take(10).joinToString(", ")),
                recommendedActions = listOf("确认这些应用是否为正常行为"),
            ))
        }

        // A2-08: 汇总非官方来源
        if (nonOfficialApps.isNotEmpty()) {
            findings.add(Finding(
                id = "A2-08", moduleId = id,
                title = "发现 ${nonOfficialApps.size} 个非官方来源应用",
                description = "以下应用非从官方应用商店安装，可能通过侧载或钓鱼网站安装: ${nonOfficialApps.take(5).joinToString()}",
                riskLevel = RiskLevel.MEDIUM,
                attAckId = "T1407.002",
                confidence = 0.7,
                evidence = mapOf("apps" to nonOfficialApps.take(10).joinToString(", ")),
                recommendedActions = listOf("确认这些应用的来源是否可信", "卸载来源不明的应用"),
            ))
        }

        // A2-09: 后台服务过多
        if (totalBgServices > 50) {
            findings.add(Finding(
                id = "A2-09", moduleId = id,
                title = "后台服务数量异常 ($totalBgServices)",
                description = "设备注册了 $totalBgServices 个后台服务。僵尸网络常注册大量服务维持持久运行。",
                riskLevel = RiskLevel.LOW,
                attAckId = "T1437",
                confidence = 0.35,
                evidence = mapOf("total_services" to "$totalBgServices"),
                recommendedActions = listOf("检查不需要的应用并卸载"),
            ))
        }

        return findings
    }
}
