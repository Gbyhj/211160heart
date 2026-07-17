package com.botguard.detection

import android.os.Build
import android.util.Log
import com.botguard.core.ScanModule
import com.botguard.core.model.Finding
import com.botguard.core.model.RiskLevel
import com.botguard.core.model.ScanContext
import com.botguard.core.model.ScanPriority
import com.botguard.detection.ProcNetParser
import com.botguard.intel.IocMatcher

/**
 * A6 Root 环境检测模块 — 检测设备安全环境状态。
 *
 * 9 项检测：
 * A6-01 Root 二进制文件（含 Magisk 模块检测）
 * A6-02 系统分区修改（ro.build.tags）
 * A6-03 模拟器检测
 * A6-04 调试器附加
 * A6-05 Xposed 框架（含 /proc/self/maps 内存映射检测）
 * A6-06 Frida 注入
 * A6-07 SELinux 状态
 * A6-08 Verified Boot 状态
 * A6-09 运行时 Hook 框架检测（内存映射）
 */
class RootEnvModule(
    private val iocMatcher: IocMatcher,
) : ScanModule {
    override val id = "A6"
    override val name = "Root环境检测"
    override val priority = ScanPriority.MEDIUM

    override suspend fun scan(ctx: ScanContext): List<Finding> {
        val findings = mutableListOf<Finding>()
        findings.addAll(checkRootBinary(ctx))
        findings.addAll(checkSystemMod(ctx))
        findings.addAll(checkEmulator(ctx))
        findings.addAll(checkDebugger(ctx))
        findings.addAll(checkXposed(ctx))
        findings.addAll(checkFrida(ctx))
        findings.addAll(checkSelinux(ctx))
        findings.addAll(checkVerifiedBoot(ctx))
        findings.addAll(checkRuntimeHooks(ctx))
        return findings
    }

    /** A6-01: Root 二进制文件（含 Magisk 模块检测） */
    private fun checkRootBinary(ctx: ScanContext): List<Finding> {
        val rootPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
            "/system/sbin/su", "/vendor/bin/su", "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk", "/system/app/SuperSU", "/data/local/tmp/su",
            "/data/local/su", "/system/bin/.su", "/system/xbin/.su",
            "/system/bin/busybox", "/system/xbin/busybox",
            "/sbin/.magisk", "/data/adb/magisk",
        )
        val found = rootPaths.filter { java.io.File(it).exists() }.toMutableList()

        // v2 增强：检查 Magisk 模块目录（/data/adb/modules/）
        val magiskModulesDir = java.io.File("/data/adb/modules/")
        if (magiskModulesDir.isDirectory()) {
            val moduleDirs = magiskModulesDir.listFiles()
                ?.filter { it.isDirectory && !it.name.startsWith(".") }
                ?.map { it.name }
            if (!moduleDirs.isNullOrEmpty()) {
                found.add("/data/adb/modules/: ${moduleDirs.joinToString(", ")}")
            }
        }

        // 检查 Magisk 服务进程（通过 /proc 遍历）
        try {
            val procDir = java.io.File("/proc")
            procDir.listFiles()?.forEach { dir ->
                if (dir.name.matches(Regex("\\d+"))) {
                    try {
                        val cmdline = java.io.File(dir, "cmdline").bufferedReader().use { it.readLine() }
                        if (cmdline != null && (cmdline.contains("magiskd", true) || cmdline.contains("magisk", true))) {
                            if ("magiskd".takeUnless { found.any { it.contains("magisk") } } != null) {
                                found.add("process: $cmdline")
                            }
                        }
                    } catch (e: Exception) { }
                }
            }
        } catch (e: Exception) { }

        if (found.isEmpty()) return emptyList()

        // 检查命中的路径是否匹配 IoC 文件路径（P2-6: RootEnvModule 接入 IocMatcher）
        val iocFamily = found.firstNotNullOfOrNull { path -> iocMatcher.matchFile(path) }
        val riskLevel = if (iocFamily != null) RiskLevel.CRITICAL else RiskLevel.HIGH
        val iocEvidence = if (iocFamily != null) mapOf("ioc_family" to iocFamily) else emptyMap<String, String>()

        return listOf(Finding(
            id = "A6-01", moduleId = id,
            title = "检测到 Root 二进制文件",
            description = "发现 Root 相关文件: ${found.joinToString()}。Root 环境大幅增加被恶意软件利用的风险。",
            riskLevel = riskLevel,
            attAckId = "T1407.001",
            confidence = if (iocFamily != null) 0.98 else 0.9,
            evidence = mapOf("root_files" to found.joinToString(", ")) + iocEvidence,
            recommendedActions = listOf("确认 Root 是否为本人操作", "如非必要，恢复原厂系统", "使用 Magisk Hide 等隐藏 Root"),
            iocHit = iocFamily != null,
            iocFamily = iocFamily,
        ))
    }

    /** A6-02: 系统分区修改（ro.build.tags） */
    private fun checkSystemMod(ctx: ScanContext): List<Finding> {
        val tags = Build.TAGS ?: ""
        val releaseKeys = tags.contains("release-keys")
        val testKeys = tags.contains("test-keys")
        if (!testKeys) return emptyList()
        return listOf(Finding(
            id = "A6-02", moduleId = id,
            title = "系统签名异常 (test-keys)",
            description = "Build.TAGS = '$tags'，使用 test-keys 而非 release-keys，系统可能被重新编译或修改。",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1407.001",
            confidence = 0.7,
            evidence = mapOf("build_tags" to tags),
            recommendedActions = listOf("确认系统是否为官方 ROM", "如非官方，考虑刷回原厂系统"),
        ))
    }

    /** A6-03: 模拟器检测 */
    private fun checkEmulator(ctx: ScanContext): List<Finding> {
        val indicators = mutableListOf<String>()
        // Build 属性
        if (Build.FINGERPRINT.contains("generic", true) ||
            Build.FINGERPRINT.contains("emulator", true)) indicators.add("fingerprint: ${Build.FINGERPRINT}")
        if (Build.MODEL.contains("Emulator", true) ||
            Build.MODEL.contains("Android SDK", true)) indicators.add("model: ${Build.MODEL}")
        if (Build.MANUFACTURER.contains("Genymotion", true) ||
            Build.MANUFACTURER.contains("unknown", true)) indicators.add("manufacturer: ${Build.MANUFACTURER}")
        if (Build.BRAND.startsWith("generic", true)) indicators.add("brand: ${Build.BRAND}")
        if (Build.PRODUCT.contains("sdk", true) ||
            Build.PRODUCT.contains("emulator", true)) indicators.add("product: ${Build.PRODUCT}")
        if (Build.HARDWARE.contains("goldfish", true) ||
            Build.HARDWARE.contains("ranchu", true)) indicators.add("hardware: ${Build.HARDWARE}")
        // 模拟器特有文件
        val emuFiles = listOf(
            "/dev/qemu_pipe", "/dev/socket/qemud", "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace", "/dev/socket/genyd",
        )
        for (f in emuFiles) { if (java.io.File(f).exists()) indicators.add("file: $f") }
        if (indicators.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A6-03", moduleId = id,
            title = "设备疑似模拟器",
            description = "检测到 ${indicators.size} 个模拟器特征: ${indicators.take(3).joinToString()}。僵尸网络可能运行在模拟器中进行批量操控。",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1417",
            confidence = 0.75,
            evidence = indicators.withIndex().associate { "indicator_${it.index}" to it.value },
            recommendedActions = listOf("确认设备是否为真机", "如在模拟器中运行，检查镜像来源"),
        ))
    }

    /** A6-04: 调试器附加 */
    private fun checkDebugger(ctx: ScanContext): List<Finding> {
        val isDebugged = android.os.Debug.isDebuggerConnected()
        if (!isDebugged) return emptyList()
        return listOf(Finding(
            id = "A6-04", moduleId = id,
            title = "检测到调试器附加",
            description = "有调试器连接到当前进程。恶意软件可能通过调试器注入代码或绕过安全检测。",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1417.001",
            confidence = 0.8,
            evidence = mapOf("debugger_connected" to "true"),
            recommendedActions = listOf("检查是否有未知的调试工具运行", "关闭 USB 调试"),
        ))
    }

    /** A6-05: Xposed 框架（含 /proc/self/maps 内存映射检测） */
    private fun checkXposed(ctx: ScanContext): List<Finding> {
        val indicators = mutableListOf<String>()
        // 检查 Xposed 包
        val xposedPkgs = listOf(
            "de.robv.android.xposed.installer",
            "de.robv.android.xposed.installer_v2",
            "org.lsposed.manager",
            "org.meowcat.edxposed.manager",
        )
        for (pkg in xposedPkgs) {
            try {
                ctx.packageManager.getPackageInfo(pkg, 0)
                indicators.add("package: $pkg")
            } catch (e: Exception) { }
        }
        // 检查 Xposed 框架文件
        val xposedFiles = listOf(
            "/system/framework/XposedBridge.jar",
            "/system/lib/libxposed_art.so",
            "/data/dalvik-cache/*/data@de.robv.android.xposed*",
        )
        for (f in xposedFiles) { if (java.io.File(f).exists()) indicators.add("file: $f") }
        // v2 增强：检查 /proc/self/maps 中的 Hook 框架内存映射
        try {
            val maps = java.io.File("/proc/self/maps")
            if (maps.exists() && maps.canRead()) {
                val mapContent = maps.readText()
                val hookIndicators = listOf(
                    "libxposed", "libriru", "libzygisk",
                    "libwhale", "libfrida", "libinject",
                )
                for (h in hookIndicators) {
                    if (mapContent.contains(h, ignoreCase = true)) {
                        indicators.add("memory_map: $h (运行时注入)")
                        break
                    }
                }
            }
        } catch (e: Exception) { }
        // 检查堆栈中是否有 Xposed
        try {
            throw Exception("stack_check")
        } catch (e: Exception) {
            for (ste in e.stackTrace) {
                if (ste.className.contains("Xposed", true) || ste.className.contains("de.robv", true)) {
                    indicators.add("stack: ${ste.className}")
                    break
                }
            }
        }
        if (indicators.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A6-05", moduleId = id,
            title = "检测到 Xposed/LSPosed 框架",
            description = "Xposed 框架可 Hook 任意应用方法，恶意软件利用它绕过安全检测或注入恶意逻辑: ${indicators.joinToString()}",
            riskLevel = RiskLevel.HIGH,
            attAckId = "T1417.001",
            confidence = 0.85,
            evidence = indicators.withIndex().associate { "indicator_${it.index}" to it.value },
            recommendedActions = listOf("确认 Xposed 模块来源可信", "检查已安装的 Xposed 模块", "如非必要，卸载 Xposed"),
        ))
    }

    /** A6-06: Frida 注入 */
    private fun checkFrida(ctx: ScanContext): List<Finding> {
        val indicators = mutableListOf<String>()
        // 检查 Frida 进程（通过 /proc 遍历）
        val procDir = java.io.File("/proc")
        procDir.listFiles()?.forEach { dir ->
            if (!dir.name.matches(Regex("\\d+"))) return@forEach
            try {
                val cmdline = java.io.File(dir, "cmdline").bufferedReader().use { it.readLine() }
                if (cmdline != null && (cmdline.contains("frida", true) || cmdline.contains("frida-server", true))) {
                    indicators.add("process: $cmdline (pid: ${dir.name})")
                }
            } catch (e: Exception) { }
        }
        // 检查 Frida 默认端口 27042 — 解析 TCP 连接按端口精确匹配（P2-4 修复）
        val tcpContent = ctx.readProcNetTcp()
        val tcpConnections = ProcNetParser.parseTcpFile(tcpContent)
        val fridaPort = 27042
        val hasFridaPort = tcpConnections.any { it.localPort == fridaPort || it.remotePort == fridaPort }
        if (hasFridaPort) {
            indicators.add("port: 27042 (frida default)")
        }
        // 检查 Frida 特有文件
        val fridaFiles = listOf(
            "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-agent",
        )
        for (f in fridaFiles) { if (java.io.File(f).exists()) indicators.add("file: $f") }
        if (indicators.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A6-06", moduleId = id,
            title = "检测到 Frida 注入工具",
            description = "Frida 可动态注入和修改任意应用行为，是高级恶意软件和攻击者的常用工具: ${indicators.joinToString()}",
            riskLevel = RiskLevel.HIGH,
            attAckId = "T1417.001",
            confidence = 0.9,
            evidence = indicators.withIndex().associate { "indicator_${it.index}" to it.value },
            recommendedActions = listOf("终止 Frida 进程", "删除 Frida 相关文件", "检查设备是否被他人接触"),
        ))
    }

    /** A6-07: SELinux 状态 */
    private fun checkSelinux(ctx: ScanContext): List<Finding> {
        // 注意：android.os.SELinux 已在 API 34 从公开 SDK 移除，
        // 改用 /sys/fs/selinux 虚拟文件系统判断（enforce=1 强制，0 宽容）
        val selinuxDir = java.io.File("/sys/fs/selinux")
        val enabled = selinuxDir.exists()
        val enforcing = try {
            java.io.File("/sys/fs/selinux/enforce").readText().trim().toIntOrNull() == 1
        } catch (e: Exception) { false }
        if (!enabled || enforcing) return emptyList()
        return listOf(Finding(
            id = "A6-07", moduleId = id,
            title = "SELinux 未处于强制模式",
            description = "SELinux 被禁用或处于宽容模式，安全边界被削弱。恶意软件可利用此状态绕过沙箱限制。",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1407.001",
            confidence = if (!enabled) 0.6 else 0.75,
            evidence = mapOf(
                "selinux_enabled" to "$enabled",
                "selinux_enforced" to "$enforcing",
            ),
            recommendedActions = listOf("恢复 SELinux 强制模式", "检查是否被 Root 工具修改"),
        ))
    }

    /** A6-08: Verified Boot 状态 */
    private fun checkVerifiedBoot(ctx: ScanContext): List<Finding> {
        // android.os.SystemProperties 是 @hide API，通过反射访问
        val state = try {
            val cls = Class.forName("android.os.SystemProperties")
            val method = cls.getMethod("get", String::class.java)
            method.invoke(null, "ro.boot.verifiedbootstate") as? String ?: ""
        } catch (e: Exception) { "" }
        if (state.isBlank() || state.equals("green", true)) return emptyList()
        val level = when {
            state.equals("yellow", true) -> RiskLevel.LOW
            state.equals("orange", true) -> RiskLevel.MEDIUM
            state.equals("red", true) -> RiskLevel.HIGH
            else -> RiskLevel.LOW
        }
        val desc = when (state.lowercase()) {
            "yellow" -> "已解锁但使用自定义密钥验证"
            "orange" -> "引导加载器已解锁，系统完整性无法保证"
            "red" -> "验证失败，系统可能被篡改"
            else -> "状态: $state"
        }
        return listOf(Finding(
            id = "A6-08", moduleId = id,
            title = "Verified Boot 状态异常 ($state)",
            description = "$desc。设备启动链完整性被破坏，恶意软件可能在启动级别持久化。",
            riskLevel = level,
            attAckId = "T1407.001",
            confidence = 0.8,
            evidence = mapOf("verified_boot_state" to state),
            recommendedActions = listOf("如非本人解锁，考虑重新锁定 Bootloader", "刷入官方系统镜像"),
        ))
    }

    /** A6-09: 运行时 Hook 框架检测（内存映射） */
    private fun checkRuntimeHooks(ctx: ScanContext): List<Finding> {
        // /proc/self/maps 是 Android 上唯一可靠的运行时 Hook 检测方法，
        // 无需 ROOT 即可读取，可检测 Zygisk/Riru/Whale 等 native hook 框架注入
        val mapsFile = java.io.File("/proc/self/maps")
        if (!mapsFile.exists() || !mapsFile.canRead()) return emptyList()

        val mapContent = try { mapsFile.readText() } catch (e: Exception) { return emptyList() }

        val hooks = mutableListOf<Pair<String, RiskLevel>>()

        // 检测 Zygisk（Magisk 的现代隐藏方案）
        var foundZygisk = false
        if (mapContent.contains("zygisk", true)) { foundZygisk = true }

        // 检测 Riru（Zygisk 前代的注入框架）
        var foundRiru = false
        if (mapContent.contains("libriru", true)) { foundRiru = true }

        // 检测 Xposed native 注入
        var foundXposed = false
        if (mapContent.contains("libxposed", true)) { foundXposed = true }

        // 检测 Whale（部分恶意软件使用）
        var foundWhale = false
        if (mapContent.contains("whale", true) && mapContent.contains("lib", true)) { foundWhale = true }

        // 检测 Frida gadget（静态注入）
        if (mapContent.contains("frida", true) && mapContent.contains("lib", true)) {
            hooks.add("Frida Gadget (静态注入)" to RiskLevel.HIGH)
        }

        // 检测内存中的 DEX 文件（动态加载）
        val dexCount = Regex("/data/app/[^/]+/base\\.apk").findAll(mapContent).count()
        // 检查是否有大量非标准内存映射
        val anonymousMaps = mapContent.lines().count { it.contains("[anon:", ignoreCase = true) }

        // 检测 inline hook 特征（可写可执行内存页）
        val rwxPages = mapContent.lines().count {
            val parts = it.trim().split("\\s+".toRegex())
            parts.size > 1 && parts[1] == "rwxp"
        }

        if (foundZygisk && foundRiru) {
            hooks.add("Riru + Zygisk 共存 (双注入)" to RiskLevel.HIGH)
        } else if (foundZygisk) {
            hooks.add("Zygisk (Magisk 隐藏方案)" to RiskLevel.MEDIUM)
        } else if (foundRiru) {
            hooks.add("Riru (进程注入框架)" to RiskLevel.MEDIUM)
        }
        if (foundXposed) {
            hooks.add("libxposed (Native Hook)" to RiskLevel.HIGH)
        }
        if (foundWhale) {
            hooks.add("Whale (Inline Hook 框架)" to RiskLevel.MEDIUM)
        }
        if (rwxPages > 3) {
            hooks.add("可写可执行内存页 (RWX, $rwxPages 页) — 潜在 shellcode 注入" to RiskLevel.MEDIUM)
        }
        if (anonymousMaps > 50) {
            hooks.add("异常匿名内存映射 ($anonymousMaps 块) — 潜在代码注入" to RiskLevel.LOW)
        }

        if (hooks.isEmpty()) return emptyList()

        val descriptions = hooks.joinToString("; ") { "${it.first}" }
        val maxRisk = hooks.maxByOrNull { it.second.ordinal }?.second ?: RiskLevel.MEDIUM
        val maxConfidence = when (maxRisk) {
            RiskLevel.HIGH -> 0.85
            RiskLevel.MEDIUM -> 0.7
            else -> 0.5
        }

        return listOf(Finding(
            id = "A6-09", moduleId = id,
            title = "检测到运行时 Hook 框架",
            description = "从 /proc/self/maps 检测到运行时注入: $descriptions。恶意软件使用 Hook 框架拦截 API 调用、隐藏自身或篡改行为。",
            riskLevel = maxRisk,
            attAckId = "T1417.001",
            confidence = maxConfidence,
            evidence = mapOf(
                "hooks_detected" to hooks.joinToString(", "),
                "rwx_pages" to "$rwxPages",
                "anonymous_maps" to "$anonymousMaps",
            ),
            recommendedActions = listOf(
                "检查设备是否被安装 Hook 框架",
                "如不是本人操作，刷入官方系统",
                "使用检测工具扫描持久化恶意软件",
            ),
        ))
    }
}
