package com.botguard.intel

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

/**
 * IoC 匹配器 — v2 核心改进：从 assets 加载全部 JSON 情报，
 * 提供统一的查询接口，被所有检测模块实际调用。
 *
 * 加载的资产：
 * - assets/ioc/ 目录下的 JSON 文件        → 6 家族 IoC（C2 IP / 域名 / 进程 / 文件 / APK 包名）
 * - assets/ioc/c2-ip-blocklist.json → 通用 C2 IP 段 + 可疑端口 + DDNS 域名
 * - assets/ioc/dga-patterns.json    → DGA 正则 + 熵值阈值
 * - assets/whitelist/ 目录下的 JSON 文件    → 系统应用 / 无图标应用 / 高耗电应用白名单
 */
class IocMatcher private constructor(context: Context) {

    // ── C2 IP ──────────────────────────────────────────────
    /** 精确 IP → 命中的家族 */
    private val exactIps = ConcurrentHashMap<String, String>()
    /** CIDR 网段列表 (network, prefix, family) */
    private val cidrBlocks = mutableListOf<Triple<UInt, Int, String>>()

    // ── C2 域名 ────────────────────────────────────────────
    private val exactDomains = ConcurrentHashMap<String, String>()
    private val wildcardDomains = mutableListOf<Pair<String, String>>() // pattern → family

    // ── 恶意进程名 ─────────────────────────────────────────
    private val maliciousProcesses = ConcurrentHashMap<String, String>()

    // ── 恶意 APK 包名 ──────────────────────────────────────
    private val maliciousPackages = ConcurrentHashMap<String, String>()

    // ── 恶意文件路径 ───────────────────────────────────────
    private val maliciousFiles = ConcurrentHashMap<String, String>()

    // ── 可疑端口 ───────────────────────────────────────────
    private val suspiciousPorts = mutableSetOf<Int>()

    // ── DDNS 域名模式 ──────────────────────────────────────
    private val ddnsPatterns = mutableListOf<String>()

    // ── DGA 正则 ───────────────────────────────────────────
    private val dgaRegexes = mutableListOf<Regex>()
    private val dgaEntropyThreshold = 3.5
    private val benignHighEntropyDomains = mutableSetOf<String>()

    // ── 白名单 ─────────────────────────────────────────────
    private val systemAppWhitelist = mutableSetOf<String>()
    private val noIconAppWhitelist = mutableSetOf<String>()
    private val highPowerAppWhitelist = mutableSetOf<String>()

    init {
        loadAll(context)
    }

    private fun loadAll(context: Context) {
        loadFamilyIocs(context)
        loadC2Blocklist(context)
        loadDgaPatterns(context)
        loadWhitelists(context)
    }

    // ════════════════════════════════════════════════════════
    //  加载方法
    // ════════════════════════════════════════════════════════

    private fun loadFamilyIocs(context: Context) {
        val files = listOf(
            "kimwolf_ioc.json", "vo1d_ioc.json", "btmob_ioc.json",
            "rafel_ioc.json", "anubis_ioc.json", "cerberus_ioc.json"
        )
        for (file in files) {
            val json = readAsset(context, "ioc/$file") ?: continue
            val family = json.optString("family", file.substringBefore("_"))
            // C2 域名
            json.optJSONArray("c2_domains")?.forEachString { domain ->
                exactDomains[domain.lowercase()] = family
            }
            // 区块链域名
            json.optJSONArray("blockchain_domains")?.forEachString { domain ->
                exactDomains[domain.lowercase()] = family
            }
            // C2 IP（精确）
            json.optJSONArray("c2_ips")?.forEachString { ip ->
                exactIps[ip.trim()] = family
            }
            json.optJSONArray("downloader_ips")?.forEachString { ip ->
                exactIps[ip.trim()] = family
            }
            // 进程名
            json.optJSONArray("processes")?.forEachString { proc ->
                maliciousProcesses[proc.trim()] = family
            }
            // 恶意 APK 包名
            json.optJSONArray("malicious_apk_packages")?.forEachString { pkg ->
                maliciousPackages[pkg.trim()] = family
            }
            // 恶意文件路径
            json.optJSONArray("files")?.forEachString { path ->
                maliciousFiles[path.trim()] = family
            }
            json.optJSONArray("system_partition_files")?.forEachString { path ->
                maliciousFiles[path.trim()] = family
            }
            json.optJSONArray("install_paths")?.forEachString { path ->
                maliciousFiles[path.trim()] = family
            }
        }
    }

    private fun loadC2Blocklist(context: Context) {
        val json = readAsset(context, "ioc/c2-ip-blocklist.json") ?: return
        json.optJSONArray("c2_ips")?.forEachObject { obj ->
            val ipSpec = obj.getString("ip")
            val family = obj.optString("family", "Generic")
            if (ipSpec.contains("/")) {
                // CIDR
                val parts = ipSpec.split("/")
                val network = ipToInt(parts[0])
                val prefix = parts[1].toInt()
                if (network != null) cidrBlocks.add(Triple(network, prefix, family))
            } else {
                exactIps[ipSpec] = family
            }
        }
        json.optJSONArray("suspicious_ports")?.forEachInt { port ->
            suspiciousPorts.add(port)
        }
        json.optJSONArray("ddns_domains")?.forEachString { pattern ->
            ddnsPatterns.add(pattern)
        }
    }

    private fun loadDgaPatterns(context: Context) {
        val json = readAsset(context, "ioc/dga-patterns.json") ?: return
        json.optJSONArray("regex_patterns")?.forEachObject { obj ->
            val pattern = obj.getString("pattern")
            dgaRegexes.add(Regex(pattern, RegexOption.IGNORE_CASE))
        }
        json.optJSONArray("benign_high_entropy_domains")?.forEachString { domain ->
            benignHighEntropyDomains.add(domain.lowercase())
        }
    }

    private fun loadWhitelists(context: Context) {
        readAsset(context, "whitelist/android-system-apps.json")?.let { json ->
            json.optJSONArray("google_apps")?.forEachString { systemAppWhitelist.add(it) }
            json.optJSONArray("aosp_system_apps")?.forEachString { systemAppWhitelist.add(it) }
            json.optJSONObject("vendor_apps")?.keys()?.forEach { vendor ->
                json.getJSONObject("vendor_apps").getJSONArray(vendor).forEachString {
                    systemAppWhitelist.add(it)
                }
            }
        }
        readAsset(context, "whitelist/android-no-icon-apps.json")?.let { json ->
            json.optJSONArray("no_icon_apps")?.forEachObject { obj ->
                noIconAppWhitelist.add(obj.getString("package"))
            }
        }
        readAsset(context, "whitelist/android-high-power-apps.json")?.let { json ->
            json.optJSONArray("high_power_apps")?.forEachObject { obj ->
                highPowerAppWhitelist.add(obj.getString("package"))
            }
        }
    }

    // ════════════════════════════════════════════════════════
    //  查询接口 — 被检测模块调用
    // ════════════════════════════════════════════════════════

    /** 检查 IP 是否命中 C2 黑名单，返回家族名或 null */
    fun matchC2Ip(ip: String): String? {
        exactIps[ip]?.let { return it }
        val ipInt = ipToInt(ip) ?: return null
        for ((network, prefix, family) in cidrBlocks) {
            val mask = if (prefix == 0) 0u else (0xFFFFFFFFu shl (32 - prefix))
            if ((ipInt and mask) == (network and mask)) return family
        }
        return null
    }

    /** 检查域名是否命中 C2 或 DGA，返回家族名或 "DGA" 或 null */
    fun matchDomain(domain: String): String? {
        val lower = domain.lowercase()
        exactDomains[lower]?.let { return it }
        // DDNS 匹配
        for (pattern in ddnsPatterns) {
            if (pattern.startsWith("*.")) {
                val suffix = pattern.substring(1) // ".ddns.net"
                if (lower.endsWith(suffix)) return "DDNS"
            }
        }
        // DGA 正则匹配
        if (lower !in benignHighEntropyDomains) {
            for (regex in dgaRegexes) {
                if (regex.matches(lower)) return "DGA"
            }
        }
        return null
    }

    /** 检查进程名是否为已知恶意进程 */
    fun matchProcess(processName: String): String? {
        val name = processName.substringAfterLast('/')
        maliciousProcesses[name]?.let { return it }
        maliciousProcesses[processName]?.let { return it }
        return null
    }

    /** 检查 APK 包名是否为已知恶意包 */
    fun matchPackage(packageName: String): String? = maliciousPackages[packageName]

    /** 检查文件路径是否为已知恶意文件 */
    fun matchFile(filePath: String): String? = maliciousFiles[filePath]

    /** 检查端口是否为可疑端口 */
    fun isSuspiciousPort(port: Int): Boolean = port in suspiciousPorts

    /** 获取全部可疑端口列表 */
    fun getSuspiciousPorts(): Set<Int> = suspiciousPorts.toSet()

    // ── 白名单查询 ──
    fun isSystemApp(packageName: String): Boolean = packageName in systemAppWhitelist
    fun isNoIconApp(packageName: String): Boolean = packageName in noIconAppWhitelist
    fun isHighPowerApp(packageName: String): Boolean = packageName in highPowerAppWhitelist

    // ════════════════════════════════════════════════════════
    //  辅助方法
    // ════════════════════════════════════════════════════════

    private fun readAsset(context: Context, path: String): JSONObject? = try {
        val text = context.assets.open(path).bufferedReader().use { it.readText() }
        JSONObject(text)
    } catch (e: Exception) { null }

    private fun ipToInt(ip: String): UInt? {
        return try {
            val parts = ip.split(".")
            if (parts.size != 4) return null
            (parts[0].toUInt() shl 24) or (parts[1].toUInt() shl 16) or
                (parts[2].toUInt() shl 8) or parts[3].toUInt()
        } catch (e: Exception) { null }
    }

    // JSON 扩展函数
    private fun JSONArray?.forEachString(block: (String) -> Unit) {
        this?.let { for (i in 0 until it.length()) block(it.getString(i)) }
    }
    private fun JSONArray?.forEachInt(block: (Int) -> Unit) {
        this?.let { for (i in 0 until it.length()) block(it.getInt(i)) }
    }
    private fun JSONArray?.forEachObject(block: (JSONObject) -> Unit) {
        this?.let { for (i in 0 until it.length()) block(it.getJSONObject(i)) }
    }

    companion object {
        @Volatile private var instance: IocMatcher? = null

        fun get(context: Context): IocMatcher {
            return instance ?: synchronized(this) {
                instance ?: IocMatcher(context.applicationContext).also { instance = it }
            }
        }

        /** 重置单例（仅用于测试） */
        fun reset() {
            instance = null
        }

        /** 统计信息（调试用） */
        fun stats(): String {
            val i = instance ?: return "not initialized"
            return buildString {
                appendLine("IocMatcher 统计:")
                appendLine("  精确 C2 IP: ${i.exactIps.size}")
                appendLine("  CIDR 网段: ${i.cidrBlocks.size}")
                appendLine("  C2 域名: ${i.exactDomains.size}")
                appendLine("  恶意进程: ${i.maliciousProcesses.size}")
                appendLine("  恶意包名: ${i.maliciousPackages.size}")
                appendLine("  恶意文件: ${i.maliciousFiles.size}")
                appendLine("  可疑端口: ${i.suspiciousPorts.size}")
                appendLine("  DDNS 模式: ${i.ddnsPatterns.size}")
                appendLine("  DGA 正则: ${i.dgaRegexes.size}")
                appendLine("  系统应用白名单: ${i.systemAppWhitelist.size}")
                appendLine("  无图标白名单: ${i.noIconAppWhitelist.size}")
                appendLine("  高耗电白名单: ${i.highPowerAppWhitelist.size}")
            }
        }
    }
}
