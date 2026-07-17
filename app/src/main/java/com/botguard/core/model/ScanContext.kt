package com.botguard.core.model

import android.app.ActivityManager
import android.app.AppOpsManager
import android.app.usage.NetworkStatsManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.os.Build
import android.os.PowerManager

/**
 * 扫描上下文，封装所有检测模块共用的系统服务引用。
 * 在扫描开始时创建一次，所有模块共享。
 * 缓存耗时的 IPC 调用结果（getInstalledApplications / /proc 遍历）。
 */
class ScanContext(val appContext: Context, val runMode: RunMode) {

    val contentResolver get() = appContext.contentResolver
    val packageManager: PackageManager get() = appContext.packageManager
    val keyguardManager: android.app.KeyguardManager get()
        = appContext.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
    val activityManager: ActivityManager get()
        = appContext.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    val powerManager: PowerManager get()
        = appContext.getSystemService(Context.POWER_SERVICE) as PowerManager
    val connectivityManager: ConnectivityManager get()
        = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val usageStatsManager: UsageStatsManager? get()
        = appContext.getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager
    val networkStatsManager: NetworkStatsManager? get()
        = appContext.getSystemService(Context.NETWORK_STATS_SERVICE) as? NetworkStatsManager
    val appOpsManager: AppOpsManager get()
        = appContext.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
    val locationManager: LocationManager get()
        = appContext.getSystemService(Context.LOCATION_SERVICE) as LocationManager

    // ════════════════════════════════════════════════════════
    //  缓存：消除重复 IPC 调用（P1-8）
    // ════════════════════════════════════════════════════════

    /** 缓存已安装应用列表（A2/A3/A5 各调用一次 → 合并为一次） */
    @Volatile private var cachedInstalledApps: List<ApplicationInfo>? = null
    fun getInstalledApplications(): List<ApplicationInfo> {
        return cachedInstalledApps ?: synchronized(this) {
            cachedInstalledApps ?: try {
                packageManager.getInstalledApplications(0)
            } catch (e: Exception) { emptyList() }.also { cachedInstalledApps = it }
        }
    }

    /** 缓存已安装包信息（A2 使用 GET_PERMISSIONS|GET_SERVICES） */
    @Volatile private var cachedInstalledPackages: List<PackageInfo>? = null
    fun getInstalledPackages(): List<PackageInfo> {
        return cachedInstalledPackages ?: synchronized(this) {
            cachedInstalledPackages ?: try {
                packageManager.getInstalledPackages(
                    PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
                )
            } catch (e: Exception) { emptyList() }.also { cachedInstalledPackages = it }
        }
    }

    /** /proc 遍历结果缓存（A5-07 和 A7-08 共享，消除重复遍历） */
    data class ProcEntry(val pid: String, val processName: String, val uid: Int)
    @Volatile private var cachedProcEntries: List<ProcEntry>? = null
    fun getProcEntries(): List<ProcEntry> {
        return cachedProcEntries ?: synchronized(this) {
            cachedProcEntries ?: scanProcDir().also { cachedProcEntries = it }
        }
    }

    private fun scanProcDir(): List<ProcEntry> {
        val result = mutableListOf<ProcEntry>()
        val procDir = java.io.File("/proc")
        procDir.listFiles()?.forEach { dir ->
            if (!dir.name.matches(Regex("\\d+"))) return@forEach
            try {
                val cmdline = java.io.File(dir, "cmdline").bufferedReader().use { it.readLine() }
                if (cmdline != null && cmdline.isNotBlank()) {
                    val procName = cmdline.trim('\u0000')
                    val statusFile = java.io.File(dir, "status")
                    val uid = try {
                        statusFile.bufferedReader().useLines { lines ->
                            lines.firstOrNull { it.startsWith("Uid:") }
                                ?.split(Regex("\\s+"))
                                ?.getOrNull(1)
                                ?.toIntOrNull() ?: -1
                        }
                    } catch (e: Exception) { -1 }
                    result.add(ProcEntry(dir.name, procName, uid))
                }
            } catch (e: Exception) { }
        }
        return result
    }

    /** 是否拥有 PACKAGE_USAGE_STATS 权限 */
    fun hasUsageStatsPermission(): Boolean {
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            appOpsManager.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(),
                appContext.packageName
            )
        } else {
            @Suppress("DEPRECATION")
            appOpsManager.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                android.os.Process.myUid(),
                appContext.packageName
            )
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    /** 读取 /proc/net/tcp 原始内容（对所有进程可读） */
    fun readProcNetTcp(): String = try {
        java.io.File("/proc/net/tcp").bufferedReader().use { it.readText() }
    } catch (e: Exception) { "" }

    fun readProcNetTcp6(): String = try {
        java.io.File("/proc/net/tcp6").bufferedReader().use { it.readText() }
    } catch (e: Exception) { "" }

    /** 读取 /proc/stat（CPU 信息，全局可读） */
    fun readProcStat(): String = try {
        java.io.File("/proc/stat").bufferedReader().use { it.readText() }
    } catch (e: Exception) { "" }

    /** 读取 /proc/loadavg（1/5/15 分钟平均负载，全局可读） */
    fun readProcLoadavg(): String = try {
        java.io.File("/proc/loadavg").bufferedReader().use { it.readLine() ?: "" }
    } catch (e: Exception) { "" }

    /** 获取 CPU 核心数 */
    fun readCpuCount(): Int = try {
        java.io.File("/proc/cpuinfo").bufferedReader().use { reader ->
            reader.lineSequence().count { it.startsWith("processor") }.coerceAtLeast(1)
        }
    } catch (e: Exception) { 1 }

    /** 读取 /proc/net/udp（UDP 连接，全局可读） */
    fun readProcNetUdp(): String = try {
        java.io.File("/proc/net/udp").bufferedReader().use { it.readText() }
    } catch (e: Exception) { "" }

    /** 读取 /proc/net/udp6（IPv6 UDP 连接，全局可读） */
    fun readProcNetUdp6(): String = try {
        java.io.File("/proc/net/udp6").bufferedReader().use { it.readText() }
    } catch (e: Exception) { "" }
}
