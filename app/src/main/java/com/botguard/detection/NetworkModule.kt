package com.botguard.detection

import android.os.Build
import com.botguard.core.ScanModule
import com.botguard.core.model.Finding
import com.botguard.core.model.RiskLevel
import com.botguard.core.model.ScanContext
import com.botguard.core.model.ScanPriority
import com.botguard.intel.IocMatcher

/**
 * A7 网络审计模块 — 检测僵尸网络 C2 通信行为。
 *
 * v2 新增模块。读取 /proc/net/tcp（全局可读，无需 Root），
 * 匹配 IoC 数据库中的 C2 IP、可疑端口和 Tor 代理。
 *
 * 11 项检测：
 * A7-01 C2 IP 连接命中
 * A7-02 可疑端口连接
 * A7-03 Tor/代理端口监听
 * A7-04 异常外连数量
 * A7-05 系统代理设置
 * A7-06 VPN 活跃状态
 * A7-07 DDNS 域名相关连接
 * A7-08 IoC 进程的网络活动
 * A7-09 DNS 服务器篡改检测
 * A7-10 非标准 DNS 查询目标
 * A7-11 DGA/C2 域名命令行检测
 */
class NetworkModule(
    private val iocMatcher: IocMatcher,
) : ScanModule {
    override val id = "A7"
    override val name = "网络审计"
    override val priority = ScanPriority.HIGH

    /** TCP 连接状态码 */
    private object TcpState {
        const val ESTABLISHED = "01"
        const val SYN_SENT = "02"
        const val LISTEN = "0A"
    }

    /** /proc/net/tcp 中的一行连接 */
    data class TcpConnection(
        val localIp: String,
        val localPort: Int,
        val remoteIp: String,
        val remotePort: Int,
        val state: String,
        val uid: Int,
    )

    override suspend fun scan(ctx: ScanContext): List<Finding> {
        val tcpConnections = parseAllTcpConnections(ctx)
        val udpConnections = parseAllUdpConnections(ctx)
        val findings = mutableListOf<Finding>()
        findings.addAll(checkC2Connections(ctx, tcpConnections))
        findings.addAll(checkSuspiciousPorts(ctx, tcpConnections))
        findings.addAll(checkTorProxy(ctx, tcpConnections))
        findings.addAll(checkExcessiveConnections(ctx, tcpConnections))
        findings.addAll(checkSystemProxy(ctx))
        findings.addAll(checkVpn(ctx))
        findings.addAll(checkDdnsConnections(ctx, tcpConnections, udpConnections))
        findings.addAll(checkIocProcessNetwork(ctx, tcpConnections))
        findings.addAll(checkDnsServers(ctx))
        findings.addAll(checkAbnormalDnsTargets(ctx, udpConnections))
        findings.addAll(checkDgaAndC2Domains(ctx))
        return findings
    }

    // ════════════════════════════════════════════════════════
    //  /proc/net 解析（使用 ProcNetParser，支持 IPv4 + IPv6）
    // ════════════════════════════════════════════════════════

    private fun parseAllTcpConnections(ctx: ScanContext): List<TcpConnection> {
        val connections = mutableListOf<TcpConnection>()
        connections.addAll(ProcNetParser.parseTcpFile(ctx.readProcNetTcp()).map { it.toTcpConnection() })
        connections.addAll(ProcNetParser.parseTcpFile(ctx.readProcNetTcp6()).map { it.toTcpConnection() })
        return connections
    }

    private fun parseAllUdpConnections(ctx: ScanContext): List<TcpConnection> {
        val connections = mutableListOf<TcpConnection>()
        connections.addAll(ProcNetParser.parseTcpFile(ctx.readProcNetUdp()).map { it.toTcpConnection() })
        connections.addAll(ProcNetParser.parseTcpFile(ctx.readProcNetUdp6()).map { it.toTcpConnection() })
        return connections
    }

    /** ProcNetParser.TcpConnection → NetworkModule.TcpConnection 适配 */
    private fun ProcNetParser.TcpConnection.toTcpConnection() =
        TcpConnection(localIp, localPort, remoteIp, remotePort, state, uid)

    // ════════════════════════════════════════════════════════
    //  检测方法
    // ════════════════════════════════════════════════════════

    /** A7-01: C2 IP 连接命中 */
    private fun checkC2Connections(ctx: ScanContext, conns: List<TcpConnection>): List<Finding> {
        val established = conns.filter { it.state == TcpState.ESTABLISHED }
        val findings = mutableListOf<Finding>()
        val hitIps = mutableMapOf<String, String>()
        for (conn in established) {
            val family = iocMatcher.matchC2Ip(conn.remoteIp)
            if (family != null) {
                hitIps[conn.remoteIp] = family
            }
        }
        for ((ip, family) in hitIps) {
            val matchingConns = established.filter { it.remoteIp == ip }
            findings.add(Finding(
                id = "A7-01", moduleId = id,
                title = "检测到 C2 服务器连接: $ip",
                description = "设备正在与 $ip 建立连接，该 IP 匹配僵尸网络家族 $family 的 C2 黑名单。连接端口: ${matchingConns.map { it.remotePort }.distinct().joinToString()}",
                riskLevel = RiskLevel.CRITICAL,
                attAckId = "T1041",
                confidence = 0.97,
                evidence = mapOf(
                    "remote_ip" to ip,
                    "ioc_family" to family,
                    "ports" to matchingConns.map { it.remotePort }.distinct().joinToString(", "),
                    "connection_count" to "${matchingConns.size}",
                ),
                recommendedActions = listOf("立即断开网络", "检查并终止关联进程", "卸载恶意应用", "全盘扫描"),
                iocHit = true, iocFamily = family,
            ))
        }
        return findings
    }

    /** A7-02: 可疑端口连接 */
    private fun checkSuspiciousPorts(ctx: ScanContext, conns: List<TcpConnection>): List<Finding> {
        val suspiciousPorts = iocMatcher.getSuspiciousPorts()
        val established = conns.filter { it.state == TcpState.ESTABLISHED }
        val hits = established.filter { it.remotePort in suspiciousPorts }
        if (hits.isEmpty()) return emptyList()
        val portSummary = hits.groupBy { it.remotePort }
            .mapValues { it.value.size }
            .entries.joinToString(", ") { "${it.key}(${it.value}次)" }
        return listOf(Finding(
            id = "A7-02", moduleId = id,
            title = "发现 ${hits.size} 个可疑端口连接",
            description = "设备正在连接已知可疑端口: $portSummary。这些端口常用于 C2 通信、Tor 代理或 DDoS 控制。",
            riskLevel = RiskLevel.HIGH,
            attAckId = "T1041",
            confidence = 0.75,
            evidence = mapOf("suspicious_ports" to portSummary, "connections" to hits.take(5).joinToString { "${it.remoteIp}:${it.remotePort}" }),
            recommendedActions = listOf("检查连接的应用来源", "使用防火墙阻断这些端口"),
        ))
    }

    /** A7-03: Tor/代理端口监听 */
    private fun checkTorProxy(ctx: ScanContext, conns: List<TcpConnection>): List<Finding> {
        // Kimwolf 使用本地 23075 端口作为 Tor 代理
        val torPorts = setOf(23075, 9050, 9051, 1080, 9150)
        val listening = conns.filter { it.state == TcpState.LISTEN || it.localPort in torPorts }
        val torListening = listening.filter { it.localPort in torPorts }
        if (torListening.isEmpty()) return emptyList()
        return listOf(Finding(
            id = "A7-03", moduleId = id,
            title = "检测到 Tor/代理端口监听",
            description = "本地端口 ${torListening.map { it.localPort }.distinct().joinToString()} 正在监听，可能运行 Tor 代理或 SOCKS5 代理。僵尸网络家族 Kimwolf 使用 23075 端口运行 Tor 代理。",
            riskLevel = RiskLevel.HIGH,
            attAckId = "T1090",
            confidence = 0.85,
            evidence = mapOf("tor_ports" to torListening.map { it.localPort }.distinct().joinToString(", ")),
            recommendedActions = listOf("检查是否有 Tor 或代理应用", "终止不明监听进程", "检查 /data/local/tmp/ 下的可执行文件"),
        ))
    }

    /** A7-04: 异常外连数量 */
    private fun checkExcessiveConnections(ctx: ScanContext, conns: List<TcpConnection>): List<Finding> {
        val established = conns.filter { it.state == TcpState.ESTABLISHED }
        // 排除本地/私有地址（RFC 1918 + loopback + link-local）
        val external = established.filter { !ProcNetParser.isPrivateIp(it.remoteIp) }
        if (external.size <= 30) return emptyList()
        // 按 UID 分组
        val byUid = external.groupBy { it.uid }
        val topUid = byUid.maxByOrNull { it.value.size }
        return listOf(Finding(
            id = "A7-04", moduleId = id,
            title = "异常外连数量 (${external.size} 个连接)",
            description = "当前有 ${external.size} 个活跃外部 TCP 连接，数量偏多。僵尸网络常维持大量 C2 连接或参与 DDoS 攻击。${topUid?.let { "UID ${it.key} 占 ${it.value.size} 个" } ?: ""}",
            riskLevel = RiskLevel.MEDIUM,
            attAckId = "T1041",
            confidence = 0.5,
            evidence = mapOf(
                "total_established" to "${external.size}",
                "top_uid" to "${topUid?.key ?: -1}",
                "top_uid_count" to "${topUid?.value?.size ?: 0}",
            ),
            recommendedActions = listOf("检查哪个应用产生了大量连接", "使用网络监控工具排查"),
        ))
    }

    /** A7-05: 系统代理设置 */
    private fun checkSystemProxy(ctx: ScanContext): List<Finding> {
        val proxyHost = try { System.getProperty("http.proxyHost") } catch (e: Exception) { null }
        val proxyPort = try { System.getProperty("http.proxyPort") } catch (e: Exception) { null }
        if (proxyHost.isNullOrBlank()) return emptyList()
        return listOf(Finding(
            id = "A7-05", moduleId = id,
            title = "系统代理已设置",
            description = "HTTP 代理设置为 $proxyHost:$proxyPort。僵尸网络可能通过代理拦截所有网络流量。",
            riskLevel = RiskLevel.LOW,
            attAckId = "T1090",
            confidence = 0.5,
            evidence = mapOf("proxy_host" to (proxyHost ?: ""), "proxy_port" to (proxyPort ?: "")),
            recommendedActions = listOf("在 WiFi 设置中检查代理", "如非本人设置，清除代理"),
        ))
    }

    /** A7-06: VPN 活跃状态 */
    private fun checkVpn(ctx: ScanContext): List<Finding> {
        val cm = ctx.connectivityManager
        val vpnActive = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                cm.activeNetwork?.let { network ->
                    cm.getNetworkCapabilities(network)?.hasTransport(
                        android.net.NetworkCapabilities.TRANSPORT_VPN
                    ) == true
                } ?: false
            } else false
        } catch (e: Exception) { false }
        if (!vpnActive) return emptyList()
        return listOf(Finding(
            id = "A7-06", moduleId = id,
            title = "VPN 连接活跃",
            description = "设备当前通过 VPN 连接网络。僵尸网络可能通过 VPN 拦截和篡改所有流量。",
            riskLevel = RiskLevel.LOW,
            attAckId = "T1090",
            confidence = 0.3,
            evidence = mapOf("vpn_active" to "true"),
            recommendedActions = listOf("确认 VPN 应用是否可信", "在设置 → VPN 中检查"),
        ))
    }

    /** A7-07: 异常 DNS 查询（检查 UDP 53 端口，DNS 主要走 UDP） */
    private fun checkDdnsConnections(ctx: ScanContext, tcpConns: List<TcpConnection>, udpConns: List<TcpConnection>): List<Finding> {
        // DNS 主要使用 UDP 端口 53，/proc/net/udp 包含 UDP 连接
        val udpDnsConns = udpConns.filter { it.remotePort == 53 && !ProcNetParser.isPrivateIp(it.remoteIp) }
        // 也检查 TCP 53（DNS-over-TCP，较少见但存在于区域传输/大响应/DoT）
        val tcpDnsConns = tcpConns.filter { it.remotePort == 53 && it.state == TcpState.ESTABLISHED && !ProcNetParser.isPrivateIp(it.remoteIp) }
        val allDnsConns = udpDnsConns + tcpDnsConns
        if (allDnsConns.size <= 5) return emptyList()
        val distinctDns = allDnsConns.map { it.remoteIp }.distinct()
        return listOf(Finding(
            id = "A7-07", moduleId = id,
            title = "异常 DNS 查询 (${allDnsConns.size} 连接, ${distinctDns.size} 个 DNS 服务器)",
            description = "设备向 ${distinctDns.size} 个不同 DNS 服务器发起查询（UDP ${udpDnsConns.size} + TCP ${tcpDnsConns.size}）。僵尸网络可能使用 DGA 域名或自定义 DNS 来隐藏 C2。DNS 服务器: ${distinctDns.take(3).joinToString()}",
            riskLevel = RiskLevel.LOW,
            attAckId = "T1071.004",
            confidence = 0.35,
            evidence = mapOf(
                "udp_dns_connections" to "${udpDnsConns.size}",
                "tcp_dns_connections" to "${tcpDnsConns.size}",
                "distinct_dns_servers" to "${distinctDns.size}",
                "dns_ips" to distinctDns.take(5).joinToString(", "),
            ),
            recommendedActions = listOf("检查 DNS 设置是否被篡改", "确认 DNS 服务器为可信地址"),
        ))
    }

    /** A7-08: IoC 进程的网络活动（使用 ScanContext 缓存，与 A5-07 共享 /proc 遍历） */
    private fun checkIocProcessNetwork(ctx: ScanContext, conns: List<TcpConnection>): List<Finding> {
        // 使用缓存的 /proc 遍历结果，与 A5-07 共享
        val procEntries = ctx.getProcEntries()
        val iocProcUids = mutableMapOf<String, Int>() // process name → uid
        for (entry in procEntries) {
            val family = iocMatcher.matchProcess(entry.processName)
            if (family != null) {
                iocProcUids["${entry.processName} ($family)"] = entry.uid
            }
        }
        if (iocProcUids.isEmpty()) return emptyList()
        // 检查这些 UID 是否有网络连接
        val findings = mutableListOf<Finding>()
        for ((procInfo, uid) in iocProcUids) {
            val procConns = conns.filter { it.uid == uid && it.state == TcpState.ESTABLISHED }
            if (procConns.isNotEmpty()) {
                findings.add(Finding(
                    id = "A7-08", moduleId = id,
                    title = "IoC 进程有活跃网络连接: $procInfo",
                    description = "匹配 IoC 的进程 $procInfo 有 ${procConns.size} 个活跃 TCP 连接。连接目标: ${procConns.take(3).joinToString { "${it.remoteIp}:${it.remotePort}" }}",
                    riskLevel = RiskLevel.CRITICAL,
                    attAckId = "T1041",
                    confidence = 0.95,
                    evidence = mapOf(
                        "process" to procInfo,
                        "uid" to "$uid",
                        "connections" to procConns.take(5).joinToString { "${it.remoteIp}:${it.remotePort}" },
                    ),
                    recommendedActions = listOf("立即终止该进程", "断开网络", "卸载关联应用", "全盘扫描"),
                    iocHit = true,
                ))
            }
        }
        return findings
    }

    // ════════════════════════════════════════════════════════
    //  知名公共 DNS 服务器列表
    // ════════════════════════════════════════════════════════

    companion object {
        private val KNOWN_PUBLIC_DNS = setOf(
            "8.8.8.8", "8.8.4.4",                    // Google
            "1.1.1.1", "1.0.0.1",                    // Cloudflare
            "114.114.114.114", "114.114.115.115",    // 114DNS
            "223.5.5.5", "223.6.6.6",                // AliDNS
            "180.76.76.76",                           // BaiduDNS
            "208.67.222.222", "208.67.220.220",       // OpenDNS
            "9.9.9.9", "149.112.112.112",            // Quad9
            "208.67.222.123", "208.67.220.123",       // OpenDNS FamilyShield
            "185.228.168.9", "185.228.169.9",         // CleanBrowsing
            "76.76.19.19", "76.76.19.19",             // Alternative DNS
            // IPv6 公共 DNS
            "2001:4860:4860::8888", "2001:4860:4860::8844",
            "2606:4700:4700::1111", "2606:4700:4700::1001",
            "2620:fe::fe", "2620:fe::9",
        )
    }

    /** A7-09: DNS 服务器篡改检测 */
    private fun checkDnsServers(ctx: ScanContext): List<Finding> {
        val dnsServers = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val activeNetwork = ctx.connectivityManager.activeNetwork
                if (activeNetwork != null) {
                    val lp = ctx.connectivityManager.getLinkProperties(activeNetwork)
                    lp?.dnsServers?.map { it.hostAddress }
                } else null
            } else null
        } catch (e: Exception) { null } ?: return emptyList()

        if (dnsServers.isEmpty()) return emptyList()

        val findings = mutableListOf<Finding>()
        val unknownDns = mutableListOf<String>()
        val suspiciousDns = mutableListOf<String>()

        for (dns in dnsServers) {
            when {
                // 私有地址或本地地址 — 可能被本地恶意程序劫持
                ProcNetParser.isPrivateIp(dns) -> suspiciousDns.add("$dns (私有地址)")
                // 非知名公共 DNS
                dns !in KNOWN_PUBLIC_DNS -> unknownDns.add(dns)
            }
        }

        // 可疑 DNS：私有地址
        if (suspiciousDns.isNotEmpty()) {
            findings.add(Finding(
                id = "A7-09a", moduleId = id,
                title = "检测到可疑 DNS 服务器",
                description = "系统 DNS 服务器指向私有/本地地址: ${suspiciousDns.joinToString()}。可能被恶意软件劫持实现 DNS 重定向。",
                riskLevel = RiskLevel.HIGH,
                attAckId = "T1071.004",
                confidence = 0.85,
                evidence = mapOf(
                    "suspicious_dns" to suspiciousDns.joinToString(", "),
                    "all_dns_servers" to dnsServers.joinToString(", "),
                ),
                recommendedActions = listOf("检查 DNS 设置是否被篡改", "重置网络设置", "重启路由器"),
            ))
        }

        // 未知 DNS（非知名公共 DNS）
        if (unknownDns.isNotEmpty()) {
            val risk = when {
                unknownDns.size >= 3 -> RiskLevel.MEDIUM
                else -> RiskLevel.LOW
            }
            findings.add(Finding(
                id = "A7-09b", moduleId = id,
                title = "使用非标准 DNS 服务器",
                description = "系统 DNS 服务器 ${unknownDns.joinToString()} 不在知名公共 DNS 列表内。自定义 DNS 可能被用于域名劫持或流量拦截。",
                riskLevel = risk,
                attAckId = "T1071.004",
                confidence = 0.45,
                evidence = mapOf(
                    "unknown_dns" to unknownDns.joinToString(", "),
                    "all_dns_servers" to dnsServers.joinToString(", "),
                ),
                recommendedActions = listOf("核实 DNS 服务器是否可信", "如不确定，改回公共 DNS"),
            ))
        }

        return findings
    }

    /** A7-10: 非标准 DNS 查询目标 */
    private fun checkAbnormalDnsTargets(ctx: ScanContext, udpConns: List<TcpConnection>): List<Finding> {
        // 获取系统 DNS 服务器列表
        val systemDnsIps = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val activeNetwork = ctx.connectivityManager.activeNetwork
                if (activeNetwork != null) {
                    ctx.connectivityManager.getLinkProperties(activeNetwork)
                        ?.dnsServers?.map { it.hostAddress }?.toSet()
                } else null
            } else null
        } catch (e: Exception) { null } ?: emptySet()

        // 从 UDP 连接中提取所有到 53 端口的远程 IP
        val dnsTargets = udpConns
            .filter { it.remotePort == 53 }
            .map { it.remoteIp }
            .distinct()
            .toSet()

        if (dnsTargets.isEmpty()) return emptyList()

        // 检查是否有连接了 53 端口但不在系统 DNS 列表中的 IP
        val abnormalTargets = dnsTargets - systemDnsIps
        if (abnormalTargets.isEmpty()) return emptyList()

        // 进一步分类：连接到的 DNS 服务器是否是公共 DNS、私有地址、或完全未知
        val suspiciousTargets = mutableListOf<String>()
        val knownTargets = mutableListOf<String>()

        for (target in abnormalTargets) {
            when {
                ProcNetParser.isPrivateIp(target) -> suspiciousTargets.add("$target (私有 DNS)")
                target in KNOWN_PUBLIC_DNS -> knownTargets.add(target)
                else -> suspiciousTargets.add(target)
            }
        }

        val findings = mutableListOf<Finding>()

        if (suspiciousTargets.isNotEmpty()) {
            findings.add(Finding(
                id = "A7-10a", moduleId = id,
                title = "发现向非系统 DNS 发送查询",
                description = "设备向非系统 DNS 服务器发送 DNS 查询: ${suspiciousTargets.joinToString("; ")}。可能表示恶意软件使用自定义 DNS 解析 DGA 域名或绕过监控。",
                riskLevel = RiskLevel.MEDIUM,
                attAckId = "T1071.004",
                confidence = 0.65,
                evidence = mapOf(
                    "abnormal_dns_targets" to suspiciousTargets.joinToString(", "),
                    "system_dns" to systemDnsIps.joinToString(", "),
                    "all_dns_targets" to (dnsTargets - systemDnsIps).joinToString(", "),
                ),
                recommendedActions = listOf("检查哪些应用发送了异常 DNS 查询", "使用抓包工具分析 DNS 流量", "确认 DNS 查询来源"),
            ))
        }

        if (knownTargets.isNotEmpty()) {
            findings.add(Finding(
                id = "A7-10b", moduleId = id,
                title = "发现绕过系统 DNS 的直连查询",
                description = "设备绕过系统 DNS 直接向公共 DNS 服务器 ${knownTargets.joinToString()} 发送查询。可能表示恶意应用使用硬编码 DNS 规避监控。",
                riskLevel = RiskLevel.LOW,
                attAckId = "T1071.004",
                confidence = 0.35,
                evidence = mapOf(
                    "direct_dns_targets" to knownTargets.joinToString(", "),
                    "system_dns" to systemDnsIps.joinToString(", "),
                ),
                recommendedActions = listOf("检查应用是否有硬编码 DNS", "确认是否为 VPN/代理应用的正常行为"),
            ))
        }

        return findings
    }

    /**
     * A7-11: DGA / C2 域名命令行检测。
     *
     * 进程命令行（/proc/<pid>/cmdline）中若硬编码了 C2 域名、DGA 随机域名或
     * DDNS 域名，是僵尸网络下载器/样本的典型特征。本检测复用已加载的
     * IocMatcher.matchDomain()，对每条进程命令行的域名形态 token 做精确匹配，
     * 仅当命中时才产出 Finding（高精度、低误报）。
     */
    private fun checkDgaAndC2Domains(ctx: ScanContext): List<Finding> {
        val procEntries = ctx.getProcEntries()
        val c2Hits = mutableListOf<String>()   // "domain (family) @ process"
        val dgaHits = mutableListOf<String>()
        val ddnsHits = mutableListOf<String>()

        for (entry in procEntries) {
            val tokens = entry.processName
                .split(Regex("[\\s\\u0000]+"))
                .map { it.trim().trim('\u0000') }
                .filter { it.length in 4..255 && looksLikeDomain(it) }
            for (token in tokens) {
                val match = try { iocMatcher.matchDomain(token) } catch (e: Exception) { null }
                when (match) {
                    null -> { /* 非已知 C2 / DGA / DDNS 域名 */ }
                    "DGA" -> dgaHits.add("$token @ ${entry.processName.take(40)}")
                    "DDNS" -> ddnsHits.add("$token @ ${entry.processName.take(40)}")
                    else -> c2Hits.add("$token ($match) @ ${entry.processName.take(40)}")
                }
            }
        }

        val findings = mutableListOf<Finding>()
        if (c2Hits.isNotEmpty()) {
            findings.add(Finding(
                id = "A7-11a", moduleId = id,
                title = "进程命令行包含已知 C2 域名",
                description = "在进程命令行中发现匹配僵尸网络家族 C2 的域名：${c2Hits.take(5).joinToString("; ")}。这通常意味着恶意样本在启动参数中硬编码了 C2 地址。",
                riskLevel = RiskLevel.CRITICAL,
                attAckId = "T1071.004",
                confidence = 0.92,
                evidence = mapOf("c2_domains" to c2Hits.joinToString("; ")),
                recommendedActions = listOf("立即终止相关进程", "卸载关联应用", "断开网络并全盘扫描"),
                iocHit = true,
            ))
        }
        if (dgaHits.isNotEmpty()) {
            findings.add(Finding(
                id = "A7-11b", moduleId = id,
                title = "检测到 DGA 域名生成算法特征",
                description = "进程命令行中出现符合 DGA 模式的随机域名：${dgaHits.take(5).joinToString("; ")}。僵尸网络常用 DGA 动态生成 C2 域名以规避封禁。",
                riskLevel = RiskLevel.HIGH,
                attAckId = "T1071.004",
                confidence = 0.8,
                evidence = mapOf("dga_domains" to dgaHits.joinToString("; ")),
                recommendedActions = listOf("分析进程来源与父进程", "隔离设备并离线取证"),
            ))
        }
        if (ddnsHits.isNotEmpty()) {
            findings.add(Finding(
                id = "A7-11c", moduleId = id,
                title = "进程使用 DDNS 动态域名",
                description = "进程命令行中出现动态 DNS (DDNS) 域名：${ddnsHits.take(5).joinToString("; ")}。僵尸网络常利用 DDNS 提供弹性 C2 地址，规避 IP 封禁。",
                riskLevel = RiskLevel.LOW,
                attAckId = "T1071.004",
                confidence = 0.4,
                evidence = mapOf("ddns_domains" to ddnsHits.joinToString("; ")),
                recommendedActions = listOf("确认进程是否为已知可信应用"),
            ))
        }
        return findings
    }

    /** 判断 token 是否像域名（而非 IP / 路径 / 端口 / 命令行参数） */
    private fun looksLikeDomain(token: String): Boolean {
        if (!token.contains('.')) return false
        if (token.contains('/') || token.contains('@') || token.contains(':')) return false
        if (token.startsWith("-") || token.startsWith(".")) return false
        if (!token.any { it.isLetter() }) return false
        // 排除纯 IPv4 地址
        if (Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(token)) return false
        return true
    }
}
