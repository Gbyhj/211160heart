package com.botguard.detection

/**
 * /proc/net/tcp 解析工具 — 从 hex 格式提取 IP 地址和端口。
 *
 * 纯 Kotlin 实现，无 Android 依赖，可单元测试。
 */
object ProcNetParser {

    /** /proc/net/tcp 中的一行连接 */
    data class TcpConnection(
        val localIp: String,
        val localPort: Int,
        val remoteIp: String,
        val remotePort: Int,
        val state: String,
        val uid: Int,
    )

    /** TCP 连接状态码 */
    object TcpState {
        const val ESTABLISHED = "01"
        const val SYN_SENT = "02"
        const val LISTEN = "0A"
    }

    /**
     * 解析 /proc/net/tcp 文件内容，返回连接列表。
     * 自动跳过表头行。
     */
    fun parseTcpFile(content: String): List<TcpConnection> {
        if (content.isBlank()) return emptyList()
        val connections = mutableListOf<TcpConnection>()
        content.lineSequence().drop(1).forEach { line ->
            val parts = line.trim().split(Regex("\\s+"))
            if (parts.size < 8) return@forEach
            try {
                val local = parts[1]
                val remote = parts[2]
                val state = parts[3]
                val uid = parts[7].toIntOrNull() ?: -1

                val (localIp, localPort) = parseHexAddr(local)
                val (remoteIp, remotePort) = parseHexAddr(remote)
                // 过滤监听套接字（无远程地址）—— IPv4 "0.0.0.0" / IPv6 "::"
                if (remotePort != 0 && remoteIp != "0.0.0.0" && remoteIp != "::") {
                    connections.add(TcpConnection(localIp, localPort, remoteIp, remotePort, state, uid))
                }
            } catch (e: Exception) { }
        }
        return connections
    }

    /**
     * 解析 /proc/net/tcp 中的地址格式。
     * IPv4: "0100007F:1F90" → ("127.0.0.1", 8080) — little-endian hex
     * IPv6: "00000000000000000000000001000000:1F90" → IPv6 地址
     */
    fun parseHexAddr(hex: String): Pair<String, Int> {
        val colonIdx = hex.indexOf(':')
        if (colonIdx < 0) return Pair("0.0.0.0", 0)
        val ipHex = hex.substring(0, colonIdx)
        val portHex = hex.substring(colonIdx + 1)

        val ip = when (ipHex.length) {
            8 -> parseIPv4Hex(ipHex)
            32 -> parseIPv6Hex(ipHex)
            else -> "0.0.0.0"
        }
        val port = try { portHex.toInt(16) } catch (e: Exception) { 0 }
        return Pair(ip, port)
    }

    /** 解析 IPv4 little-endian hex: "0100007F" → "127.0.0.1" */
    private fun parseIPv4Hex(hex: String): String {
        return try {
            "${hex.substring(6, 8).toInt(16)}.${hex.substring(4, 6).toInt(16)}." +
                "${hex.substring(2, 4).toInt(16)}.${hex.substring(0, 2).toInt(16)}"
        } catch (e: Exception) { "0.0.0.0" }
    }

    /** 解析 IPv6 hex: "00000000000000000000000001000000" → "::1" */
    private fun parseIPv6Hex(hex: String): String {
        return try {
            // 32 hex chars = 16 bytes = 8 groups of 2 bytes (4 hex chars)
            val groups = (0..7).map { i ->
                hex.substring(i * 4, i * 4 + 4)
            }
            // /proc/net/tcp6 uses little-endian within each 32-bit word
            // Each group of 4 hex chars is actually 2 bytes in little-endian
            val bytes = groups.map { g ->
                // Swap bytes within each 16-bit group (little-endian → big-endian)
                g.substring(2, 4) + g.substring(0, 2)
            }
            // Format as IPv6 address with zero-compression
            val parts = bytes.map { "${it.substring(0, 2).toInt(16)}:${it.substring(2, 4).toInt(16)}" }
            // Join and apply zero-compression
            val joined = parts.joinToString(":")
            // Simplify ::1 and :: patterns
            simplifyIPv6(joined)
        } catch (e: Exception) { "::" }
    }

    /** 简化 IPv6 地址表示（零压缩） */
    private fun simplifyIPv6(addr: String): String {
        if (addr == "0:0:0:0:0:0:0:0") return "::"
        if (addr == "0:0:0:0:0:0:0:1") return "::1"
        // General zero-compression
        val parts = addr.split(":")
        val result = StringBuilder()
        var inZero = false
        var zeroStart = -1
        var zeroLen = 0
        var maxZeroStart = -1
        var maxZeroLen = 0

        for (i in parts.indices) {
            if (parts[i] == "0") {
                if (!inZero) { inZero = true; zeroStart = i; zeroLen = 1 }
                else zeroLen++
                if (zeroLen > maxZeroLen) { maxZeroLen = zeroLen; maxZeroStart = zeroStart }
            } else {
                inZero = false; zeroLen = 0
            }
        }

        if (maxZeroLen >= 2) {
            for (i in parts.indices) {
                if (i == maxZeroStart) {
                    result.append(":")
                    if (maxZeroStart == 0) result.append(":")
                } else if (i > maxZeroStart && i < maxZeroStart + maxZeroLen) {
                    // skip
                } else {
                    if (result.isNotEmpty() && !result.endsWith(":")) result.append(":")
                    result.append(parts[i])
                }
            }
            return result.toString()
        }
        return addr
    }

    /** 判断是否为私有/本地 IP 地址（RFC 1918 + IPv6 本地地址） */
    fun isPrivateIp(ip: String): Boolean {
        // IPv4 私有地址
        if (ip.startsWith("10.") ||
            ip.startsWith("192.168.") ||
            ip.startsWith("127.") ||
            ip.startsWith("169.254.") ||
            ip.matches(Regex("^172\\.(1[6-9]|2[0-9]|3[01])\\..*"))
        ) return true
        // IPv6 本地地址
        if (ip == "::1" || // loopback
            ip == "::" ||  // unspecified
            ip.startsWith("fe80:") || // link-local
            ip.startsWith("fc") || ip.startsWith("fd") // unique local (fc00::/7)
        ) return true
        // IPv4-mapped IPv6 (::ffff:10.x.x.x 等)
        if (ip.startsWith("::ffff:")) {
            val v4 = ip.substringAfter("::ffff:")
            return isPrivateIp(v4)
        }
        return false
    }
}
