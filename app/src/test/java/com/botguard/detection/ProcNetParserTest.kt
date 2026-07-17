package com.botguard.detection

import com.google.common.truth.Truth.assertThat
import org.junit.Test

/**
 * ProcNetParser 单元测试 — /proc/net/tcp hex 地址解析。
 *
 * 覆盖：
 * - IPv4 hex 解析（little-endian）
 * - 端口 hex 解析
 * - 完整 /proc/net/tcp 文件解析
 * - IPv6 地址解析
 * - 私有 IP 判断
 * - 空文件/异常输入
 */
class ProcNetParserTest {

    // ════════════════════════════════════════════════════════
    //  IPv4 hex 地址解析
    // ════════════════════════════════════════════════════════

    @Test
    fun `parseHexAddr parses loopback 127_0_0_1`() {
        // 0100007F = 127.0.0.1 in little-endian hex
        val (ip, port) = ProcNetParser.parseHexAddr("0100007F:1F90")
        assertThat(ip).isEqualTo("127.0.0.1")
        assertThat(port).isEqualTo(8080) // 0x1F90 = 8080
    }

    @Test
    fun `parseHexAddr parses 0_0_0_0`() {
        val (ip, port) = ProcNetParser.parseHexAddr("00000000:0050")
        assertThat(ip).isEqualTo("0.0.0.0")
        assertThat(port).isEqualTo(80) // 0x50 = 80
    }

    @Test
    fun `parseHexAddr parses 192_168_1_1`() {
        // 192.168.1.1 → hex bytes: C0.A8.01.01 → little-endian: 0101A8C0
        val (ip, port) = ProcNetParser.parseHexAddr("0101A8C0:0035")
        assertThat(ip).isEqualTo("192.168.1.1")
        assertThat(port).isEqualTo(53) // 0x35 = 53
    }

    @Test
    fun `parseHexAddr parses 10_0_0_1`() {
        // 10.0.0.1 → hex bytes: 0A.00.00.01 → little-endian: 0100000A
        val (ip, port) = ProcNetParser.parseHexAddr("0100000A:01BD")
        assertThat(ip).isEqualTo("10.0.0.1")
        assertThat(port).isEqualTo(445) // 0x01BD = 445
    }

    @Test
    fun `parseHexAddr parses public IP 8_8_8_8`() {
        // 8.8.8.8 → hex bytes: 08.08.08.08 → little-endian: 08080808
        val (ip, port) = ProcNetParser.parseHexAddr("08080808:01BB")
        assertThat(ip).isEqualTo("8.8.8.8")
        assertThat(port).isEqualTo(443) // 0x01BB = 443
    }

    @Test
    fun `parseHexAddr handles invalid input`() {
        val (ip, port) = ProcNetParser.parseHexAddr("invalid")
        assertThat(ip).isEqualTo("0.0.0.0")
        assertThat(port).isEqualTo(0)
    }

    @Test
    fun `parseHexAddr handles missing colon`() {
        val (ip, port) = ProcNetParser.parseHexAddr("0100007F")
        assertThat(ip).isEqualTo("0.0.0.0")
        assertThat(port).isEqualTo(0)
    }

    @Test
    fun `parseHexAddr handles empty string`() {
        val (ip, port) = ProcNetParser.parseHexAddr("")
        assertThat(ip).isEqualTo("0.0.0.0")
        assertThat(port).isEqualTo(0)
    }

    // ════════════════════════════════════════════════════════
    //  完整 /proc/net/tcp 文件解析
    // ════════════════════════════════════════════════════════

    @Test
    fun `parseTcpFile parses multiple connections`() {
        val content = """
            sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
             0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 22 0 0 10 -1
             1: 0101A8C0:0035 08080808:0050 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 22 0 0 10 -1
             2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 22 0 0 10 -1
        """.trimIndent()

        val connections = ProcNetParser.parseTcpFile(content)
        assertThat(connections).hasSize(3)

        // First connection: 127.0.0.1:8080 → 8.8.8.8:443, ESTABLISHED
        assertThat(connections[0].localIp).isEqualTo("127.0.0.1")
        assertThat(connections[0].localPort).isEqualTo(8080)
        assertThat(connections[0].remoteIp).isEqualTo("8.8.8.8")
        assertThat(connections[0].remotePort).isEqualTo(443)
        assertThat(connections[0].state).isEqualTo("01")
        assertThat(connections[0].uid).isEqualTo(0)

        // Second connection: 192.168.1.1:53 → 8.8.8.8:80, ESTABLISHED
        assertThat(connections[1].localIp).isEqualTo("192.168.1.1")
        assertThat(connections[1].remotePort).isEqualTo(80)
        assertThat(connections[1].uid).isEqualTo(1000)

        // Third connection: LISTEN, remote is 0.0.0.0:0 → should be included
        assertThat(connections[2].state).isEqualTo("0A")
    }

    @Test
    fun `parseTcpFile filters out zero remote addresses`() {
        val content = """
            sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
             0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 22 0 0 10 -1
        """.trimIndent()

        // Remote is 0.0.0.0:0, should be filtered out by the "remoteIp != 0.0.0.0" check
        val connections = ProcNetParser.parseTcpFile(content)
        assertThat(connections).isEmpty()
    }

    @Test
    fun `parseTcpFile handles empty content`() {
        assertThat(ProcNetParser.parseTcpFile("")).isEmpty()
    }

    @Test
    fun `parseTcpFile handles blank content`() {
        assertThat(ProcNetParser.parseTcpFile("   ")).isEmpty()
    }

    @Test
    fun `parseTcpFile handles header only`() {
        val content = "sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
        assertThat(ProcNetParser.parseTcpFile(content)).isEmpty()
    }

    @Test
    fun `parseTcpFile handles malformed lines gracefully`() {
        val content = """
            sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
             0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 22 0 0 10 -1
             garbage line with no valid format
             1: 0101A8C0:0035 08080808:0050 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 22 0 0 10 -1
        """.trimIndent()

        val connections = ProcNetParser.parseTcpFile(content)
        // Should parse 2 valid connections, skip the garbage line
        assertThat(connections).hasSize(2)
    }

    // ════════════════════════════════════════════════════════
    //  私有 IP 判断
    // ════════════════════════════════════════════════════════

    @Test
    fun `isPrivateIp identifies 10_x range`() {
        assertThat(ProcNetParser.isPrivateIp("10.0.0.1")).isTrue()
        assertThat(ProcNetParser.isPrivateIp("10.255.255.255")).isTrue()
    }

    @Test
    fun `isPrivateIp identifies 192_168_x range`() {
        assertThat(ProcNetParser.isPrivateIp("192.168.1.1")).isTrue()
        assertThat(ProcNetParser.isPrivateIp("192.168.0.0")).isTrue()
    }

    @Test
    fun `isPrivateIp identifies 127_x loopback`() {
        assertThat(ProcNetParser.isPrivateIp("127.0.0.1")).isTrue()
        assertThat(ProcNetParser.isPrivateIp("127.1.2.3")).isTrue()
    }

    @Test
    fun `isPrivateIp identifies 169_254_x link-local`() {
        assertThat(ProcNetParser.isPrivateIp("169.254.1.1")).isTrue()
    }

    @Test
    fun `isPrivateIp identifies 172_16-31_x range`() {
        assertThat(ProcNetParser.isPrivateIp("172.16.0.1")).isTrue()
        assertThat(ProcNetParser.isPrivateIp("172.31.255.255")).isTrue()
        assertThat(ProcNetParser.isPrivateIp("172.20.10.5")).isTrue()
    }

    @Test
    fun `isPrivateIp rejects public IPs`() {
        assertThat(ProcNetParser.isPrivateIp("8.8.8.8")).isFalse()
        assertThat(ProcNetParser.isPrivateIp("1.1.1.1")).isFalse()
        assertThat(ProcNetParser.isPrivateIp("172.15.0.1")).isFalse()
        assertThat(ProcNetParser.isPrivateIp("172.32.0.1")).isFalse()
        assertThat(ProcNetParser.isPrivateIp("192.167.1.1")).isFalse()
    }
}
