package com.botguard.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.botguard.core.model.RiskLevel
import com.botguard.core.model.RunMode
import com.botguard.core.engine.ScanHistory

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(
    scanning: Boolean = false,
    currentModule: String = "",
    progress: Float = 0f,
    error: String? = null,
    onScan: () -> Unit,
    iocStats: String = "",
    selectedRunMode: RunMode = RunMode.NO_ROOT,
    onRunModeSelected: (RunMode) -> Unit = {},
    scanHistory: List<ScanHistory.HistoryEntry> = emptyList(),
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("BotGuard 僵尸网络自检", fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                Icons.Default.Security,
                contentDescription = null,
                modifier = Modifier.size(80.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.height(16.dp))
            Text("设备安全自检", fontSize = 24.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(8.dp))
            Text(
                "检测设备是否已被僵尸网络控制\n" +
                "45 项检测 · 5 大模块 · 6 个家族 IoC",
                fontSize = 14.sp, color = MaterialTheme.colorScheme.onSurfaceVariant,
                lineHeight = 20.sp,
            )

            if (iocStats.isNotBlank()) {
                Spacer(Modifier.height(16.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Text(
                        iocStats,
                        modifier = Modifier.padding(12.dp),
                        fontSize = 11.sp,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    )
                }
            }

            Spacer(Modifier.height(16.dp))

            // 运行模式选择器
            Text("运行模式", fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            RunModeSelector(selectedRunMode, onRunModeSelected, scanning)
            Spacer(Modifier.height(8.dp))

            if (scanning) {
                LinearProgressIndicator(
                    progress = { progress },
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(8.dp))
                Text("正在扫描: $currentModule", fontSize = 14.sp)
            }

            if (error != null) {
                Spacer(Modifier.height(16.dp))
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = Color(0xFFFFCDD2)
                    )
                ) {
                    Text(
                        error,
                        modifier = Modifier.padding(12.dp),
                        color = Color(0xFFB71C1C),
                        fontSize = 14.sp,
                    )
                }
            }

            Spacer(Modifier.height(24.dp))

            Button(
                onClick = onScan,
                enabled = !scanning,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                shape = RoundedCornerShape(16.dp),
            ) {
                Text(if (scanning) "扫描中..." else "开始扫描", fontSize = 18.sp)
            }

            Spacer(Modifier.height(24.dp))

            // 模块列表
            Text("检测模块", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            val modules = listOf(
                "A5" to "行为审计 · 8项 · HIGHEST",
                "A2" to "应用审计 · 9项 · HIGH",
                "A3" to "持久化审计 · 12项 · HIGH",
                "A7" to "网络审计 · 8项 · HIGH",
                "A6" to "Root环境检测 · 8项 · MEDIUM",
            )
            for ((mid, mname) in modules) {
                ModuleRow(mid, mname)
                Spacer(Modifier.height(4.dp))
            }

            Spacer(Modifier.height(16.dp))

            // 扫描历史（P2-3: 持久化展示）
            if (scanHistory.isNotEmpty() && !scanning) {
                Text("扫描历史", fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(8.dp))
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        scanHistory.take(5).forEach { entry ->
                            val dateStr = try {
                                java.text.SimpleDateFormat("MM-dd HH:mm", java.util.Locale.CHINA)
                                    .format(java.util.Date(entry.timestamp))
                            } catch (e: Exception) { "" }
                            val riskColor = when (entry.riskLevel) {
                                "CRITICAL" -> Color(0xFFD93025)
                                "HIGH" -> Color(0xFFE8710A)
                                "MEDIUM" -> Color(0xFFF9AB00)
                                "LOW" -> Color(0xFF1A73E8)
                                else -> Color(0xFF1E8E3E)
                            }
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Surface(
                                    shape = RoundedCornerShape(4.dp),
                                    color = riskColor,
                                    modifier = Modifier.size(8.dp),
                                ) {}
                                Spacer(Modifier.width(8.dp))
                                Text(dateStr, fontSize = 12.sp, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                                Spacer(Modifier.width(8.dp))
                                Text("${entry.totalScore}/100", fontSize = 12.sp, fontWeight = FontWeight.Medium, color = riskColor)
                                Spacer(Modifier.width(8.dp))
                                Text("${entry.totalFindings}项", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                if (entry.iocHits > 0) {
                                    Spacer(Modifier.width(4.dp))
                                    Text("IoC:${entry.iocHits}", fontSize = 11.sp, color = Color(0xFFD93025), fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
                Spacer(Modifier.height(16.dp))
            }

            Text(
                "BotGuard v2.0 · 本地离线运行 · 无需联网",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun RunModeSelector(
    selected: RunMode,
    onSelect: (RunMode) -> Unit,
    disabled: Boolean,
) {
    val modes = listOf(
        RunMode.NO_ROOT to "普通模式" to "无需 Root，45 项中 43 项可用",
        RunMode.ADB to "ADB 模式" to "通过 ADB 运行，增强进程检测",
        RunMode.ROOT to "Root 模式" to "完整检测，含系统分区扫描",
    )
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            modes.forEach { (pair, desc) ->
                val (mode, label) = pair
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(
                        selected = selected == mode,
                        onClick = { if (!disabled) onSelect(mode) },
                        enabled = !disabled,
                    )
                    Spacer(Modifier.width(8.dp))
                    Column {
                        Text(label, fontSize = 14.sp, fontWeight = FontWeight.Medium)
                        Text(desc, fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }
    }
}

@Composable
private fun ModuleRow(id: String, name: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Surface(
            shape = RoundedCornerShape(8.dp),
            color = MaterialTheme.colorScheme.primaryContainer,
            modifier = Modifier.size(40.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text(id, fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }
        Spacer(Modifier.width(12.dp))
        Text(name, fontSize = 14.sp)
    }
}
