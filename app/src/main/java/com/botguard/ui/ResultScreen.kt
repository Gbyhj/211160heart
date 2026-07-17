package com.botguard.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.botguard.core.model.Finding
import com.botguard.core.model.RiskLevel
import com.botguard.core.model.ScanResult

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResultScreen(
    result: ScanResult,
    reportText: String,
    detailedText: String = "",
    onRescan: () -> Unit,
    onShareReport: (String) -> Unit = { },
    onExportJson: () -> Unit = {},
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("扫描结果", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onRescan) {
                        Icon(Icons.Default.Refresh, contentDescription = "重新扫描")
                    }
                },
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
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            Spacer(Modifier.height(16.dp))

            // 风险评分卡
            RiskScoreCard(result)

            Spacer(Modifier.height(16.dp))

            // 统计摘要
            StatsRow(result)

            Spacer(Modifier.height(16.dp))

            // IoC 命中
            if (result.iocHits > 0) {
                IocHitCard(result)
                Spacer(Modifier.height(16.dp))
            }

            // 检测发现列表
            if (result.findings.isEmpty()) {
                EmptyResultCard()
            } else {
                Text(
                    "检测发现 (${result.findings.size} 项)",
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Spacer(Modifier.height(8.dp))
                for (f in result.findings) {
                    FindingCard(f)
                    Spacer(Modifier.height(8.dp))
                }
            }

            Spacer(Modifier.height(16.dp))

            // 完整报告（简版 / 详版切换，Phase 2 情报增强）
            var showDetailed by remember { mutableStateOf(false) }
            val displayedText = if (showDetailed) detailedText else reportText
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("完整报告", fontSize = 18.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                SingleChoiceSegmentedButtonRow {
                    SegmentedButton(
                        selected = !showDetailed,
                        onClick = { showDetailed = false },
                        shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
                    ) { Text("简版", fontSize = 12.sp) }
                    SegmentedButton(
                        selected = showDetailed,
                        onClick = { showDetailed = true },
                        shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
                    ) { Text("详版", fontSize = 12.sp) }
                }
            }
            Spacer(Modifier.height(8.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Text(
                    displayedText,
                    modifier = Modifier.padding(12.dp),
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                    lineHeight = 16.sp,
                )
            }

            Spacer(Modifier.height(24.dp))

            // 报告导出/分享按钮（P2-2）
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = { onShareReport(displayedText) },
                    modifier = Modifier.weight(1f).height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("分享", fontSize = 14.sp)
                }
                OutlinedButton(
                    onClick = onExportJson,
                    modifier = Modifier.weight(1f).height(48.dp),
                    shape = RoundedCornerShape(12.dp),
                ) {
                    Icon(Icons.Default.FileDownload, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("导出 JSON", fontSize = 14.sp)
                }
            }

            Spacer(Modifier.height(8.dp))
            Button(
                onClick = onRescan,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                shape = RoundedCornerShape(12.dp),
            ) {
                Text("重新扫描", fontSize = 16.sp)
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun RiskScoreCard(result: ScanResult) {
    val score = result.riskScore.totalScore
    val level = result.riskScore.riskLevel
    val cardColor = Color(level.color)
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(containerColor = cardColor),
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text("$score", fontSize = 48.sp, fontWeight = FontWeight.Bold, color = Color.White)
            Text("/100", fontSize = 16.sp, color = Color.White.copy(alpha = 0.8f))
            Spacer(Modifier.height(4.dp))
            Text(level.label, fontSize = 20.sp, fontWeight = FontWeight.SemiBold, color = Color.White)
        }
    }
}

@Composable
private fun StatsRow(result: ScanResult) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceEvenly,
    ) {
        StatItem("严重", result.criticalCount, Color(RiskLevel.CRITICAL.color))
        StatItem("高危", result.highCount, Color(RiskLevel.HIGH.color))
        StatItem("中危", result.mediumCount, Color(RiskLevel.MEDIUM.color))
        StatItem("低危", result.lowCount, Color(RiskLevel.LOW.color))
    }
}

@Composable
private fun StatItem(label: String, count: Int, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Surface(
            shape = RoundedCornerShape(8.dp),
            color = color,
            modifier = Modifier.size(48.dp, 32.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text("$count", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 16.sp)
            }
        }
        Text(label, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
    }
}

@Composable
private fun IocHitCard(result: ScanResult) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFFFEBEE)),
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("⚠ IoC 命中", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = Color(0xFFB71C1C))
            Spacer(Modifier.height(4.dp))
            Text("命中 ${result.iocHits} 项威胁情报", fontSize = 14.sp, color = Color(0xFFB71C1C))
            if (result.iocFamilies.isNotEmpty()) {
                Text("家族: ${result.iocFamilies.joinToString()}", fontSize = 14.sp, color = Color(0xFFB71C1C))
            }
        }
    }
}

@Composable
private fun EmptyResultCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFE8F5E9)),
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text("✓", fontSize = 48.sp, color = Color(0xFF4CAF50))
            Text("未发现异常", fontSize = 18.sp, fontWeight = FontWeight.SemiBold, color = Color(0xFF2E7D32))
            Text("设备状态良好", fontSize = 14.sp, color = Color(0xFF4CAF50))
        }
    }
}

@Composable
private fun FindingCard(f: Finding) {
    val color = Color(f.riskLevel.color)
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        ),
        border = androidx.compose.foundation.BorderStroke(2.dp, color.copy(alpha = 0.3f)),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Surface(
                    shape = RoundedCornerShape(4.dp),
                    color = color,
                    modifier = Modifier.size(8.dp),
                ) {}
                Spacer(Modifier.width(8.dp))
                Text("[${f.id}] ${f.title}", fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.weight(1f))
                Text(f.riskLevel.label, fontSize = 12.sp, color = color, fontWeight = FontWeight.Bold)
            }
            Spacer(Modifier.height(4.dp))
            Text(f.description, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (f.iocHit) {
                Spacer(Modifier.height(4.dp))
                Text("⚠ IoC 命中: ${f.iocFamily ?: "未知"}", fontSize = 12.sp, color = Color(0xFFB71C1C), fontWeight = FontWeight.Bold)
            }
            if (f.attAckId != null) {
                Text("ATT&CK: ${f.attAckId}", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, fontFamily = FontFamily.Monospace)
            }
            if (f.evidence.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                f.evidence.forEach { (k, v) ->
                    Text("  $k: $v", fontSize = 11.sp, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (f.recommendedActions.isNotEmpty()) {
                Spacer(Modifier.height(4.dp))
                Text("建议:", fontSize = 12.sp, fontWeight = FontWeight.Medium)
                f.recommendedActions.forEach {
                    Text("  • $it", fontSize = 12.sp)
                }
            }
        }
    }
}
