package com.botguard

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope
import com.botguard.core.engine.ScannerEngine
import com.botguard.core.model.RunMode
import com.botguard.core.model.ScanResult
import com.botguard.intel.IocMatcher
import com.botguard.ui.BotGuardTheme
import com.botguard.ui.ScanScreen
import com.botguard.ui.ResultScreen
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File

class MainActivity : ComponentActivity() {

    private val _scanState = MutableStateFlow<ScanState>(ScanState.Idle)
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()

    private val container: AppContainer get() = (application as BotGuardApp).container

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            BotGuardTheme {
                val state by _scanState.collectAsState()
                var selectedRunMode by remember { mutableStateOf(RunMode.NO_ROOT) }
                when (val s = state) {
                    ScanState.Idle -> ScanScreen(
                        onScan = { startScan(selectedRunMode) },
                        iocStats = IocMatcher.stats(),
                        selectedRunMode = selectedRunMode,
                        onRunModeSelected = { selectedRunMode = it },
                        scanHistory = container.scanHistory.getAll(),
                    )
                    is ScanState.Scanning -> ScanScreen(
                        scanning = true,
                        currentModule = s.moduleName,
                        progress = s.progress,
                        onScan = { },
                        iocStats = IocMatcher.stats(),
                        selectedRunMode = selectedRunMode,
                        onRunModeSelected = { },
                    )
                    is ScanState.Done -> ResultScreen(
                        result = s.result,
                        reportText = container.reportGenerator.generateText(s.result),
                        detailedText = container.reportGenerator.generateDetailed(s.result),
                        onRescan = { _scanState.value = ScanState.Idle },
                        onShareReport = { text -> shareReportText(text) },
                        onExportJson = { exportJson(s.result) },
                    )
                    is ScanState.Error -> ScanScreen(
                        error = s.message,
                        onScan = { startScan(selectedRunMode) },
                        iocStats = IocMatcher.stats(),
                        selectedRunMode = selectedRunMode,
                        onRunModeSelected = { selectedRunMode = it },
                    )
                }
            }
        }
    }

    private fun startScan(runMode: RunMode) {
        _scanState.value = ScanState.Scanning("初始化", 0f)
        lifecycleScope.launch {
            container.scannerEngine.scan(runMode).collect { event ->
                when (event) {
                    is ScannerEngine.ScanEvent.ModuleStart ->
                        _scanState.value = ScanState.Scanning(
                            event.moduleName,
                            event.moduleIndex.toFloat() / event.totalModules,
                        )
                    is ScannerEngine.ScanEvent.ModuleDone ->
                        _scanState.value = ScanState.Scanning(
                            event.moduleId,
                            event.moduleIndex.toFloat() / event.totalModules,
                        )
                    is ScannerEngine.ScanEvent.Complete -> {
                        // 持久化扫描结果到历史记录（P2-3）
                        container.scanHistory.save(event.result)
                        _scanState.value = ScanState.Done(event.result)
                    }
                    is ScannerEngine.ScanEvent.Error -> {
                        Log.w("MainActivity", "扫描模块错误: ${event.message}")
                    }
                }
            }
        }
    }

    /** 分享文本报告（P2-2 / Phase 2 详版切换） */
    private fun shareReportText(text: String) {
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "BotGuard 扫描报告")
            putExtra(Intent.EXTRA_TEXT, text)
        }
        startActivity(Intent.createChooser(intent, "分享报告"))
    }

    /** 导出 JSON 报告到外部存储（P2-2） */
    private fun exportJson(result: ScanResult) {
        try {
            val json = container.reportGenerator.generateJson(result)
            val dir = File(getExternalFilesDir(null), "reports")
            if (!dir.exists()) dir.mkdirs()
            val file = File(dir, "botguard_report_${System.currentTimeMillis()}.json")
            file.writeText(json)

            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/json"
                putExtra(Intent.EXTRA_STREAM, android.net.Uri.fromFile(file))
                putExtra(Intent.EXTRA_SUBJECT, "BotGuard JSON 报告")
            }
            startActivity(Intent.createChooser(intent, "导出 JSON 报告"))
        } catch (e: Exception) {
            Log.e("MainActivity", "导出 JSON 失败", e)
        }
    }
}

sealed class ScanState {
    data object Idle : ScanState()
    data class Scanning(val moduleName: String, val progress: Float) : ScanState()
    data class Done(val result: ScanResult) : ScanState()
    data class Error(val message: String) : ScanState()
}
