package com.botguard.core.engine

import android.content.Context
import android.util.Log
import com.botguard.core.ScanModule
import com.botguard.core.model.DeviceInfo
import com.botguard.core.model.Finding
import com.botguard.core.model.ModuleError
import com.botguard.core.model.RunMode
import com.botguard.core.model.RiskScore
import com.botguard.core.model.ScanContext
import com.botguard.core.model.ScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.withContext

/**
 * 扫描调度引擎。管理所有检测模块的注册、排序和执行。
 * 每个模块在 Dispatchers.IO 上异步执行，避免阻塞 UI。
 */
class ScannerEngine(
    private val context: Context,
    private val modules: List<ScanModule>,
) {

    /** 扫描进度事件 */
    sealed class ScanEvent {
        data class ModuleStart(
            val moduleId: String,
            val moduleName: String,
            val moduleIndex: Int,
            val totalModules: Int,
        ) : ScanEvent()
        data class ModuleDone(
            val moduleId: String,
            val findings: Int,
            val moduleIndex: Int,
            val totalModules: Int,
        ) : ScanEvent()
        data class Complete(val result: ScanResult) : ScanEvent()
        data class Error(val message: String) : ScanEvent()
    }

    /**
     * 执行完整扫描，通过 Flow 推送进度。
     * 每个模块在 IO 线程上执行，不阻塞 UI。
     */
    fun scan(runMode: RunMode): Flow<ScanEvent> = flow {
        val scanContext = ScanContext(context, runMode)
        val allFindings = mutableListOf<Finding>()
        val moduleErrors = mutableListOf<ModuleError>()
        val startTime = System.currentTimeMillis()

        val sortedModules = modules.sortedBy { it.priority.order }
        val total = sortedModules.size

        for ((index, module) in sortedModules.withIndex()) {
            emit(ScanEvent.ModuleStart(module.id, module.name, index, total))
            try {
                val findings = withContext(Dispatchers.IO) {
                    module.scan(scanContext)
                }
                allFindings.addAll(findings)
                emit(ScanEvent.ModuleDone(module.id, findings.size, index + 1, total))
            } catch (e: Exception) {
                Log.e(TAG, "模块 ${module.id}(${module.name}) 执行失败", e)
                val error = ModuleError(module.id, module.name, e.message ?: "Unknown error")
                moduleErrors.add(error)
                emit(ScanEvent.Error("模块 ${module.name}(${module.id}) 执行失败: ${e.message}"))
                emit(ScanEvent.ModuleDone(module.id, 0, index + 1, total))
            }
        }

        val riskScore = RiskScore.calculate(allFindings)
        val result = ScanResult(
            findings = allFindings.sortedByDescending { it.riskLevel.weight },
            riskScore = riskScore,
            deviceInfo = DeviceInfo(),
            scanDurationMs = System.currentTimeMillis() - startTime,
            modulesScanned = sortedModules.size,
            runMode = runMode,
            errors = moduleErrors,
        )
        emit(ScanEvent.Complete(result))
    }

    /** 模块列表（用于展示） */
    fun moduleList(): List<Pair<String, String>> = modules.map { it.id to it.name }

    companion object {
        private const val TAG = "ScannerEngine"
    }
}
