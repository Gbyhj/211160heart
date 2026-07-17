package com.botguard.core.engine

import android.content.Context
import android.content.SharedPreferences
import com.botguard.core.model.ScanResult
import org.json.JSONArray
import org.json.JSONObject

/**
 * 扫描历史持久化 — 使用 SharedPreferences 存储最近扫描结果摘要。
 * 最多保留 20 条记录，按时间倒序排列。
 */
class ScanHistory(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    data class HistoryEntry(
        val timestamp: Long,
        val totalScore: Int,
        val riskLevel: String,
        val totalFindings: Int,
        val criticalCount: Int,
        val iocHits: Int,
        val runMode: String,
        val deviceModel: String,
    )

    /** 保存一次扫描结果摘要 */
    fun save(result: ScanResult) {
        val entries = getAll().toMutableList()
        entries.add(0, HistoryEntry(
            timestamp = result.timestamp,
            totalScore = result.riskScore.totalScore,
            riskLevel = result.riskScore.riskLevel.name,
            totalFindings = result.totalFindings,
            criticalCount = result.criticalCount,
            iocHits = result.iocHits,
            runMode = result.runMode.name,
            deviceModel = result.deviceInfo.model,
        ))
        // 保留最近 20 条
        val trimmed = entries.take(MAX_ENTRIES)
        val arr = JSONArray()
        for (e in trimmed) {
            arr.put(JSONObject().apply {
                put("timestamp", e.timestamp)
                put("total_score", e.totalScore)
                put("risk_level", e.riskLevel)
                put("total_findings", e.totalFindings)
                put("critical_count", e.criticalCount)
                put("ioc_hits", e.iocHits)
                put("run_mode", e.runMode)
                put("device_model", e.deviceModel)
            })
        }
        prefs.edit().putString(KEY_HISTORY, arr.toString()).apply()
    }

    /** 获取全部历史记录（时间倒序） */
    fun getAll(): List<HistoryEntry> {
        val json = prefs.getString(KEY_HISTORY, null) ?: return emptyList()
        return try {
            val arr = JSONArray(json)
            (0 until arr.length()).map { i ->
                val obj = arr.getJSONObject(i)
                HistoryEntry(
                    timestamp = obj.getLong("timestamp"),
                    totalScore = obj.getInt("total_score"),
                    riskLevel = obj.getString("risk_level"),
                    totalFindings = obj.getInt("total_findings"),
                    criticalCount = obj.getInt("critical_count"),
                    iocHits = obj.getInt("ioc_hits"),
                    runMode = obj.getString("run_mode"),
                    deviceModel = obj.optString("device_model", ""),
                )
            }
        } catch (e: Exception) { emptyList() }
    }

    /** 清除所有历史记录 */
    fun clear() {
        prefs.edit().remove(KEY_HISTORY).apply()
    }

    companion object {
        private const val PREFS_NAME = "botguard_history"
        private const val KEY_HISTORY = "scan_history"
        private const val MAX_ENTRIES = 20
    }
}
