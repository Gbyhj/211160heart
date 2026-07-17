package com.botguard

import android.app.Application
import android.content.Context
import com.botguard.core.engine.ReportGenerator
import com.botguard.core.engine.ScanHistory
import com.botguard.core.engine.ScannerEngine
import com.botguard.detection.AppModule
import com.botguard.detection.BehaviorModule
import com.botguard.detection.NetworkModule
import com.botguard.detection.PersistenceModule
import com.botguard.detection.RootEnvModule
import com.botguard.intel.IocMatcher

/**
 * 手动 DI 容器 — 无需 Hilt，零注解处理。
 */
class AppContainer(context: Context) {
    val iocMatcher: IocMatcher = IocMatcher.get(context)
    val scannerEngine: ScannerEngine = ScannerEngine(
        context = context,
        modules = listOf(
            BehaviorModule(iocMatcher),
            AppModule(iocMatcher),
            PersistenceModule(iocMatcher),
            NetworkModule(iocMatcher),
            RootEnvModule(iocMatcher),
        )
    )
    val reportGenerator: ReportGenerator = ReportGenerator()
    val scanHistory: ScanHistory = ScanHistory(context)
}

class BotGuardApp : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
    }
}
