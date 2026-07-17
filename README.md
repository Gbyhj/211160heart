# BotGuard

Android 端僵尸网络自检工具 —— 48 项安全检测，覆盖 Root/提权、持久化、网络 C2、DGA 域名、Hook 框架、Magisk、行为异常等维度，并映射 MITRE ATT&CK。

## 功能概览

- **48 项检测**：网络（C2 IP/域名、DGA、异常 DNS）、Root 环境（Magisk、SELinux、su 二进制）、持久化（开机自启、设备管理员、辅助服务）、应用行为（多签名、未知来源、Hook 框架）、敏感权限等。
- **情报匹配**：内置 6 大僵尸网络家族 IoC（C2 IP / 域名 / 进程 / 文件 / APK 包名），assets 资源加载。
- **报告生成**：简版 + 详版（逐模块明细 + ATT&CK 映射 + 去重修复指南），支持分享。
- **UI**：Jetpack Compose + Material 3。

## 技术栈

- Kotlin + Jetpack Compose + Material 3
- Gradle 8.7 / JDK 17 / AGP / compileSdk 34 / minSdk 26
- detekt 静态分析 + Robolectric 单元测试
- 版本目录（`gradle/libs.versions.toml`）

## 本地构建

> 国内网络环境下，`gradle-wrapper.properties` 已指向腾讯镜像，可直接使用 `./gradlew`。

```bash
# 需要 JDK 17 与 Android SDK (platform-34 + build-tools;34.0.0)
# 在 local.properties 中设置 sdk.dir=<你的 SDK 路径>
./gradlew assembleDebug
# 产物：app/build/outputs/apk/debug/app-debug.apk
```

安装到设备：

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

## CI

GitHub Actions 三阶段流水线（`.github/workflows/ci.yml`）：
`detekt 静态分析 → 单元测试 → 构建 APK 并上传产物`。

## 项目结构

```
app/src/main/java/com/botguard/
├── detection/      # 各检测模块（Root/网络/持久化/应用/行为/权限/文件）
├── intel/          # IoC 匹配引擎
├── report/         # 报告生成（简版/详版）
├── ui/             # Compose 界面
└── ...
config/detekt.yml   # detekt 规则
```
