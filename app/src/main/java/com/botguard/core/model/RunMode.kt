package com.botguard.core.model

/**
 * 运行模式：决定检测模块能获取多少系统权限。
 * - NO_ROOT: 普通用户模式，仅依赖公开 API
 * - ADB: 通过 adb shell 运行，拥有部分系统权限
 * - ROOT: 拥有 root 权限，可读取所有分区
 */
enum class RunMode {
    NO_ROOT,
    ADB,
    ROOT;

    fun canReadSystemPartition(): Boolean = this == ROOT
    fun canListAllProcesses(): Boolean = this != NO_ROOT
    fun canReadProcNet(): Boolean = true // /proc/net/tcp 对所有进程可读
}
