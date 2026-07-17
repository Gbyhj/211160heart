# BotGuard ProGuard / R8 rules

# ── Model classes (serialized to JSON) ──
-keep class com.botguard.core.model.** { *; }

# ── IoC matcher (loads JSON from assets, uses reflection-free access) ──
-keep class com.botguard.intel.** { *; }

# ── Keep JSON library (org.json is part of Android, no extra rules needed) ──

# ── Kotlin metadata ──
-keepattributes *Annotation*, InnerClasses, Signature, Exceptions, Deprecated

# ── Compose ──
-dontwarn androidx.compose.**
-keep class androidx.compose.runtime.** { *; }

# ── Coroutines ──
-dontwarn kotlinx.coroutines.**
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# ── Reflection used for SystemProperties access in RootEnvModule ──
-keep class android.os.SystemProperties { *; }
-keepclassmembers class android.os.SystemProperties {
    public static *;
}

# ── Keep enum methods ──
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ── Keep data class toString/hashCode/equals for debugging ──
-keepclassmembers class com.botguard.** {
    public java.lang.String toString();
    public int hashCode();
    public boolean equals(java.lang.Object);
}
