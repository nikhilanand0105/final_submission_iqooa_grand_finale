# ProGuard / R8 rules optimized for Saathi on Snapdragon 8 Elite (arm64-v8a)

# Preserve model data classes serialized or used in reflections
-keep class dev.guardianai.model.** { *; }
-keep class dev.guardianai.storage.** { *; }
-keep class dev.guardianai.sense.** { *; }
-keep class dev.guardianai.shield.** { *; }
-keep class dev.guardianai.personal.ui.model.** { *; }
-keep class dev.guardianai.personal.ui.state.** { *; }

# Preserve Android Activities and UI components
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# Keep GuardianAiFileProvider
-keep class dev.guardianai.personal.provider.GuardianAiFileProvider { *; }

# Optimization options for 64-bit Oryon CPU
-allowaccessmodification
-dontwarn java.lang.invoke.**
