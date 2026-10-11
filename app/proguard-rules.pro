# ProGuard / R8 rules optimized for Saathi on Snapdragon 8 Elite (arm64-v8a)

# Preserve model data classes serialized or used in reflections
-keep class dev.saathi.model.** { *; }
-keep class dev.saathi.storage.** { *; }
-keep class dev.saathi.sense.** { *; }
-keep class dev.saathi.shield.** { *; }
-keep class dev.saathi.personal.ui.model.** { *; }
-keep class dev.saathi.personal.ui.state.** { *; }

# Preserve Android Activities and UI components
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# Keep SaathiFileProvider
-keep class dev.saathi.personal.provider.SaathiFileProvider { *; }

# Optimization options for 64-bit Oryon CPU
-allowaccessmodification
-dontwarn java.lang.invoke.**
