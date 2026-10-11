# R8 rules for Saathi Kids

# LiteRT-LM is called through JNI; native code looks classes and members up by name.
-keep class com.google.ai.edge.litertlm.** { *; }
-dontwarn com.google.ai.edge.litertlm.**

# Keep Android entry points
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application

-allowaccessmodification
-dontwarn java.lang.invoke.**
