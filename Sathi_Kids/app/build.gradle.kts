import java.util.Properties

plugins {
    id("com.android.application")
}

// Deployment configuration is read from local.properties / Gradle properties so nothing project-specific
// is committed. None of these are secrets: the Firebase Web API key only identifies the project; all
// authorisation is enforced by the backend. Server secrets (e.g. the Web Risk key) never reach the app.
val localProps = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

fun cfg(name: String): String =
    (localProps.getProperty(name) ?: (project.findProperty(name) as String?) ?: "").trim()

fun quoted(v: String): String = "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

android {
    namespace = "dev.saathi.kids"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.saathi.kids"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0-kids"

        // https://<region>-<project>.cloudfunctions.net/api  (empty = family, SOS and online link check disabled)
        buildConfigField("String", "SAATHI_BACKEND_URL", quoted(cfg("saathi.backendUrl")))
        buildConfigField("String", "FIREBASE_WEB_API_KEY", quoted(cfg("saathi.firebaseWebApiKey")))
        // Name of the .litertlm model file placed in the app's files/models directory, and its expected SHA-256.
        buildConfigField("String", "GEMMA_MODEL_FILE", quoted(cfg("saathi.gemma.modelFile")))
        buildConfigField("String", "GEMMA_MODEL_SHA256", quoted(cfg("saathi.gemma.sha256").lowercase()))

        // Snapdragon 8 Elite (SM8850) is 64-bit only; LiteRT-LM ships arm64-v8a natives.
        ndk {
            abiFilters.clear()
            abiFilters.add("arm64-v8a")
        }
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            // Debug signing for local hackathon builds only; replace with a real release key before distribution.
            signingConfig = signingConfigs.getByName("debug")
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(project(":core"))
    // LiteRT-LM on-device LLM runtime (Apache-2.0). Version verified on Google Maven, Oct 2026.
    implementation("com.google.ai.edge.litertlm:litertlm-android:0.18.0")
}
