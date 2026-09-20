import java.util.Properties

plugins {
    // Kotlin is built into AGP 9; no separate Kotlin plugin.
    id("com.android.application")
}

// Release signing is read from keystore.properties, which is gitignored along
// with the keystore itself.
//
// The keystore is load-bearing: because DISALLOW_DEBUGGING_FEATURES lands 24h
// after provisioning, a signed APK update is the ONLY non-destructive way to
// change policy afterwards. An update must be signed with this same key. Lose
// it and the policy is frozen until the phone is wiped.
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}
val hasReleaseKeystore = keystoreProps.getProperty("storeFile") != null

android {
    namespace = "io.github.dan537.devicepolicy"
    compileSdk = 36

    defaultConfig {
        applicationId = "io.github.dan537.devicepolicy"
        // API 30 is the floor for the provisioning handler contract we rely on.
        // The target device (Galaxy A36) is on Android 16, so this is generous.
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
    }

    if (hasReleaseKeystore) {
        signingConfigs {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // R8 is left off deliberately. Every entry point in this app is
            // reached only from the manifest or the platform, so shrinking buys
            // nothing and adds a way for the policy engine to be silently
            // broken by an over-aggressive rule.
            isMinifyEnabled = false
            isShrinkResources = false
            if (hasReleaseKeystore) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        // Fail the build on a real error rather than shipping a broken policy.
        abortOnError = true
        warningsAsErrors = false
    }
}

dependencies {
    implementation("androidx.work:work-runtime-ktx:2.11.1")
}
