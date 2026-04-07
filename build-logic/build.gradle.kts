plugins {
    `kotlin-dsl`
}

group = "com.eltavine.duckdetector.buildlogic"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}

dependencies {
    implementation(libs.android.gradle.plugin)
    implementation(libs.kotlin.gradle.plugin)
}

gradlePlugin {
    plugins {
        register("duckDetectorAndroidApplication") {
            id = "duckdetector.android.application"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorAndroidApplicationConventionPlugin"
        }
        register("duckDetectorAndroidApkArtifacts") {
            id = "duckdetector.android.apk-artifacts"
            implementationClass = "com.eltavine.duckdetector.buildlogic.DuckDetectorApkArtifactsConventionPlugin"
        }
    }
}
