package com.eltavine.duckdetector.buildlogic

import org.gradle.api.Project

internal fun Project.requiredGradleProperty(name: String): String =
    providers.gradleProperty(name).orNull
        ?: error("Missing required Gradle property: $name")

internal fun Project.requiredIntGradleProperty(name: String): Int =
    requiredGradleProperty(name).toInt()
