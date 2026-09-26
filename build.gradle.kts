plugins {
    kotlin("jvm") version "2.4.20" // version kotlin
    id("com.gradleup.shadow") version "9.6.1" // fat jar plugin
}

group = "com.example"
version = "0.1.0"

repositories {
    mavenCentral() // repo library
}

dependencies {
    implementation("net.portswigger.burp.extensions:montoya-api:2025.3")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
}

tasks.named("shadowJar") { // settings plugins
    this as AbstractArchiveTask
    archiveBaseName.set("burp-plugin") // Filename
    archiveClassifier.set("") // Without "-all"
    archiveVersion.set("") // Without version in filename
}




