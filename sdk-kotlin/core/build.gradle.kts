plugins {
    kotlin("jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("com.google.code.gson:gson:2.11.0")
    testImplementation(kotlin("test"))
}
