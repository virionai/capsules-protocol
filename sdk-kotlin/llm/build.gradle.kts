plugins {
    kotlin("jvm")
}

kotlin { jvmToolchain(17) }

dependencies {
    api(project(":core"))
    api(project(":skills"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    testImplementation(kotlin("test"))
}
