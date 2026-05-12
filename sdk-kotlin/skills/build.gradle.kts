plugins {
    kotlin("jvm")
}

kotlin { jvmToolchain(17) }

dependencies {
    api(project(":core"))
    implementation("com.google.code.gson:gson:2.11.0")
    testImplementation(kotlin("test"))
}
