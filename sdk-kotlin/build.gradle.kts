plugins {
    id("com.android.library") version "8.5.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.24" apply false
    id("org.jetbrains.kotlin.jvm") version "2.2.0" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.0" apply false
    id("com.vanniktech.maven.publish") version "0.29.0" apply false
}

allprojects {
    group = "ai.virion.capsule"
    version = "0.6.0-prototype.1"
}
