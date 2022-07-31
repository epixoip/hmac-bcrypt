plugins {
    kotlin("multiplatform") version "1.7.10"
}

group   = "com.github.epixoip"
version = "1.0"

repositories {
    mavenCentral()
}

kotlin {
    jvm {
        compilations.all {
            kotlinOptions.jvmTarget = "1.8"
        }
    }
    sourceSets {
        val commonMain by getting

        val jvmMain by getting {
            dependencies {
                implementation("at.favre.lib:bcrypt:0.9.0")
            }
        }

        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
    }
}
