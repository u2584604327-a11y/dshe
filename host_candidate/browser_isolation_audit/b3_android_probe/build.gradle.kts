plugins {
    id("com.android.application") version "8.6.1"
}
android {
    namespace = "com.dsh.b3probe"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.dsh.b3probe"
        minSdk = 29
        targetSdk = 28
    }
    sourceSets.getByName("main").java.srcDir("../slot_command_gate")
}
