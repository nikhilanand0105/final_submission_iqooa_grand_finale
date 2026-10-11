plugins {
    application
    kotlin("jvm")
}

application {
    mainClass.set("dev.guardianai.cli.Main")
}

dependencies {
    implementation(project(":core"))
    testImplementation(kotlin("test"))
}
