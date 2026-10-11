plugins {
    application
    kotlin("jvm")
}

application {
    mainClass.set("dev.saathi.cli.Main")
}

dependencies {
    implementation(project(":core"))
    testImplementation(kotlin("test"))
}
