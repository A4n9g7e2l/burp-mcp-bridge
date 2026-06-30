plugins {
    java
    id("com.gradleup.shadow") version "8.3.6"
}

group = "com.burpmcpbridge"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<JavaCompile> {
    options.compilerArgs.add("--release")
    options.compilerArgs.add("17")
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extender:montoya-api:2024.12")
    implementation("org.nanohttpd:nanohttpd:2.3.1")
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("org.graalvm.js:js:23.0.12")
    implementation("org.graalvm.js:js-scriptengine:23.0.12")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}

tasks.shadowJar {
    archiveBaseName.set("burp-mcp-bridge")
    archiveClassifier.set("")
    archiveVersion.set(version.toString())
    mergeServiceFiles()
}