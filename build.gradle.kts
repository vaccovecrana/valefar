plugins {
  id("io.vacco.oss.gitflow") version "0.9.7"
}

group = "io.vacco.valefar"
version = "0.1.0"

configure<io.vacco.oss.gitflow.GsPluginProfileExtension> {
  addJ8Spec()
  addClasspathHell()
  sharedLibrary(true, true)
}

dependencies {
  testImplementation("io.vacco.jsonbeans:jsonbeans:1.0.0")
}
