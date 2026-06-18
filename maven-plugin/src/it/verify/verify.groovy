File buildLog = new File(basedir, "build.log")
assert buildLog.exists()
String log = buildLog.text

// Phase 1: dependency-signers should have generated the config
File trustConfig = new File(basedir, "trust-config.yaml")
assert trustConfig.exists() : "trust-config.yaml should have been generated"
String yaml = trustConfig.text
assert yaml.contains("signers:") : "Generated config should have signers section"
assert yaml.contains("trust:") : "Generated config should have trust section"

// Phase 2: verify goal should have run successfully
assert log.contains("Verifying signers") : "Should log verification start"
assert log.contains("Summary:") : "Should log the summary"
assert !log.contains("BUILD FAILURE") : "Build should succeed"

println "SUCCESS: generated trust-config.yaml and verified dependencies against it"
