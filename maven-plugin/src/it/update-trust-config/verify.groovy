File buildLog = new File(basedir, "build.log")
assert buildLog.exists()
String log = buildLog.text

// The update should have added the missing jspecify signer
assert log.contains("Trust configuration updated") : "Should log config update"

// The config should now have both signers
File trustConfig = new File(basedir, "trust-config.yaml")
assert trustConfig.exists()
String yaml = trustConfig.text
assert yaml.contains("gary-gregory") : "Should still have original signer"
assert yaml.contains("org.jspecify") : "Should have added jspecify trust entry"

// Verify goal should pass with the updated config
assert log.contains("Verifying signers") : "Should log verification start"
assert log.contains("Summary:") : "Should log the summary"
assert !log.contains("BUILD FAILURE") : "Build should succeed"

// Should not have duplicate section headers
int signersCount = yaml.split("signers:").length - 1
assert signersCount == 1 : "Should have exactly one signers: section, found ${signersCount}"
int trustCount = yaml.split("trust:").length - 1
assert trustCount == 1 : "Should have exactly one trust: section, found ${trustCount}"

// Comments should be preserved
assert yaml.contains("# Trust configuration for update test") : "Header comment should be preserved"
assert yaml.contains("# Gary Gregory signs commons-lang3") : "Inline comment should be preserved"

println "SUCCESS: updated trust-config.yaml with missing signer, preserved comments, and verified"
