File buildDir = new File(basedir, "target")
assert buildDir.exists() : "target directory missing"

File jarAsc = new File(buildDir, "sign-verify-roundtrip-1.0-SNAPSHOT.jar.asc")
assert jarAsc.exists() : ".asc signature file was not created"

String content = jarAsc.text
int beginCount = content.count("-----BEGIN PGP SIGNATURE-----")
int endCount = content.count("-----END PGP SIGNATURE-----")

assert beginCount == 2 : "Expected 2 PGP signature blocks, found ${beginCount}"
assert endCount == 2 : "Expected 2 PGP end markers, found ${endCount}"

println "SUCCESS: hybrid .asc file contains classic + PQC signature blocks"
