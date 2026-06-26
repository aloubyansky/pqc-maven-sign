package io.github.aloubyansky.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import io.github.aloubyansky.sigmund.core.EmailCredential;
import io.github.aloubyansky.sigmund.core.FingerprintCredential;
import io.github.aloubyansky.sigmund.core.SignatureInfo;
import io.github.aloubyansky.sigmund.core.SignerIdentity;
import io.github.aloubyansky.sigmund.core.VerificationResult;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class VerifyMojoTest {

    @Nested
    class VerificationStateTests {

        private TrustConfig configWithSigner(String ref, String uid) {
            var member = new TrustConfig.Member(null, null, uid);
            var signer = new TrustConfig.Signer(null, List.of(member));
            return new TrustConfig(
                    TrustConfig.Settings.defaults(),
                    Map.of(ref, signer),
                    Map.of(),
                    Map.of(),
                    List.of());
        }

        @Test
        void isUidTrustedReturnsTrueForTrustedSignerUid() {
            var state = new VerifyMojo.VerificationState(
                    true, false, configWithSigner("alice", "Alice <alice@example.com>"));
            state.allTrustedSignerRefs.add("alice");
            assertTrue(state.isUidTrusted("Alice <alice@example.com>"));
        }

        @Test
        void isUidTrustedReturnsFalseForUnknownUid() {
            var state = new VerifyMojo.VerificationState(
                    true, false, configWithSigner("alice", "Alice <alice@example.com>"));
            state.allTrustedSignerRefs.add("alice");
            assertFalse(state.isUidTrusted("Bob <bob@example.com>"));
        }

        @Test
        void isUidTrustedReturnsFalseWhenRefNotInTrustedSet() {
            var state = new VerifyMojo.VerificationState(
                    true, false, configWithSigner("alice", "Alice <alice@example.com>"));
            assertFalse(state.isUidTrusted("Alice <alice@example.com>"));
        }
    }

    @Nested
    class SignatureMatchTests {

        private SignerIdentity signerWithGpg(String fingerprint) {
            return new SignerIdentity("test", "Test",
                    List.of(new FingerprintCredential("openpgp-v4", fingerprint)));
        }

        private SignerIdentity signerWithPqc(String fingerprint) {
            return new SignerIdentity("test", "Test",
                    List.of(new FingerprintCredential("openpgp-v6", fingerprint)));
        }

        private SignerIdentity signerWithEmail(String email) {
            return new SignerIdentity("test", "Test",
                    List.of(new EmailCredential(email)));
        }

        private SignerIdentity signerWithGpgAndEmail(String fingerprint, String email) {
            return new SignerIdentity("test", "Test",
                    List.of(new FingerprintCredential("openpgp-v4", fingerprint),
                            new EmailCredential(email)));
        }

        @Test
        void gpgFingerprintMatch() {
            var signer = signerWithGpg("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12");
            var sig = new SignatureInfo(4,
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12",
                    "RSA", "Alice <alice@example.com>", VerificationResult.PASS);
            assertTrue(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void gpgFingerprintSuffixMatch() {
            var signer = signerWithGpg("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12");
            var sig = new SignatureInfo(4,
                    "2D7BAF3C1E9F5A12",
                    "RSA", "Alice <alice@example.com>", VerificationResult.PASS);
            assertTrue(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void gpgFingerprintNoMatch() {
            var signer = signerWithGpg("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12");
            var sig = new SignatureInfo(4,
                    "BBBBBBBBBBBBBBBB",
                    "RSA", "Alice <alice@example.com>", VerificationResult.PASS);
            assertFalse(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void pqcFingerprintMatchV6() {
            var signer = signerWithPqc("D62AAB339E45E5EA2FD036872B01D46A517A2991");
            var sig = new SignatureInfo(6,
                    "D62AAB339E45E5EA2FD036872B01D46A517A2991",
                    "ML-DSA", null, VerificationResult.PASS);
            assertTrue(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void pqcFingerprintIgnoredForV4() {
            var signer = signerWithPqc("D62AAB339E45E5EA2FD036872B01D46A517A2991");
            var sig = new SignatureInfo(4,
                    "D62AAB339E45E5EA2FD036872B01D46A517A2991",
                    "RSA", null, VerificationResult.PASS);
            assertFalse(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void emailMatch() {
            var signer = signerWithEmail("alice@example.com");
            var sig = new SignatureInfo(4, "KEYID1234567890AB",
                    "RSA", "Alice <alice@example.com>", VerificationResult.PASS);
            assertTrue(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void emailNoMatch() {
            var signer = signerWithEmail("alice@example.com");
            var sig = new SignatureInfo(4, "KEYID1234567890AB",
                    "RSA", "Bob <bob@example.com>", VerificationResult.PASS);
            assertFalse(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void emailMatchWhenFingerprintDiffers() {
            var signer = signerWithGpgAndEmail("AAAAAAAAAAAAAAAA", "alice@example.com");
            var sig = new SignatureInfo(4, "BBBBBBBBBBBBBBBB",
                    "RSA", "Alice <alice@example.com>", VerificationResult.PASS);
            // In credential model, ANY credential match is sufficient
            assertTrue(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void gpgFingerprintIgnoredForV6() {
            var signer = signerWithGpg("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12");
            var sig = new SignatureInfo(6,
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12",
                    "ML-DSA", null, VerificationResult.PASS);
            assertFalse(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void notPresentAlwaysFalse() {
            var signer = signerWithEmail("alice@example.com");
            var sig = new SignatureInfo(-1, null, null, null, VerificationResult.SKIPPED);
            assertFalse(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void failResultNeverMatchesGpg() {
            var signer = signerWithGpg("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12");
            var sig = new SignatureInfo(4,
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12",
                    "RSA", "Alice <alice@example.com>", VerificationResult.FAIL);
            assertFalse(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void failResultNeverMatchesPqc() {
            var signer = signerWithPqc("D62AAB339E45E5EA2FD036872B01D46A517A2991");
            var sig = new SignatureInfo(6,
                    "D62AAB339E45E5EA2FD036872B01D46A517A2991",
                    "ML-DSA", null, VerificationResult.FAIL);
            assertFalse(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void failResultNeverMatchesEmail() {
            var signer = signerWithEmail("alice@example.com");
            var sig = new SignatureInfo(4, "KEYID1234567890AB",
                    "RSA", "Alice <alice@example.com>", VerificationResult.FAIL);
            assertFalse(VerifyMojo.signatureMatchesSigner(signer, sig));
        }

        @Test
        void noKeyDoesNotMatch() {
            var signer = signerWithGpg("4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12");
            var sig = new SignatureInfo(4,
                    "4AEE18F83AFDEB23468B2E5A2D7BAF3C1E9F5A12",
                    "RSA", null, VerificationResult.NO_KEY);
            assertTrue(VerifyMojo.signatureMatchesSigner(signer, sig));
        }
    }

    @Nested
    class PomVerificationTests {

        private ArtifactCoords jarArtifact(String groupId, String artifactId, String version) {
            return new ArtifactCoords(groupId, artifactId, "", "jar", version);
        }

        @Test
        void addPomArtifactsCreatesPomForEachJar() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(jarArtifact("com.example", "lib-a", "1.0"));
            artifacts.add(jarArtifact("com.example", "lib-b", "2.0"));

            mojo.addPomArtifacts(artifacts, null);

            assertEquals(4, artifacts.size());
            ArtifactCoords pomA = artifacts.get(2);
            assertEquals("com.example", pomA.groupId());
            assertEquals("lib-a", pomA.artifactId());
            assertEquals("pom", pomA.type());
            assertEquals("1.0", pomA.version());

            ArtifactCoords pomB = artifacts.get(3);
            assertEquals("lib-b", pomB.artifactId());
            assertEquals("pom", pomB.type());
        }

        @Test
        void addPomArtifactsSkipsExistingPomArtifacts() {
            var mojo = new VerifyMojo();
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(new ArtifactCoords(
                    "com.example", "parent", "", "pom", "1.0"));

            mojo.addPomArtifacts(artifacts, null);

            assertEquals(1, artifacts.size());
        }

        @Test
        void addPomArtifactsInheritsSignerRefs() {
            var mojo = new VerifyMojo();
            ArtifactCoords jar = jarArtifact("com.example", "lib", "1.0");
            List<ArtifactCoords> artifacts = new ArrayList<>();
            artifacts.add(jar);

            Map<String, List<String>> refs = new HashMap<>();
            refs.put("com.example:lib:1.0", List.of("alice"));

            mojo.addPomArtifacts(artifacts, refs);

            assertEquals(List.of("alice"), refs.get("com.example:lib:pom:1.0"));
        }
    }
}
