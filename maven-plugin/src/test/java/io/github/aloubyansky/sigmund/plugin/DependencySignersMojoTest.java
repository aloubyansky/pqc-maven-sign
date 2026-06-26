package io.github.aloubyansky.sigmund.plugin;

import static org.junit.jupiter.api.Assertions.*;

import io.github.aloubyansky.sigmund.core.SignatureInfo;
import io.github.aloubyansky.sigmund.core.VerificationResult;
import io.github.aloubyansky.sigmund.plugin.SignatureInspector.SignedArtifact;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class DependencySignersMojoTest {

    @Test
    void signedArtifact_v4WithSigner() {
        SignedArtifact signer = new SignedArtifact(
                "com.example:lib:1.0", "central",
                new SignatureInfo(4, "ABCD1234", "RSA", "User <user@example.com>", VerificationResult.PASS));
        assertEquals("com.example:lib:1.0", signer.coordinates());
        assertEquals("central", signer.repoId());
        assertEquals(4, signer.signatureInfo().version());
        assertEquals("ABCD1234", signer.signatureInfo().keyId());
        assertEquals("User <user@example.com>", signer.signatureInfo().signerUserId());
    }

    @Test
    void signedArtifact_v6Detected() {
        SignedArtifact signer = new SignedArtifact(
                "com.example:lib:1.0", "central",
                new SignatureInfo(6, null, null, null, VerificationResult.SKIPPED));
        assertEquals(6, signer.signatureInfo().version());
        assertNull(signer.signatureInfo().keyId());
        assertEquals(VerificationResult.SKIPPED, signer.signatureInfo().result());
    }

    @Test
    void signedArtifact_noSignature() {
        SignedArtifact signer = new SignedArtifact(
                "com.example:lib:1.0", null,
                new SignatureInfo(-1, null, null, null, VerificationResult.SKIPPED));
        assertNull(signer.repoId());
        assertEquals(-1, signer.signatureInfo().version());
    }

    // --- ArtifactCoords.toString tests ---

    @Test
    void artifactCoords_simpleJar() {
        ArtifactCoords coords = createArtifact("com.example", "lib", "1.0");
        assertEquals("com.example:lib:1.0", coords.toString());
    }

    @Test
    void artifactCoords_withClassifier() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "sources", "jar", "1.0");
        assertEquals("com.example:lib:jar:sources:1.0", coords.toString());
    }

    @Test
    void artifactCoords_nonJarType() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "", "pom", "1.0");
        assertEquals("com.example:lib:pom:1.0", coords.toString());
    }

    @Test
    void artifactCoords_nonJarTypeWithClassifier() {
        ArtifactCoords coords = new ArtifactCoords(
                "com.example", "lib", "dist", "zip", "1.0");
        assertEquals("com.example:lib:zip:dist:1.0", coords.toString());
    }

    @Nested
    class GenerateSignerIdTests {

        private final DependencySignersMojo mojo = new DependencySignersMojo();

        @Test
        void normalUidProducesKebabCaseId() {
            var sig = new SignatureInfo(4, "KEY1", "RSA",
                    "John Smith <john@example.com>", VerificationResult.PASS);
            assertEquals("john-smith", mojo.generateSignerId(sig, 1));
        }

        @Test
        void uidWithoutEmailBrackets() {
            var sig = new SignatureInfo(4, "KEY1", "RSA",
                    "Jane Doe", VerificationResult.PASS);
            assertEquals("jane-doe", mojo.generateSignerId(sig, 1));
        }

        @Test
        void emptyNameFallsBackToCounter() {
            var sig = new SignatureInfo(4, "KEY1", "RSA",
                    " <user@example.com>", VerificationResult.PASS);
            assertEquals("signer-1", mojo.generateSignerId(sig, 1));
        }

        @Test
        void specialCharsOnlyFallsBackToCounter() {
            var sig = new SignatureInfo(4, "KEY1", "RSA",
                    "... <user@example.com>", VerificationResult.PASS);
            assertEquals("signer-2", mojo.generateSignerId(sig, 2));
        }

        @Test
        void nullUidFallsBackToCounter() {
            var sig = new SignatureInfo(4, "KEY1", "RSA",
                    null, VerificationResult.PASS);
            assertEquals("signer-3", mojo.generateSignerId(sig, 3));
        }

        @Test
        void collisionProducesUniqueSuffix() {
            var sig1 = new SignatureInfo(4, "KEY1", "RSA",
                    "John Smith <john@a.com>", VerificationResult.PASS);
            var sig2 = new SignatureInfo(4, "KEY2", "RSA",
                    "John Smith <john@b.com>", VerificationResult.PASS);

            Map<String, DependencySignersMojo.SignerInfo> existingSigners = new LinkedHashMap<>();
            var info1 = new DependencySignersMojo.SignerInfo(
                    mojo.resolveUniqueSignerId(sig1, 1, existingSigners, Set.of()), sig1);
            existingSigners.put("KEY1", info1);

            String id2 = mojo.resolveUniqueSignerId(sig2, 2, existingSigners, Set.of());
            assertEquals("john-smith", info1.id);
            assertEquals("john-smith-2", id2);
        }

        @Test
        void collisionWithReservedIds() {
            var sig = new SignatureInfo(4, "KEY1", "RSA",
                    "Alice <alice@example.com>", VerificationResult.PASS);
            String id = mojo.resolveUniqueSignerId(sig, 1, new LinkedHashMap<>(), Set.of("alice"));
            assertEquals("alice-2", id);
        }
    }

    private ArtifactCoords createArtifact(String groupId, String artifactId, String version) {
        return new ArtifactCoords(groupId, artifactId, "", "jar", version);
    }
}
