package io.github.aloubyansky.pqc.maven.core;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class HybridVerifierTest {

    @Test
    void reportBothPass() {
        VerificationReport report = new VerificationReport(
                VerificationResult.PASS,
                "0xABCD1234",
                VerificationResult.PASS,
                SqRunner.DEFAULT_PQC_ALGORITHM,
                "abc123def456");

        assertTrue(report.isStrictPass());
        assertTrue(report.isTransitionalPass());

        String formatted = report.format();
        assertTrue(formatted.contains("PASS"));
        assertTrue(formatted.contains("0xABCD1234"));
        assertTrue(formatted.contains(SqRunner.DEFAULT_PQC_ALGORITHM));
        assertTrue(formatted.contains("abc123def456"));
    }

    @Test
    void reportClassicPassPqcNoKey() {
        VerificationReport report = new VerificationReport(
                VerificationResult.PASS,
                "0xABCD1234",
                VerificationResult.NO_KEY,
                SqRunner.DEFAULT_PQC_ALGORITHM,
                null);

        assertFalse(report.isStrictPass());
        assertTrue(report.isTransitionalPass());

        String formatted = report.format();
        assertTrue(formatted.contains("NO_KEY"));
    }

    @Test
    void reportClassicPassPqcNotPresent() {
        VerificationReport report = new VerificationReport(
                VerificationResult.PASS,
                "0xABCD1234",
                VerificationResult.NOT_PRESENT,
                null,
                null);

        assertFalse(report.isStrictPass());
        assertTrue(report.isTransitionalPass());

        String formatted = report.format();
        assertTrue(formatted.contains("NOT PRESENT"));
    }

    @Test
    void reportBothFail() {
        VerificationReport report = new VerificationReport(
                VerificationResult.FAIL,
                "0xABCD1234",
                VerificationResult.FAIL,
                SqRunner.DEFAULT_PQC_ALGORITHM,
                "abc123def456");

        assertFalse(report.isStrictPass());
        assertFalse(report.isTransitionalPass());

        String formatted = report.format();
        assertTrue(formatted.contains("FAIL"));
    }

    @Test
    void reportClassicFailPqcPass() {
        VerificationReport report = new VerificationReport(
                VerificationResult.FAIL,
                "0xABCD1234",
                VerificationResult.PASS,
                SqRunner.DEFAULT_PQC_ALGORITHM,
                "abc123def456");

        assertFalse(report.isStrictPass());
        assertFalse(report.isTransitionalPass());
    }

    @Test
    void reportNullKeyId() {
        VerificationReport report = new VerificationReport(
                VerificationResult.PASS,
                null,
                VerificationResult.PASS,
                SqRunner.DEFAULT_PQC_ALGORITHM,
                "abc123def456");

        String formatted = report.format();
        boolean classicLineHasNoKey = false;
        for (String line : formatted.split("\n")) {
            if (line.contains("Classic (GPG)") && !line.contains("[key:")) {
                classicLineHasNoKey = true;
                break;
            }
        }
        assertTrue(classicLineHasNoKey);
        assertTrue(formatted.contains("PASS"));
    }

    @Test
    void reportNullPqcFingerprint() {
        VerificationReport report = new VerificationReport(
                VerificationResult.PASS,
                "0xABCD1234",
                VerificationResult.PASS,
                SqRunner.DEFAULT_PQC_ALGORITHM,
                null);

        String formatted = report.format();
        boolean pqcLineHasNoKey = false;
        for (String line : formatted.split("\n")) {
            if (line.contains(SqRunner.DEFAULT_PQC_ALGORITHM) && !line.contains("[key:")) {
                pqcLineHasNoKey = true;
                break;
            }
        }
        assertTrue(pqcLineHasNoKey);
    }

    @Test
    void pqcKeyConfigCertFile() {
        PqcKeyConfig config = PqcKeyConfig.certFile(Path.of("/tmp/cert.pem"));
        assertTrue(config.isCertFile());
        assertFalse(config.isFingerprint());
        assertEquals(Path.of("/tmp/cert.pem"), config.certFilePath());
    }

    @Test
    void pqcKeyConfigFingerprint() {
        PqcKeyConfig config = PqcKeyConfig.fingerprint("ABCD1234");
        assertFalse(config.isCertFile());
        assertTrue(config.isFingerprint());
        assertEquals("ABCD1234", config.fingerprint());
    }

    @Test
    void pqcKeyConfigNullFingerprintThrows() {
        assertThrows(IllegalArgumentException.class, () -> PqcKeyConfig.fingerprint(null));
    }

    @Test
    void pqcKeyConfigNullCertFileThrows() {
        assertThrows(IllegalArgumentException.class, () -> PqcKeyConfig.certFile(null));
    }

    @Nested
    class VerifyTests {

        @TempDir
        Path tempDir;

        private static final String FP = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

        private static final byte[] V4_PACKET = {
                (byte) 0x88, 0x5E, 0x04, 0x00, 0x11, 0x08, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x09, 0x00, 0x0A, 0x09, 0x10
        };

        private static final byte[] V6_PACKET = {
                (byte) 0x88, 0x10, 0x06, 0x00, 0x11, 0x08, 0x00, 0x06,
                0x05, 0x02, 0x61, 0x74, 0x00, 0x09, 0x00, 0x0A, 0x09, 0x10
        };

        private Path writeArtifact() throws IOException {
            Path artifact = tempDir.resolve("test.jar");
            Files.writeString(artifact, "test content");
            return artifact;
        }

        private Path writeCombinedAsc(String v4Block, String v6Block) throws IOException {
            String combined = AscCombiner.combine(v4Block, v6Block);
            Path sig = tempDir.resolve("test.jar.asc");
            Files.writeString(sig, combined);
            return sig;
        }

        private Path writeSingleBlockAsc(String block) throws IOException {
            Path sig = tempDir.resolve("test.jar.asc");
            Files.writeString(sig, block);
            return sig;
        }

        private GpgRunner mockGpg(VerificationResult result, String keyId) {
            return new GpgRunner() {
                @Override
                public VerifyResult verify(Path artifactFile, Path signatureFile) {
                    return new VerifyResult(result, keyId, "RSA", "Test User <test@test.com>");
                }
            };
        }

        private SqRunner mockSq(boolean verifyResult) {
            return new SqRunner(tempDir) {
                @Override
                public boolean verify(Path artifactFile, Path signatureFile, String signerFingerprint) {
                    return verifyResult;
                }

                @Override
                public boolean verifyCertFile(Path artifactFile, Path signatureFile, Path certFile) {
                    return verifyResult;
                }
            };
        }

        @Test
        void verifyBothPassStrictPass() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeCombinedAsc(AscCombiner.armor(V4_PACKET), AscCombiner.armor(V6_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSq(true));

            VerificationReport report = verifier.verify(artifact, sig, PqcKeyConfig.fingerprint(FP));

            assertTrue(report.isStrictPass());
            assertTrue(report.isTransitionalPass());
            assertEquals(VerificationResult.PASS, report.classicResult());
            assertEquals(VerificationResult.PASS, report.pqcResult());
            assertEquals("KEY123", report.classicKeyId());
            assertEquals(SqRunner.DEFAULT_PQC_ALGORITHM, report.pqcAlgorithm());
            assertEquals(FP, report.pqcKeyFingerprint());
        }

        @Test
        void verifyClassicPassPqcFailsTransitionalPassOnly() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeCombinedAsc(AscCombiner.armor(V4_PACKET), AscCombiner.armor(V6_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSq(false));

            VerificationReport report = verifier.verify(artifact, sig, PqcKeyConfig.fingerprint(FP));

            assertFalse(report.isStrictPass());
            assertTrue(report.isTransitionalPass());
            assertEquals(VerificationResult.PASS, report.classicResult());
            assertEquals(VerificationResult.FAIL, report.pqcResult());
        }

        @Test
        void verifyClassicFailsBothModeFail() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeCombinedAsc(AscCombiner.armor(V4_PACKET), AscCombiner.armor(V6_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.FAIL, "KEY123"),
                    mockSq(true));

            VerificationReport report = verifier.verify(artifact, sig, PqcKeyConfig.fingerprint(FP));

            assertFalse(report.isStrictPass());
            assertFalse(report.isTransitionalPass());
            assertEquals(VerificationResult.FAIL, report.classicResult());
        }

        @Test
        void verifyNoPqcBlockPqcNotPresent() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeSingleBlockAsc(AscCombiner.armor(V4_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSq(true));

            VerificationReport report = verifier.verify(artifact, sig, PqcKeyConfig.fingerprint(FP));

            assertTrue(report.isTransitionalPass());
            assertFalse(report.isStrictPass());
            assertEquals(VerificationResult.PASS, report.classicResult());
            assertEquals(VerificationResult.NOT_PRESENT, report.pqcResult());
        }

        @Test
        void verifySqRunnerNullPqcSkipped() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeCombinedAsc(AscCombiner.armor(V4_PACKET), AscCombiner.armor(V6_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    null);

            VerificationReport report = verifier.verify(artifact, sig, PqcKeyConfig.fingerprint(FP));

            assertTrue(report.isTransitionalPass());
            assertEquals(VerificationResult.PASS, report.classicResult());
            assertEquals(VerificationResult.SKIPPED, report.pqcResult());
        }

        @Test
        void verifyPqcKeyConfigNullPqcSkipped() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeCombinedAsc(AscCombiner.armor(V4_PACKET), AscCombiner.armor(V6_PACKET));

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSq(true));

            VerificationReport report = verifier.verify(artifact, sig, null);

            assertTrue(report.isTransitionalPass());
            assertEquals(VerificationResult.PASS, report.classicResult());
            assertEquals(VerificationResult.SKIPPED, report.pqcResult());
        }

        @Test
        void verifyCertFileCallsVerifyCertFile() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeCombinedAsc(AscCombiner.armor(V4_PACKET), AscCombiner.armor(V6_PACKET));
            Path certFile = tempDir.resolve("cert.pem");
            Files.writeString(certFile, "fake cert");

            AtomicBoolean certFileVerifyCalled = new AtomicBoolean(false);

            SqRunner sq = new SqRunner(tempDir) {
                @Override
                public boolean verify(Path artifactFile, Path signatureFile, String signerFingerprint) {
                    fail("verify() should not be called when certFile is set");
                    return false;
                }

                @Override
                public boolean verifyCertFile(Path artifactFile, Path signatureFile, Path cert) {
                    certFileVerifyCalled.set(true);
                    return true;
                }
            };

            HybridVerifier verifier = new HybridVerifier(mockGpg(VerificationResult.PASS, "KEY123"), sq);
            VerificationReport report = verifier.verify(artifact, sig, PqcKeyConfig.certFile(certFile));

            assertTrue(certFileVerifyCalled.get());
            assertEquals(VerificationResult.PASS, report.pqcResult());
        }

        @Test
        void verifyNoClassicBlockClassicNotPresent() throws Exception {
            Path artifact = writeArtifact();
            Path sig = writeSingleBlockAsc(AscCombiner.armor(V6_PACKET));

            GpgRunner gpg = new GpgRunner() {
                @Override
                public VerifyResult verify(Path artifactFile, Path signatureFile) {
                    fail("GPG verify should not be called when no classic block present");
                    return null;
                }
            };

            HybridVerifier verifier = new HybridVerifier(gpg, mockSq(true));
            VerificationReport report = verifier.verify(artifact, sig, PqcKeyConfig.fingerprint(FP));

            assertEquals(VerificationResult.NOT_PRESENT, report.classicResult());
            assertEquals(VerificationResult.PASS, report.pqcResult());
        }

        @Test
        void verifyUnreadableSignatureFileBothFail() throws Exception {
            Path artifact = writeArtifact();
            Path nonexistent = tempDir.resolve("nonexistent.asc");

            HybridVerifier verifier = new HybridVerifier(
                    mockGpg(VerificationResult.PASS, "KEY123"),
                    mockSq(true));

            VerificationReport report = verifier.verify(artifact, nonexistent, PqcKeyConfig.fingerprint(FP));

            assertEquals(VerificationResult.FAIL, report.classicResult());
            assertEquals(VerificationResult.FAIL, report.pqcResult());
        }

        @Test
        void verifyNullArtifactFileThrows() {
            HybridVerifier verifier = new HybridVerifier(mockGpg(VerificationResult.PASS, "KEY123"), null);
            assertThrows(IllegalArgumentException.class,
                    () -> verifier.verify(null, tempDir.resolve("sig.asc"), null));
        }

        @Test
        void verifyNullSignatureFileThrows() throws Exception {
            Path artifact = writeArtifact();
            HybridVerifier verifier = new HybridVerifier(mockGpg(VerificationResult.PASS, "KEY123"), null);
            assertThrows(IllegalArgumentException.class,
                    () -> verifier.verify(artifact, null, null));
        }

        @Test
        void constructorNullGpgThrows() {
            assertThrows(IllegalArgumentException.class, () -> new HybridVerifier(null, null));
        }
    }
}
