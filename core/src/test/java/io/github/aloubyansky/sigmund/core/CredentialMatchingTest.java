package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Integration tests for the identity matching algorithm:
 * checks for overlap between a signer's credential bag and
 * evidence's proven credentials.
 */
class CredentialMatchingTest {

    @Test
    void fingerprintMatch_v4() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")));

        var evidence = new EvidenceResult(Verdict.PASS, List.of(
                new FingerprintCredential("openpgp4",
                        "AB01CD23EF45678901234AEE18F83AFDEB23")),
                "openpgp");

        assertTrue(matchesAny(signer, evidence));
    }

    @Test
    void emailMatch_acrossBackends() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new EmailCredential("alice@example.com")));

        // Sigstore produces both OIDC and Email credentials
        var evidence = new EvidenceResult(Verdict.PASS, List.of(
                new OidcCredential("https://accounts.google.com", "alice@example.com"),
                new EmailCredential("alice@example.com")),
                "sigstore");

        assertTrue(matchesAny(signer, evidence));
    }

    @Test
    void oidcMatch_strictIssuer() {
        var signer = new SignerIdentity("ci", "CI Pipeline", List.of(
                new OidcCredential("https://token.actions.githubusercontent.com",
                        "https://github.com/org/repo")));

        var evidence = new EvidenceResult(Verdict.PASS, List.of(
                new OidcCredential("https://token.actions.githubusercontent.com",
                        "https://github.com/org/repo")),
                "sigstore");

        assertTrue(matchesAny(signer, evidence));
    }

    @Test
    void oidcMismatch_wrongIssuer() {
        var signer = new SignerIdentity("ci", "CI Pipeline", List.of(
                new OidcCredential("https://token.actions.githubusercontent.com",
                        "https://github.com/org/repo")));

        var evidence = new EvidenceResult(Verdict.PASS, List.of(
                new OidcCredential("https://evil-issuer.com",
                        "https://github.com/org/repo")),
                "sigstore");

        assertFalse(matchesAny(signer, evidence));
    }

    @Test
    void noOverlap_differentCredentialTypes() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23")));

        var evidence = new EvidenceResult(Verdict.PASS, List.of(
                new EmailCredential("alice@example.com")),
                "sigstore");

        assertFalse(matchesAny(signer, evidence));
    }

    @Test
    void multipleCredentials_oneMatches() {
        var signer = new SignerIdentity("alice", "Alice", List.of(
                new FingerprintCredential("openpgp4", "4AEE18F83AFDEB23"),
                new FingerprintCredential("openpgp6", "ABCD1234ABCD1234"),
                new EmailCredential("alice@example.com")));

        var evidence = new EvidenceResult(Verdict.PASS, List.of(
                new FingerprintCredential("openpgp6", "ABCD1234ABCD1234")),
                "openpgp");

        assertTrue(matchesAny(signer, evidence));
    }

    @Test
    void emptyCredentials_noMatch() {
        var signer = new SignerIdentity("empty", "Empty", List.of());
        var evidence = new EvidenceResult(Verdict.PASS, List.of(
                new EmailCredential("alice@example.com")),
                "sigstore");

        assertFalse(matchesAny(signer, evidence));
    }

    /**
     * Checks for overlap between a signer's credential bag and evidence's proven credentials.
     * This is the same algorithm used by {@code TrustVerifier.assess()}.
     */
    private static boolean matchesAny(SignerIdentity signer, EvidenceResult evidence) {
        for (Credential proven : evidence.provenCredentials()) {
            for (Credential expected : signer.credentials()) {
                if (expected.matches(proven)) {
                    return true;
                }
            }
        }
        return false;
    }
}
