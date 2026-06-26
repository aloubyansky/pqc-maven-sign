package io.github.aloubyansky.sigmund.core;

import java.util.List;

/**
 * The output of verifying a piece of evidence.
 * <p>
 * Carries the verification outcome and the proven credentials so that identity matching
 * is type-agnostic — the trust layer only needs {@link #result()} and
 * {@link #provenCredentials()}, never provider-specific details.
 * <p>
 * Provider-specific details (OpenPGP key IDs, Sigstore log indices) are handled internally
 * by each {@link EvidenceProvider} and do not leak into the trust layer.
 *
 * <h3>Examples</h3>
 * <ul>
 * <li>A verified OpenPGP v4 signature produces {@code provenCredentials} containing
 * a {@code FingerprintCredential("openpgp-v4", "AB01CD23...")}.</li>
 * <li>A verified Sigstore bundle produces an {@code EmailCredential("alice@example.com")}.</li>
 * </ul>
 *
 * @see EvidenceProvider
 * @see TrustResult
 */
public class EvidenceResult {

    private final VerificationResult result;
    private final List<Credential> provenCredentials;
    private final String mechanism;

    /**
     * Creates a new evidence result.
     *
     * @param result the verification outcome
     * @param provenCredentials the credentials proven by this evidence
     * @param mechanism the verification mechanism name (e.g., {@code "openpgp"}, {@code "sigstore"})
     */
    public EvidenceResult(VerificationResult result, List<Credential> provenCredentials,
            String mechanism) {
        this.result = result;
        this.provenCredentials = provenCredentials != null ? List.copyOf(provenCredentials) : List.of();
        this.mechanism = mechanism;
    }

    /**
     * Returns the verification outcome.
     *
     * @return the result (PASS, FAIL, NO_KEY, or SKIPPED)
     */
    public VerificationResult result() {
        return result;
    }

    /**
     * Returns the credentials that this evidence proves.
     * <p>
     * Empty when verification failed or a key was missing. May contain multiple
     * credentials of different types (e.g., both an {@link OidcCredential} and an
     * {@link EmailCredential} for a Sigstore verification).
     *
     * @return an unmodifiable list of proven credentials
     */
    public List<Credential> provenCredentials() {
        return provenCredentials;
    }

    /**
     * Returns the name of the verification mechanism (e.g., {@code "openpgp"},
     * {@code "sigstore"}, {@code "slsa"}).
     *
     * @return the mechanism name
     */
    public String mechanism() {
        return mechanism;
    }
}
