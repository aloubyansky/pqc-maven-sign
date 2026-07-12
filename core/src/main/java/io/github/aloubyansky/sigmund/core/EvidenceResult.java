package io.github.aloubyansky.sigmund.core;

import java.util.List;

/**
 * The output of verifying a piece of evidence.
 * <p>
 * Carries the verification outcome and the proven credentials so that identity matching
 * is type-agnostic — the trust layer only needs {@link #verdict()} and
 * {@link #provenCredentials()}, never provider-specific details.
 * <p>
 * Provider-specific details (OpenPGP key IDs, Sigstore log indices) are handled internally
 * by each {@link EvidenceProvider} and do not leak into the trust layer.
 *
 * <h3>Examples</h3>
 * <ul>
 * <li>A verified OpenPGP v4 signature produces {@code provenCredentials} containing
 * a {@code FingerprintCredential("openpgp4", "AB01CD23...")}.</li>
 * <li>A verified Sigstore bundle produces an {@code EmailCredential("alice@example.com")}.</li>
 * </ul>
 *
 * @param verdict the verification outcome
 * @param provenCredentials the credentials proven by this evidence
 * @param provider the evidence provider name (e.g., {@code "openpgp"}, {@code "sigstore"})
 * @see EvidenceProvider
 * @see TrustResult
 */
public record EvidenceResult(Verdict verdict, List<Credential> provenCredentials, String provider) {

    public EvidenceResult {
        provenCredentials = provenCredentials != null ? List.copyOf(provenCredentials) : List.of();
    }
}
