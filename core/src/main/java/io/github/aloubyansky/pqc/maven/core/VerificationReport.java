package io.github.aloubyansky.pqc.maven.core;

/**
 * Represents the combined result of verifying both classic (GPG) and PQC signatures.
 * <p>
 * This record encapsulates the verification results from both signature components
 * and provides methods to determine overall verification status under different
 * security policies:
 * <ul>
 * <li><b>Strict mode</b>: Both classic and PQC signatures must pass</li>
 * <li><b>Transitional mode</b>: Only the classic signature must pass (PQC optional)</li>
 * </ul>
 *
 * <p>
 * Example usage:
 *
 * <pre>{@code
 * VerificationReport report = verifier.verify(artifactFile, signatureFile);
 *
 * if (report.isStrictPass()) {
 *     System.out.println("Both signatures valid - quantum-safe!");
 * } else if (report.isTransitionalPass()) {
 *     System.out.println("Classic signature valid - transitional security");
 * } else {
 *     System.err.println("Verification failed!");
 * }
 *
 * System.out.println(report.format());
 * }</pre>
 *
 * @param classicResult the result of classic GPG signature verification
 * @param classicKeyId the GPG key ID that signed the artifact, or null if unavailable
 * @param pqcResult the result of PQC signature verification
 * @param pqcAlgorithm the PQC algorithm used (e.g., "ML-DSA-87+Ed448"), or null if
 *        signature not present
 * @param pqcKeyFingerprint the PQC key fingerprint, or null if unavailable
 *
 * @see HybridVerifier
 * @see VerificationResult
 */
public record VerificationReport(
        VerificationResult classicResult,
        String classicKeyId,
        VerificationResult pqcResult,
        String pqcAlgorithm,
        String pqcKeyFingerprint) {

    /**
     * Determines if verification passes under strict security policy.
     * <p>
     * Strict mode requires both classic and PQC signatures to be present and valid.
     * This provides quantum-resistant security by ensuring both signature types pass.
     *
     *
     * @return true if both {@link #classicResult} and {@link #pqcResult} are
     *         {@link VerificationResult#PASS}, false otherwise
     */
    public boolean isStrictPass() {
        return classicResult == VerificationResult.PASS
                && pqcResult == VerificationResult.PASS;
    }

    /**
     * Determines if verification passes under transitional security policy.
     * <p>
     * Transitional mode requires only the classic GPG signature to be valid. This
     * allows for gradual migration to PQC signatures while maintaining backward
     * compatibility with existing classic-only signatures.
     *
     *
     * @return true if {@link #classicResult} is {@link VerificationResult#PASS},
     *         false otherwise (regardless of PQC result)
     */
    public boolean isTransitionalPass() {
        return classicResult == VerificationResult.PASS;
    }

    /**
     * Formats the verification report as a human-readable multi-line string.
     * <p>
     * The output includes:
     * <ul>
     * <li>Classic (GPG) verification result with optional key ID</li>
     * <li>PQC verification result with algorithm and optional fingerprint</li>
     * <li>Overall assessment based on both results</li>
     * </ul>
     *
     * <p>
     * Example output:
     *
     * <pre>
     * Signature Verification Report:
     *   Classic (GPG):           PASS    [key: 0xABCD1234]
     *   PQC (ML-DSA-87+Ed448):   PASS    [key: abc123def456]
     *   Overall: PASS (both signatures valid)
     * </pre>
     *
     * @return a formatted multi-line string describing the verification results
     */
    public String format() {
        StringBuilder sb = new StringBuilder();
        sb.append("Signature Verification Report:\n");
        sb.append(formatClassicLine()).append("\n");
        sb.append(formatPqcLine()).append("\n");
        sb.append(formatOverallLine());
        return sb.toString();
    }

    /**
     * Formats the classic (GPG) verification result line.
     * <p>
     * The line includes the result status and optionally the key ID if available.
     * The result is left-padded to align with the PQC line.
     *
     *
     * @return a formatted string like " Classic (GPG): PASS [key: 0xABCD1234]"
     */
    private int resultColumn() {
        String algorithm = (pqcAlgorithm != null) ? pqcAlgorithm : "unknown";
        int pqcPrefix = "  PQC (".length() + algorithm.length() + "): ".length();
        int classicPrefix = "  Classic (GPG): ".length();
        return Math.max(pqcPrefix, classicPrefix);
    }

    private String formatClassicLine() {
        StringBuilder sb = new StringBuilder();
        String prefix = "  Classic (GPG): ";
        sb.append(prefix);
        sb.append(" ".repeat(resultColumn() - prefix.length()));
        sb.append(String.format("%-11s", classicResult));

        if (classicKeyId != null && !classicKeyId.isEmpty()) {
            sb.append(" [key: ").append(classicKeyId).append("]");
        }

        return sb.toString();
    }

    /**
     * Formats the PQC verification result line.
     * <p>
     * The line includes the algorithm name (or "unknown" if not present), the
     * result status, and optionally the key fingerprint. Special handling for
     * {@link VerificationResult#NOT_PRESENT} displays a user-friendly message.
     *
     *
     * @return a formatted string like " PQC (ML-DSA-87+Ed448): PASS [key: abc123]"
     */
    private String formatPqcLine() {
        StringBuilder sb = new StringBuilder();
        String algorithm = (pqcAlgorithm != null) ? pqcAlgorithm : "unknown";
        String prefix = "  PQC (" + algorithm + "): ";
        sb.append(prefix);
        sb.append(" ".repeat(resultColumn() - prefix.length()));

        if (pqcResult == VerificationResult.NOT_PRESENT) {
            sb.append("NOT PRESENT (classic-only signature)");
        } else {
            sb.append(String.format("%-11s", pqcResult));

            if (pqcKeyFingerprint != null && !pqcKeyFingerprint.isEmpty()) {
                sb.append(" [key: ").append(pqcKeyFingerprint).append("]");
            }
        }

        return sb.toString();
    }

    /**
     * Formats the overall assessment line based on both results.
     * <p>
     * The assessment describes the combined security status:
     * <ul>
     * <li>Both PASS: "PASS (both signatures valid)"</li>
     * <li>Classic PASS, PQC not PASS: "TRANSITIONAL PASS (classic valid, PQC...)"</li>
     * <li>Classic FAIL: "FAIL (classic signature invalid)"</li>
     * </ul>
     *
     *
     * @return a formatted string like " Overall: PASS (both signatures valid)"
     */
    private String formatOverallLine() {
        StringBuilder sb = new StringBuilder();
        sb.append("  Overall: ");

        if (isStrictPass()) {
            sb.append("PASS (both signatures valid)");
        } else if (isTransitionalPass()) {
            sb.append("TRANSITIONAL PASS (classic valid, ");
            if (pqcResult == VerificationResult.NOT_PRESENT) {
                sb.append("PQC not present");
            } else if (pqcResult == VerificationResult.NO_KEY) {
                sb.append("PQC key not available");
            } else {
                sb.append("PQC invalid");
            }
            sb.append(")");
        } else {
            sb.append("FAIL (");
            if (classicResult == VerificationResult.NO_KEY) {
                sb.append("classic key not available");
            } else {
                sb.append("classic signature invalid");
            }
            sb.append(")");
        }

        return sb.toString();
    }
}
