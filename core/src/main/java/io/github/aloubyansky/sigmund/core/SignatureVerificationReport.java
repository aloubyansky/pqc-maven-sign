package io.github.aloubyansky.sigmund.core;

import java.util.List;

/**
 * Hierarchical verification report for direct signature verification (without trust policy).
 * <p>
 * Aggregates per-file sub-reports. Callers can check the overall outcome or drill
 * into each file's results.
 */
public class SignatureVerificationReport {

    private final List<FileSignatureReport> files;

    /**
     * Creates a new report from per-file sub-reports.
     *
     * @param files the per-file verification reports
     */
    public SignatureVerificationReport(List<FileSignatureReport> files) {
        this.files = List.copyOf(files);
    }

    /**
     * Returns the aggregate verification outcome.
     *
     * @return the overall outcome
     */
    public VerificationOutcome outcome() {
        boolean anyPass = false;
        boolean anyFail = false;
        boolean anySkip = false;
        for (FileSignatureReport file : files) {
            for (VerifyResult r : file.results()) {
                switch (r.result()) {
                    case PASS -> anyPass = true;
                    case FAIL -> anyFail = true;
                    case NO_KEY, SKIPPED -> anySkip = true;
                    default -> {
                    }
                }
            }
        }
        if (!anyPass && !anyFail && !anySkip) {
            return VerificationOutcome.NONE_PASSED;
        }
        if (anyPass && !anyFail) {
            return anySkip ? VerificationOutcome.PASS_WITH_SKIPS : VerificationOutcome.ALL_PASS;
        }
        if (anyPass) {
            return VerificationOutcome.PASS_WITH_FAILURES;
        }
        return VerificationOutcome.NONE_PASSED;
    }

    /**
     * Returns the per-file sub-reports.
     *
     * @return an unmodifiable list of file reports
     */
    public List<FileSignatureReport> files() {
        return files;
    }

    /**
     * Strict pass: all signatures must be valid.
     *
     * @return {@code true} if outcome is {@link VerificationOutcome#ALL_PASS}
     */
    public boolean isPass() {
        return outcome() == VerificationOutcome.ALL_PASS;
    }

    /**
     * Lenient pass: at least one signature valid, none failed.
     *
     * @return {@code true} if outcome is ALL_PASS or PASS_WITH_SKIPS
     */
    public boolean isLenientPass() {
        var o = outcome();
        return o == VerificationOutcome.ALL_PASS || o == VerificationOutcome.PASS_WITH_SKIPS;
    }

    /**
     * Formats the report as a human-readable multi-line string.
     *
     * @return the formatted report
     */
    public String format() {
        var sb = new StringBuilder();
        sb.append("Signature Verification Report:\n");
        int idx = 1;
        for (FileSignatureReport file : files) {
            for (VerifyResult r : file.results()) {
                sb.append("  [").append(idx++).append("] ");
                formatResult(sb, r);
                sb.append('\n');
            }
        }
        sb.append("  Overall: ").append(outcome());
        return sb.toString();
    }

    private void formatResult(StringBuilder sb, VerifyResult r) {
        sb.append(r.result());
        if (r.algorithm() != null) {
            sb.append(" (").append(r.algorithm()).append(')');
        }
        if (r instanceof OpenPgpVerifyResult opvr) {
            if (opvr.keyId() != null) {
                sb.append(" [key: ").append(opvr.keyId()).append(']');
            }
        }
        if (r.signerDisplayName() != null) {
            sb.append(" [signer: ").append(r.signerDisplayName()).append(']');
        }
    }
}
