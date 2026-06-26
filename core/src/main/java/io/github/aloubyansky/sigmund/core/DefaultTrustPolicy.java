package io.github.aloubyansky.sigmund.core;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Default {@link TrustPolicy} implementation backed by parsed configuration.
 * <p>
 * Pattern matching uses a colon-separated format with 1–3 parts:
 * {@code namespace}, {@code namespace:name}, or {@code namespace:name:version}.
 * Wildcards ({@code *}) match any value. When multiple patterns match,
 * the most specific one wins (exact matches score higher than wildcards,
 * and more segments score higher than fewer).
 */
public class DefaultTrustPolicy implements TrustPolicy {

    static final DefaultTrustPolicy EMPTY = new DefaultTrustPolicy(
            Map.of(), List.of(), false, UntrustedPolicy.FAIL);

    private final Map<String, List<SignerIdentity>> trustMappings;
    private final List<String> unsignedPatterns;
    private final boolean requireAllEvidenceMatch;
    private final UntrustedPolicy untrustedPolicy;

    /**
     * Creates a new default trust policy.
     *
     * @param trustMappings artifact patterns mapped to expected signers
     * @param unsignedPatterns patterns for artifacts allowed to be unsigned
     * @param requireAllEvidenceMatch whether all evidence must match
     * @param untrustedPolicy how to handle untrusted artifacts
     */
    public DefaultTrustPolicy(
            Map<String, List<SignerIdentity>> trustMappings,
            List<String> unsignedPatterns,
            boolean requireAllEvidenceMatch,
            UntrustedPolicy untrustedPolicy) {
        this.trustMappings = Map.copyOf(trustMappings);
        this.unsignedPatterns = List.copyOf(unsignedPatterns);
        this.requireAllEvidenceMatch = requireAllEvidenceMatch;
        this.untrustedPolicy = untrustedPolicy;
    }

    @Override
    public List<SignerIdentity> expectedSigners(ArtifactIdentity artifact) {
        String bestPattern = findBestMatch(artifact, trustMappings.keySet());
        if (bestPattern == null) {
            return List.of();
        }
        return trustMappings.get(bestPattern);
    }

    @Override
    public boolean isUnsignedAllowed(ArtifactIdentity artifact) {
        return findBestMatch(artifact, unsignedPatterns) != null;
    }

    @Override
    public boolean requireAllEvidenceMatch() {
        return requireAllEvidenceMatch;
    }

    @Override
    public UntrustedPolicy onUntrusted() {
        return untrustedPolicy;
    }

    private String findBestMatch(ArtifactIdentity artifact, Iterable<String> patterns) {
        String best = null;
        int bestScore = -1;
        for (String pattern : patterns) {
            int score = matchScore(artifact, pattern);
            if (score > bestScore) {
                bestScore = score;
                best = pattern;
            }
        }
        return best;
    }

    static int matchScore(ArtifactIdentity artifact, String pattern) {
        String[] parts = pattern.split(":", -1);
        return switch (parts.length) {
            case 1 -> scoreSegment(parts[0], artifact.namespace()) >= 0
                    ? scoreNamespace(parts[0], artifact.namespace())
                    : -1;
            case 2 -> scoreTwoParts(parts, artifact);
            case 3 -> scoreThreeParts(parts, artifact);
            default -> -1;
        };
    }

    private static int scoreTwoParts(String[] parts, ArtifactIdentity artifact) {
        int ns = scoreSegment(parts[0], artifact.namespace());
        int name = scoreSegment(parts[1], artifact.name());
        if (ns < 0 || name < 0) {
            return -1;
        }
        return scoreNamespace(parts[0], artifact.namespace()) + name;
    }

    private static int scoreThreeParts(String[] parts, ArtifactIdentity artifact) {
        int ns = scoreSegment(parts[0], artifact.namespace());
        int name = scoreSegment(parts[1], artifact.name());
        int ver = scoreSegment(parts[2], artifact.version());
        if (ns < 0 || name < 0 || ver < 0) {
            return -1;
        }
        return scoreNamespace(parts[0], artifact.namespace()) + name + ver;
    }

    /**
     * Namespace scoring: segment count × 10 to dominate other segments.
     * "com.example" (2 segments) scores 20, "com.example.sub" (3 segments) scores 30.
     */
    private static int scoreNamespace(String pattern, String value) {
        if ("*".equals(pattern)) {
            return 0;
        }
        if (pattern.endsWith(".*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            if (value.equals(prefix) || value.startsWith(prefix + ".")) {
                return countSegments(prefix) * 10;
            }
            return -1;
        }
        if (pattern.equals(value)) {
            return (countSegments(pattern) + 1) * 10;
        }
        return -1;
    }

    private static int scoreSegment(String pattern, String value) {
        if ("*".equals(pattern)) {
            return 0;
        }
        if (pattern.equals(value)) {
            return 2;
        }
        if (pattern.endsWith(".*") || pattern.endsWith("*")) {
            String prefix = pattern.endsWith(".*")
                    ? pattern.substring(0, pattern.length() - 2)
                    : pattern.substring(0, pattern.length() - 1);
            if (value.startsWith(prefix)) {
                return 1;
            }
        }
        return -1;
    }

    private static int countSegments(String s) {
        int count = 1;
        for (int i = 0; i < s.length(); i++) {
            if (s.charAt(i) == '.') {
                count++;
            }
        }
        return count;
    }

    /**
     * Creates a builder-like list of trust mappings from raw parsed data.
     */
    static Map<String, List<SignerIdentity>> resolveTrustMappings(
            Map<String, List<String>> rawTrust,
            Map<String, SignerIdentity> signers) {
        var result = new java.util.LinkedHashMap<String, List<SignerIdentity>>();
        for (var entry : rawTrust.entrySet()) {
            List<SignerIdentity> resolved = new ArrayList<>();
            for (String ref : entry.getValue()) {
                SignerIdentity signer = signers.get(ref);
                if (signer == null) {
                    throw new PolicyConfigException(
                            "Trust entry '" + entry.getKey() + "' references undefined signer '" + ref + "'");
                }
                resolved.add(signer);
            }
            result.put(entry.getKey(), List.copyOf(resolved));
        }
        return result;
    }
}
