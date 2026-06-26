package io.github.aloubyansky.sigmund.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Bridges Layer 2 (signature operations) to Layer 1 (identity verification).
 * <p>
 * Wraps a {@link SignatureFormat} and its associated {@link SignatureTool}s into an
 * {@link EvidenceProvider}. There is one adapter per format, not per tool — the adapter
 * parses the file once and routes each {@link VerificationUnit} to the right tool via
 * {@link SignatureTool#canVerify(VerificationUnit)}.
 *
 * <h3>Verification flow</h3>
 * <ol>
 * <li>{@link SignatureFormat#canHandle(Path)} → detection</li>
 * <li>{@link SignatureFormat#parse(Path)} → {@link VerificationUnit}s</li>
 * <li>For each unit, find a {@link SignatureTool} where {@code canVerify(unit)} is true</li>
 * <li>{@link SignatureTool#verify(Path, VerificationUnit)} → {@link VerifyResult}</li>
 * <li>If {@code NO_KEY} and key fetching is enabled, fetch and retry</li>
 * <li>{@link SignatureTool#extractCredentials(VerifyResult)} → proven credentials</li>
 * <li>Wrap into {@link EvidenceResult}</li>
 * </ol>
 *
 * <h3>Key fetching</h3>
 * <p>
 * Key fetching lives in this adapter because it has all the context needed: the
 * {@link VerificationUnit} (with the fingerprint to fetch), the {@link SignatureTool}
 * (to re-verify), and the {@link DiscoveryConfig} (with keyserver and import settings).
 *
 * @see EvidenceProvider
 * @see SignatureFormat
 * @see SignatureTool
 */
public class SignatureEvidenceAdapter implements EvidenceProvider {

    private final SignatureFormat format;
    private final List<SignatureTool> tools;
    private final DiscoveryConfig discoveryConfig;

    /**
     * Creates a new adapter bridging the given format and tools into an evidence provider.
     *
     * @param format the signature format (e.g., {@link OpenPgpSignatureFormat})
     * @param tools the tools that can verify units of this format
     * @param discoveryConfig configuration for key fetching behavior
     */
    public SignatureEvidenceAdapter(SignatureFormat format, List<SignatureTool> tools,
            DiscoveryConfig discoveryConfig) {
        this.format = format;
        this.tools = List.copyOf(tools);
        this.discoveryConfig = discoveryConfig != null ? discoveryConfig : DiscoveryConfig.DEFAULT;
    }

    @Override
    public String name() {
        return format.name();
    }

    @Override
    public boolean isAvailable() {
        return tools.stream().anyMatch(SignatureTool::isAvailable);
    }

    @Override
    public boolean canHandle(Path evidenceFile) {
        return format.canHandle(evidenceFile);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Parses the evidence file into verification units, verifies each unit with
     * the appropriate tool, optionally fetches missing keys, and wraps results
     * into {@link EvidenceResult}s.
     */
    @Override
    public List<EvidenceResult> verify(Path artifactFile, Path evidenceFile) {
        List<VerificationUnit> units = parseUnits(evidenceFile);
        List<EvidenceResult> results = new ArrayList<>(units.size());
        for (VerificationUnit unit : units) {
            results.add(verifyUnit(artifactFile, unit));
        }
        return results;
    }

    private List<VerificationUnit> parseUnits(Path evidenceFile) {
        return format.parse(evidenceFile);
    }

    private EvidenceResult verifyUnit(Path artifactFile, VerificationUnit unit) {
        SignatureTool tool = routeUnitToTool(unit);
        if (tool == null) {
            return new EvidenceResult(VerificationResult.SKIPPED, List.of(), format.name());
        }

        VerifyResult result = tool.verify(artifactFile, unit);

        if (result.result() == VerificationResult.NO_KEY) {
            result = fetchKeyAndRetry(artifactFile, unit, tool, result);
        }

        return wrapAsEvidence(tool, result);
    }

    private SignatureTool routeUnitToTool(VerificationUnit unit) {
        for (SignatureTool tool : tools) {
            if (tool.canVerify(unit)) {
                return tool;
            }
        }
        return null;
    }

    private VerifyResult fetchKeyAndRetry(Path artifactFile, VerificationUnit unit,
            SignatureTool tool, VerifyResult originalResult) {
        if (!discoveryConfig.fetchSignerInfo()) {
            return originalResult;
        }

        String keyId = extractKeyIdFromUnit(unit);
        if (keyId == null) {
            return originalResult;
        }

        boolean imported = tryImportKey(keyId);
        if (!imported) {
            return originalResult;
        }

        return tool.verify(artifactFile, unit);
    }

    private String extractKeyIdFromUnit(VerificationUnit unit) {
        if (unit instanceof OpenPgpVerificationUnit opgu) {
            return opgu.issuerFingerprint();
        }
        return null;
    }

    private boolean tryImportKey(String keyId) {
        KeyImporter importer = findKeyImporter();
        if (importer == null) {
            return false;
        }

        List<String> keyservers = discoveryConfig.keyservers();
        if (keyservers.isEmpty()) {
            return importer.importKey(keyId, "hkps://keys.openpgp.org");
        }

        for (String keyserver : keyservers) {
            if (importer.importKey(keyId, keyserver)) {
                return true;
            }
        }
        return false;
    }

    private KeyImporter findKeyImporter() {
        for (SignatureTool tool : tools) {
            if (tool instanceof KeyImporter ki) {
                return ki;
            }
        }
        return null;
    }

    private EvidenceResult wrapAsEvidence(SignatureTool tool, VerifyResult result) {
        List<Credential> credentials = tool.extractCredentials(result);
        return new EvidenceResult(result.result(), credentials, format.name());
    }
}
