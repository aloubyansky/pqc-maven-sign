package io.github.aloubyansky.sigmund.core;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The central facade for Sigmund — tool registry, signature verification, and session creation.
 *
 * <h3>Usage from config file</h3>
 *
 * <pre>{@code
 * SigmundConfig config = SigmundConfig.parse(Path.of("sigmund.yaml"));
 * Sigmund sigmund = Sigmund.builder()
 *         .config(config)
 *         .discover()
 *         .build();
 *
 * // Sign
 * Signer signer = sigmund.signer();
 * SigningOutput output = signer.sign(artifact, outputDir);
 *
 * // Verify trust
 * TrustVerifier verifier = sigmund.verifier(config.trustPolicy());
 * TrustResult result = verifier.assess(artifact, artifactFile, evidenceFiles);
 * }</pre>
 *
 * <h3>Programmatic construction</h3>
 *
 * <pre>{@code
 * Sigmund sigmund = Sigmund.builder()
 *         .addTool(new GpgRunner("mykey"))
 *         .addTool(new SqRunner("sq", sqHome, fingerprint))
 *         .build();
 * }</pre>
 *
 * <h3>Verify-only</h3>
 *
 * <pre>{@code
 * Sigmund sigmund = Sigmund.builder().discover().build();
 * SignatureVerificationReport report = sigmund.verify(artifactFile, signatureFile);
 * }</pre>
 *
 * @see Signer
 * @see TrustVerifier
 */
public class Sigmund {

    private final List<SignatureTool> tools;
    private final List<EvidenceProvider> evidenceProviders;
    private final DiscoveryConfig discoveryConfig;
    private final Map<String, SignatureFormat> formats;

    private Sigmund(List<SignatureTool> tools, List<EvidenceProvider> evidenceProviders,
            DiscoveryConfig discoveryConfig) {
        this.tools = List.copyOf(tools);
        this.discoveryConfig = discoveryConfig;
        this.formats = collectFormats(tools);
        this.evidenceProviders = buildProviders(tools, evidenceProviders, discoveryConfig);
    }

    /**
     * Creates a new builder.
     *
     * @return the builder
     */
    public static Builder builder() {
        return new Builder();
    }

    // --- Session creation ---

    /**
     * Creates a signer using all tools where {@link SignatureTool#canSign()} is true.
     *
     * @return a new signer
     */
    public Signer signer() {
        List<SignatureTool> signingTools = tools.stream()
                .filter(SignatureTool::canSign)
                .toList();
        return new Signer(signingTools);
    }

    /**
     * Creates a trust verifier using the given policy.
     * <p>
     * The {@link DiscoveryConfig} set at build time is used for key fetching.
     *
     * @param policy the trust policy to apply
     * @return a new trust verifier
     */
    public TrustVerifier verifier(TrustPolicy policy) {
        return new TrustVerifier(policy, evidenceProviders);
    }

    // --- Direct signature verification ---

    /**
     * Verifies a single signature file against an artifact (no trust policy).
     *
     * @param artifactFile the artifact that was signed
     * @param signatureFile the signature file to verify
     * @return the verification report
     */
    public SignatureVerificationReport verify(Path artifactFile, Path signatureFile) {
        return verifyAll(artifactFile, List.of(signatureFile));
    }

    /**
     * Verifies multiple signature files against an artifact (no trust policy).
     *
     * @param artifactFile the artifact that was signed
     * @param signatureFiles the signature files to verify
     * @return the verification report
     */
    public SignatureVerificationReport verifyAll(Path artifactFile, List<Path> signatureFiles) {
        List<FileSignatureReport> fileReports = new ArrayList<>();
        for (Path sigFile : signatureFiles) {
            fileReports.add(verifySingleFile(artifactFile, sigFile));
        }
        return new SignatureVerificationReport(fileReports);
    }

    // --- Tool access ---

    /**
     * Returns all registered tools.
     *
     * @return an unmodifiable list of tools
     */
    public List<SignatureTool> tools() {
        return tools;
    }

    /**
     * Returns a tool by name.
     *
     * @param name the tool name
     * @return the tool, or {@code null} if not found
     */
    public SignatureTool tool(String name) {
        for (SignatureTool tool : tools) {
            if (tool.name().equals(name)) {
                return tool;
            }
        }
        return null;
    }

    /**
     * Finds the first tool implementing the given capability interface.
     *
     * @param capability the capability interface class (e.g., {@code KeyGenerator.class})
     * @param <T> the capability type
     * @return the tool cast to the capability, or {@code null} if none found
     */
    public <T> T findTool(Class<T> capability) {
        for (SignatureTool tool : tools) {
            if (capability.isInstance(tool)) {
                return capability.cast(tool);
            }
        }
        return null;
    }

    /**
     * Finds a tool implementing the given capability with a specific name.
     *
     * @param capability the capability interface class
     * @param toolName the tool name to match
     * @param <T> the capability type
     * @return the tool cast to the capability, or {@code null} if not found
     */
    public <T> T findTool(Class<T> capability, String toolName) {
        for (SignatureTool tool : tools) {
            if (tool.name().equals(toolName) && capability.isInstance(tool)) {
                return capability.cast(tool);
            }
        }
        return null;
    }

    // --- Private ---

    private FileSignatureReport verifySingleFile(Path artifactFile, Path signatureFile) {
        SignatureFormat format = findFormat(signatureFile);
        if (format == null) {
            return new FileSignatureReport(signatureFile, "unknown", List.of());
        }
        List<VerificationUnit> units = format.parse(signatureFile);
        List<VerifyResult> results = new ArrayList<>();
        for (VerificationUnit unit : units) {
            SignatureTool tool = findToolForUnit(unit);
            if (tool != null) {
                results.add(tool.verify(artifactFile, unit));
            }
        }
        return new FileSignatureReport(signatureFile, format.name(), results);
    }

    private SignatureFormat findFormat(Path signatureFile) {
        for (SignatureFormat format : formats.values()) {
            if (format.canHandle(signatureFile)) {
                return format;
            }
        }
        return null;
    }

    private SignatureTool findToolForUnit(VerificationUnit unit) {
        for (SignatureTool tool : tools) {
            if (tool.isAvailable() && tool.canVerify(unit)) {
                return tool;
            }
        }
        return null;
    }

    private static Map<String, SignatureFormat> collectFormats(List<SignatureTool> tools) {
        Map<String, SignatureFormat> formats = new LinkedHashMap<>();
        for (SignatureTool tool : tools) {
            formats.putIfAbsent(tool.signatureFormat().name(), tool.signatureFormat());
        }
        return formats;
    }

    private static List<EvidenceProvider> buildProviders(List<SignatureTool> tools,
            List<EvidenceProvider> extraProviders, DiscoveryConfig discoveryConfig) {
        Map<String, List<SignatureTool>> toolsByFormat = new LinkedHashMap<>();
        for (SignatureTool tool : tools) {
            toolsByFormat.computeIfAbsent(tool.signatureFormat().name(), k -> new ArrayList<>())
                    .add(tool);
        }

        List<EvidenceProvider> providers = new ArrayList<>();
        for (var entry : toolsByFormat.entrySet()) {
            SignatureFormat format = entry.getValue().get(0).signatureFormat();
            providers.add(new SignatureEvidenceAdapter(format, entry.getValue(), discoveryConfig));
        }
        providers.addAll(extraProviders);
        return providers;
    }

    // --- Builder ---

    /**
     * Builder for constructing a {@link Sigmund} instance.
     * <p>
     * Methods: {@link #discover()} probes for available tools (verify-only).
     * {@link #config(SigmundConfig)} applies the full config including signing and discovery.
     * {@link #addTool(SignatureTool)} adds or replaces a tool (takes precedence over {@code discover()}).
     * {@link #discoveryConfig(DiscoveryConfig)} sets key fetching config (fixed at build time).
     */
    public static class Builder {

        private final Map<String, SignatureTool> toolsByName = new LinkedHashMap<>();
        private final List<EvidenceProvider> extraProviders = new ArrayList<>();
        private DiscoveryConfig discoveryConfig = DiscoveryConfig.DEFAULT;
        private boolean discovered;

        /**
         * Probes for available tools and adds verify-only instances.
         * <p>
         * Only adds tools not already present (explicit {@code addTool()} takes precedence).
         *
         * @return this builder
         */
        public Builder discover() {
            this.discovered = true;
            return this;
        }

        /**
         * Sets key fetching and keyserver configuration, fixed at build time.
         * All {@link TrustVerifier} instances created from this {@link Sigmund} share it.
         *
         * @param dc the discovery configuration
         * @return this builder
         */
        public Builder discoveryConfig(DiscoveryConfig dc) {
            this.discoveryConfig = dc != null ? dc : DiscoveryConfig.DEFAULT;
            return this;
        }

        /**
         * Applies the full configuration: signing tools, discovery config, and tool overrides.
         * <p>
         * Overrides any prior {@code discoveryConfig()} call.
         * Explicit {@code addTool()} calls take precedence over config-derived tools.
         *
         * @param config the unified configuration
         * @return this builder
         */
        public Builder config(SigmundConfig config) {
            this.discoveryConfig = config.discoveryConfig();
            return this;
        }

        /**
         * Adds or replaces a {@link SignatureTool} by {@link SignatureTool#name()}.
         *
         * @param tool the tool to add
         * @return this builder
         */
        public Builder addTool(SignatureTool tool) {
            toolsByName.put(tool.name(), tool);
            return this;
        }

        /**
         * Adds a non-signature {@link EvidenceProvider} (e.g., SLSA attestation verifier).
         *
         * @param provider the evidence provider
         * @return this builder
         */
        public Builder addEvidenceProvider(EvidenceProvider provider) {
            extraProviders.add(provider);
            return this;
        }

        /**
         * Builds the {@link Sigmund} instance.
         * <p>
         * Filters out tools/providers where {@code isAvailable()} returns false.
         *
         * @return the configured Sigmund instance
         */
        public Sigmund build() {
            if (discovered) {
                discoverTools();
            }

            List<SignatureTool> available = toolsByName.values().stream()
                    .filter(SignatureTool::isAvailable)
                    .toList();

            List<EvidenceProvider> availableProviders = extraProviders.stream()
                    .filter(EvidenceProvider::isAvailable)
                    .toList();

            return new Sigmund(available, availableProviders, discoveryConfig);
        }

        private void discoverTools() {
            if (!toolsByName.containsKey("gpg") && GpgRunner.isToolAvailable()) {
                toolsByName.put("gpg", new GpgRunner());
            }
            if (!toolsByName.containsKey("sq") && SqRunner.isToolAvailable()) {
                toolsByName.put("sq", new SqRunner(SqRunner.defaultHome()));
            }
        }
    }
}
