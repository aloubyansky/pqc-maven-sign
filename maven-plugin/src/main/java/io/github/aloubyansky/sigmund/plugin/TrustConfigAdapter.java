package io.github.aloubyansky.sigmund.plugin;

import io.github.aloubyansky.sigmund.core.Credential;
import io.github.aloubyansky.sigmund.core.DefaultTrustPolicy;
import io.github.aloubyansky.sigmund.core.EmailCredential;
import io.github.aloubyansky.sigmund.core.FingerprintCredential;
import io.github.aloubyansky.sigmund.core.GpgRunner;
import io.github.aloubyansky.sigmund.core.SignerIdentity;
import io.github.aloubyansky.sigmund.core.TrustPolicy;
import io.github.aloubyansky.sigmund.core.UntrustedPolicy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Converts the plugin's {@link TrustConfig} (parsed from {@code trust-config.yaml})
 * into the core's {@link TrustPolicy} and {@link SignerIdentity} objects.
 */
class TrustConfigAdapter {

    private final Map<String, SignerIdentity> signerIdentities;
    private final TrustPolicy trustPolicy;

    TrustConfigAdapter(TrustConfig config, TrustConfig.Settings settings) {
        this.signerIdentities = convertSigners(config);
        this.trustPolicy = buildPolicy(config, settings, signerIdentities);
    }

    TrustPolicy trustPolicy() {
        return trustPolicy;
    }

    Map<String, SignerIdentity> signerIdentities() {
        return signerIdentities;
    }

    private static Map<String, SignerIdentity> convertSigners(TrustConfig config) {
        Map<String, SignerIdentity> result = new LinkedHashMap<>();
        for (var entry : config.signers().entrySet()) {
            String ref = entry.getKey();
            TrustConfig.Signer signer = entry.getValue();
            result.put(ref, toSignerIdentity(ref, signer));
        }
        return Map.copyOf(result);
    }

    private static SignerIdentity toSignerIdentity(String ref, TrustConfig.Signer signer) {
        List<Credential> credentials = new ArrayList<>();
        for (TrustConfig.Member member : signer.members()) {
            if (member.gpg() != null) {
                credentials.add(new FingerprintCredential("openpgp-v4", member.gpg()));
            }
            if (member.pqc() != null) {
                credentials.add(new FingerprintCredential("openpgp-v6", member.pqc()));
            }
            if (member.uid() != null) {
                String email = GpgRunner.extractEmail(member.uid());
                if (email != null) {
                    credentials.add(new EmailCredential(email));
                }
            }
        }
        String displayName = signer.name() != null ? signer.name() : ref;
        return new SignerIdentity(ref, displayName, credentials);
    }

    private static TrustPolicy buildPolicy(TrustConfig config, TrustConfig.Settings settings,
            Map<String, SignerIdentity> signerIdentities) {
        Map<String, List<SignerIdentity>> trustMappings = new LinkedHashMap<>();
        Map<String, List<String>> artifactGroups = config.artifacts();

        for (var entry : config.trust().entrySet()) {
            String key = entry.getKey();
            List<String> signerRefs = entry.getValue();

            List<SignerIdentity> signers = new ArrayList<>();
            for (String ref : signerRefs) {
                SignerIdentity identity = signerIdentities.get(ref);
                if (identity != null) {
                    signers.add(identity);
                }
            }
            if (signers.isEmpty()) {
                continue;
            }

            List<String> patterns = artifactGroups.getOrDefault(key, List.of(key));
            for (String pattern : patterns) {
                trustMappings.put(pattern, List.copyOf(signers));
            }
        }

        List<String> unsignedPatterns = new ArrayList<>();
        for (String key : config.unsigned()) {
            List<String> patterns = artifactGroups.getOrDefault(key, List.of(key));
            unsignedPatterns.addAll(patterns);
        }

        boolean requireAll = settings.verifyAllSignatures();
        UntrustedPolicy untrustedPolicy = "fail".equals(settings.onUntrusted())
                ? UntrustedPolicy.FAIL
                : UntrustedPolicy.WARN;

        return new DefaultTrustPolicy(trustMappings, unsignedPatterns, requireAll, untrustedPolicy);
    }
}
