package io.github.aloubyansky.sigmund.plugin;

import io.github.aloubyansky.sigmund.core.FileSignatureReport;
import io.github.aloubyansky.sigmund.core.GpgRunner;
import io.github.aloubyansky.sigmund.core.KeyImporter;
import io.github.aloubyansky.sigmund.core.OpenPgpVerifyResult;
import io.github.aloubyansky.sigmund.core.Sigmund;
import io.github.aloubyansky.sigmund.core.SignatureInfo;
import io.github.aloubyansky.sigmund.core.SignatureVerificationReport;
import io.github.aloubyansky.sigmund.core.SqRunner;
import io.github.aloubyansky.sigmund.core.VerificationResult;
import io.github.aloubyansky.sigmund.core.VerifyResult;
import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.logging.Log;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;

/**
 * Inspects OpenPGP signatures for Maven artifacts, extracting signer metadata
 * from both classical (v4/GPG) and PQC (v6) signature blocks.
 * <p>
 * Uses the {@link Sigmund} facade for signature verification and
 * {@link ArtifactFileResolver} for Maven artifact resolution.
 */
class SignatureInspector {

    private final Log log;
    private final ArtifactFileResolver fileResolver;
    private final Sigmund sigmund;
    private final KeyImporter keyImporter;
    private final List<String> keyServers;
    private final Set<String> fetchedKeyIds = new HashSet<>();

    private SignatureInspector(Builder builder) {
        this.log = builder.log;
        this.fileResolver = new ArtifactFileResolver(
                builder.repoSystem, builder.repoSession, builder.remoteRepos, builder.log);
        this.sigmund = builder.sigmund;
        this.keyImporter = sigmund.findTool(KeyImporter.class);
        this.keyServers = List.copyOf(builder.keyServers);
    }

    static Builder builder() {
        return new Builder();
    }

    static class Builder {
        private Log log;
        private RepositorySystem repoSystem;
        private RepositorySystemSession repoSession;
        private List<RemoteRepository> remoteRepos;
        private Sigmund sigmund;
        private File sqHome;
        private final List<String> keyServers = new ArrayList<>();

        Builder log(Log log) {
            this.log = log;
            return this;
        }

        Builder repoSystem(RepositorySystem repoSystem) {
            this.repoSystem = repoSystem;
            return this;
        }

        Builder repoSession(RepositorySystemSession repoSession) {
            this.repoSession = repoSession;
            return this;
        }

        Builder remoteRepos(List<RemoteRepository> remoteRepos) {
            this.remoteRepos = remoteRepos;
            return this;
        }

        Builder sigmund(Sigmund sigmund) {
            this.sigmund = sigmund;
            return this;
        }

        Builder sqHome(File sqHome) {
            this.sqHome = sqHome;
            return this;
        }

        Builder addKeyServer(String server) {
            this.keyServers.add(server);
            return this;
        }

        SignatureInspector build() throws MojoExecutionException {
            if (sigmund == null) {
                Sigmund.Builder sb = Sigmund.builder()
                        .addTool(new GpgRunner());
                if (SqRunner.isToolAvailable()) {
                    sb.addTool(new SqRunner(SequoiaHomeResolver.resolve(sqHome)));
                } else if (log != null) {
                    log.debug("Sequoia (sq) not found - PQC signer info will not be available");
                }
                sigmund = sb.build();
            }
            return new SignatureInspector(this);
        }
    }

    static String versionLabel(int version) {
        return switch (version) {
            case 4 -> "GPG";
            case 6 -> "PQC";
            default -> version > 0 ? "OpenPGP v" + version : "-";
        };
    }

    List<SignedArtifact> inspectAll(Collection<ArtifactCoords> artifacts) {
        List<SignedArtifact> results = new ArrayList<>();
        for (ArtifactCoords artifact : artifacts) {
            results.addAll(inspectSignatures(artifact));
        }
        return results;
    }

    List<SignedArtifact> inspectSignatures(ArtifactCoords coords) {
        String coordsStr = coords.toString();

        ArtifactFileResolver.ResolvedArtifact resolved = fileResolver.resolveArtifact(coords);
        if (resolved == null) {
            return List.of(new SignedArtifact(coordsStr, null,
                    new SignatureInfo(-1, null, null, null, VerificationResult.SKIPPED)));
        }

        List<RemoteRepository> sigRepos = fileResolver.signatureRepos(resolved.sourceRepo());
        ArtifactFileResolver.ResolvedSignature sigResult = fileResolver.resolveSignature(
                coords, ".asc", sigRepos);
        if (sigResult == null) {
            return List.of(new SignedArtifact(coordsStr, null,
                    new SignatureInfo(-1, null, null, null, VerificationResult.SKIPPED)));
        }

        String repoId = sigResult.repoId();
        Path ascFile = sigResult.signatureFile();

        SignatureVerificationReport report;
        try {
            report = sigmund.verify(resolved.artifactFile(), ascFile);
        } catch (Exception e) {
            log.warn("Verification failed for " + coordsStr + ": " + e.getMessage());
            return List.of(new SignedArtifact(coordsStr, repoId,
                    new SignatureInfo(-1, null, null, null, VerificationResult.FAIL)));
        }

        if (report.files().isEmpty()) {
            return List.of(new SignedArtifact(coordsStr, repoId,
                    new SignatureInfo(-1, null, null, null, VerificationResult.SKIPPED)));
        }

        List<SignedArtifact> entries = new ArrayList<>();
        for (FileSignatureReport fileReport : report.files()) {
            if (fileReport.results().isEmpty()) {
                entries.add(new SignedArtifact(coordsStr, repoId,
                        new SignatureInfo(-1, null, null, null, VerificationResult.SKIPPED)));
                continue;
            }
            for (VerifyResult vr : fileReport.results()) {
                SignatureInfo sig = toSignatureInfo(vr);
                SignedArtifact entry = new SignedArtifact(coordsStr, repoId, sig,
                        resolved.artifactFile(), ascFile);
                SignedArtifact fetched;
                try {
                    fetched = fetchSignerInfoIfMissing(entry);
                } catch (Exception e) {
                    log.debug("Signer info fetch failed for " + coordsStr + ": " + e.getMessage());
                    fetched = entry;
                }
                entries.add(new SignedArtifact(fetched.coordinates(), fetched.repoId(),
                        fetched.signatureInfo()));
            }
        }

        return entries;
    }

    private static SignatureInfo toSignatureInfo(VerifyResult vr) {
        if (vr instanceof OpenPgpVerifyResult opvr) {
            String keyId = opvr.fingerprint() != null ? opvr.fingerprint() : opvr.keyId();
            return new SignatureInfo(opvr.version(), keyId, opvr.algorithm(),
                    opvr.signerDisplayName(), opvr.result());
        }
        return new SignatureInfo(-1, null, vr.algorithm(),
                vr.signerDisplayName(), vr.result());
    }

    SignedArtifact fetchSignerInfoIfMissing(SignedArtifact entry) {
        SignatureInfo sig = entry.signatureInfo();
        if (keyServers.isEmpty() || sig.keyId() == null || sig.signerUserId() != null) {
            return entry;
        }
        if (keyImporter == null) {
            return entry;
        }
        if (!fetchedKeyIds.add(sig.keyId())) {
            return reverify(entry);
        }
        for (String server : keyServers) {
            if (keyImporter.importKey(sig.keyId(), server)) {
                return reverify(entry);
            }
        }
        return entry;
    }

    private SignedArtifact reverify(SignedArtifact entry) {
        if (entry.artifactFile() == null || entry.signatureFile() == null) {
            return entry;
        }
        try {
            SignatureVerificationReport report = sigmund.verify(
                    entry.artifactFile(), entry.signatureFile());
            if (report.files().isEmpty()) {
                return entry;
            }
            FileSignatureReport fileReport = report.files().get(0);
            for (VerifyResult vr : fileReport.results()) {
                if (vr instanceof OpenPgpVerifyResult opvr) {
                    String keyId = opvr.fingerprint() != null ? opvr.fingerprint() : opvr.keyId();
                    if (keyId != null && keyId.equalsIgnoreCase(entry.signatureInfo().keyId())) {
                        return new SignedArtifact(entry.coordinates(), entry.repoId(),
                                toSignatureInfo(vr), entry.artifactFile(), entry.signatureFile());
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Re-verification failed: " + e.getMessage());
        }
        return entry;
    }

    static List<String> parseKeyservers(String keyservers) {
        List<String> servers = new ArrayList<>();
        for (String s : keyservers.split(",")) {
            String trimmed = s.trim();
            if (!trimmed.isEmpty()) {
                servers.add(trimmed);
            }
        }
        return servers;
    }

    record SignedArtifact(String coordinates, String repoId, SignatureInfo signatureInfo,
            Path artifactFile, Path signatureFile) {
        SignedArtifact(String coordinates, String repoId, SignatureInfo signatureInfo) {
            this(coordinates, repoId, signatureInfo, null, null);
        }
    }
}
