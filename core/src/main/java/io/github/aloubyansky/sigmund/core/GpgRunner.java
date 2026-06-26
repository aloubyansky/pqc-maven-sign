package io.github.aloubyansky.sigmund.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Wrapper for the GnuPG (gpg) command-line tool for signing and verification.
 * <p>
 * This class provides a Java interface to GPG's signing and verification
 * functionality, specifically for creating and verifying detached ASCII-armored
 * signatures.
 *
 * <p>
 * Example usage:
 *
 * <pre>
 * {
 *     &#64;code
 *     // Using the default GPG key
 *     GpgRunner gpg = new GpgRunner();
 *     SignResult result = gpg.sign(
 *             Path.of("artifact.jar"),
 *             Path.of("artifact.jar.asc"));
 *
 *     // Verify a signature
 *     GpgRunner.VerifyResult result = gpg.verify(
 *             Path.of("artifact.jar"),
 *             Path.of("artifact.jar.asc"));
 * }
 * </pre>
 * <p>
 * Note: This class requires the {@code gpg} executable to be available on the
 * system PATH or at the location specified via the constructor.
 *
 * @see #isAvailable()
 */
public class GpgRunner implements SignatureTool, KeyImporter, SignerIdentityResolver {

    private static final Pattern GPG_KEY_PATTERN = Pattern.compile(
            "using (\\w+) key\\s+([0-9A-Fa-f]{16,40})", Pattern.MULTILINE);

    private static final Pattern GPG_SIGNER_PATTERN = Pattern.compile(
            "Good signature from \"([^\"]+)\"", Pattern.MULTILINE);

    private static final int GPG_COLONS_UID_FIELD = 9;

    /**
     * Checks if the GPG executable is available and functional.
     *
     * @return true if GPG is available and responds to --version, false otherwise
     */
    /**
     * Checks if the GPG executable is available and functional.
     *
     * @return true if GPG is available and responds to --version, false otherwise
     */
    public static boolean isToolAvailable() {
        try {
            CliTool.Result result = CliTool.run("gpg", "--version");
            return result.exitCode() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Extracts the GPG key ID from gpg --verify stderr output.
     * <p>
     * Parses stderr output looking for lines like:
     * {@code gpg:                using RSA key 4AEE18F83AFDEB23}
     *
     * @param gpgStderr the stderr output from gpg --verify command
     * @return the extracted key ID in uppercase, or null if not found
     */
    static String extractGpgKeyId(String gpgStderr) {
        if (gpgStderr == null) {
            return null;
        }
        Matcher matcher = GPG_KEY_PATTERN.matcher(gpgStderr);
        if (matcher.find()) {
            return matcher.group(2).toUpperCase();
        }
        return null;
    }

    /**
     * Extracts the key algorithm (e.g., "RSA", "EDDSA") from gpg --verify stderr output.
     *
     * @param gpgStderr the stderr output from gpg --verify command
     * @return the algorithm name in uppercase, or null if not found
     */
    static String extractAlgorithm(String gpgStderr) {
        if (gpgStderr == null) {
            return null;
        }
        Matcher matcher = GPG_KEY_PATTERN.matcher(gpgStderr);
        if (matcher.find()) {
            return matcher.group(1).toUpperCase();
        }
        return null;
    }

    /**
     * Extracts the signer's user ID from gpg --verify stderr output.
     * <p>
     * Parses stderr output looking for lines like:
     * {@code gpg: Good signature from "Name <email@example.com>" [ultimate]}
     *
     * @param gpgStderr the stderr output from gpg --verify command
     * @return the signer's user ID (e.g., "Name &lt;email@example.com&gt;"), or null if not found
     */
    static String extractSignerUserId(String gpgStderr) {
        if (gpgStderr == null) {
            return null;
        }
        Matcher matcher = GPG_SIGNER_PATTERN.matcher(gpgStderr);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private static final Set<String> SUPPORTED_CREDENTIAL_TYPES = Set.of("openpgp-v4");

    private final String gpgExecutable;
    private final String keyName;
    private final OpenPgpSignatureFormat format;

    /**
     * Constructs a GpgRunner using the default "gpg" executable and default key.
     */
    public GpgRunner() {
        this("gpg", null);
    }

    /**
     * Constructs a GpgRunner using the default "gpg" executable.
     *
     * @param keyName the key name/ID to use with --local-user, or null to use
     *        GPG's default key
     */
    public GpgRunner(String keyName) {
        this("gpg", keyName);
    }

    /**
     * Constructs a GpgRunner with a custom GPG executable path.
     *
     * @param gpgExecutable the path to the gpg executable (e.g., "gpg" or "/usr/bin/gpg")
     * @param keyName the key name/ID to use with --local-user, or null to use
     *        GPG's default key
     * @throws IllegalArgumentException if gpgExecutable is null or empty
     */
    public GpgRunner(String gpgExecutable, String keyName) {
        if (gpgExecutable == null || gpgExecutable.isEmpty()) {
            throw new IllegalArgumentException("gpgExecutable cannot be null or empty");
        }
        this.gpgExecutable = gpgExecutable;
        this.keyName = keyName;
        this.format = new OpenPgpSignatureFormat();
    }

    /**
     * Result of a GPG signature verification.
     *
     * @param result the verification outcome: {@link VerificationResult#PASS} if the signature is valid,
     *        {@link VerificationResult#FAIL} if the signature does not match,
     *        {@link VerificationResult#NO_KEY} if the signing key is not in the keyring
     * @param keyId the signing key ID extracted from GPG output, or null if not found
     * @param algorithm the key algorithm (e.g., "RSA", "EDDSA"), or null if not found
     * @param signerUserId the signer's user ID (e.g., "Name &lt;email&gt;"), or null if the key is not in the keyring
     */
    public record VerifyResult(VerificationResult result, String keyId, String algorithm, String signerUserId) {
    }

    /**
     * {@inheritDoc}
     * <p>
     * Creates a detached ASCII-armored signature using GPG with options:
     * {@code --batch --yes --armor --detach-sign [--local-user keyName] --output outputSig artifactFile}.
     *
     * @param artifactFile the file to sign
     * @param outputSig the path where the signature file will be written
     * @return a {@link SignResult} with the algorithm used
     * @throws IllegalArgumentException if artifactFile or outputSig is null
     * @throws ToolExecutionException if the GPG command fails
     */
    @Override
    public SignResult sign(Path artifactFile, Path outputSig) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (outputSig == null) {
            throw new IllegalArgumentException("outputSig cannot be null");
        }

        String[] command = buildSignCommand(artifactFile, outputSig);
        CliTool.Result result = CliTool.run(command);
        if (result.exitCode() != 0) {
            throw new ToolExecutionException("'" + String.join(" ", command)
                    + "' failed with exit code " + result.exitCode()
                    + (result.stderr().isEmpty() ? "" : ": " + result.stderr().trim()));
        }

        return new SignResult("RSA");
    }

    /**
     * Creates a detached ASCII-armored signature and returns the signature content.
     *
     * @param artifactFile the file to sign
     * @param outputSig the path where the signature file will be written
     * @return the ASCII-armored signature content as a String
     * @throws ToolExecutionException if the GPG command fails
     */
    public String signAndRead(Path artifactFile, Path outputSig) {
        sign(artifactFile, outputSig);
        return readSignatureFile(outputSig);
    }

    /**
     * Verifies a detached signature file for the specified artifact.
     * <p>
     * This method runs {@code gpg --verify <signatureFile> <artifactFile>}
     * and interprets the result.
     *
     * @param artifactFile the file that was signed
     * @param signatureFile the detached signature file to verify
     * @return a {@link VerifyResult} with the verification outcome and extracted key ID
     * @throws IllegalArgumentException if artifactFile or signatureFile is null
     */
    public VerifyResult verifyFile(Path artifactFile, Path signatureFile) {
        if (artifactFile == null) {
            throw new IllegalArgumentException("artifactFile cannot be null");
        }
        if (signatureFile == null) {
            throw new IllegalArgumentException("signatureFile cannot be null");
        }

        CliTool.Result result = CliTool.run(
                gpgExecutable,
                "--verify",
                signatureFile.toString(),
                artifactFile.toString());

        String keyId = extractGpgKeyId(result.stderr());
        String algorithm = extractAlgorithm(result.stderr());
        String signerUserId = extractSignerUserId(result.stderr());

        // Exit code 2 means warnings (e.g. unknown packet versions); treat as
        // valid only if GPG still reports "Good signature"
        VerificationResult verificationResult;
        if (result.exitCode() == 0
                || (result.exitCode() == 2 && result.stderr().contains("Good signature"))) {
            verificationResult = VerificationResult.PASS;
        } else if (result.stderr().contains("No public key")) {
            verificationResult = VerificationResult.NO_KEY;
        } else {
            verificationResult = VerificationResult.FAIL;
        }
        return new VerifyResult(verificationResult, keyId, algorithm, signerUserId);
    }

    /**
     * Receives a public key from a keyserver and imports it into the local keyring.
     *
     * @param keyId the key ID to receive
     * @param keyserver the keyserver URL (e.g., "hkps://keys.openpgp.org")
     * @return true if the key was successfully received, false otherwise
     */
    public boolean receiveKey(String keyId, String keyserver) {
        CliTool.Result result = CliTool.run(
                gpgExecutable,
                "--keyserver", keyserver,
                "--recv-keys", keyId);
        return result.exitCode() == 0;
    }

    /**
     * Looks up the user ID (UID) for a key in the local keyring.
     * <p>
     * Parses the {@code --with-colons} output format where the user ID is at field index 9
     * on lines starting with {@code uid:}.
     *
     * @param keyId the key ID to look up
     * @return the user ID string (e.g., "Name &lt;email@example.com&gt;"), or null if not found
     */
    public String listKeyUserId(String keyId) {
        CliTool.Result result = CliTool.run(
                gpgExecutable,
                "--list-keys",
                "--with-colons",
                keyId);
        if (result.exitCode() != 0) {
            return null;
        }
        for (String line : result.stdout().split("\\R")) {
            if (line.startsWith("uid:")) {
                String[] fields = line.split(":", -1);
                if (fields.length > GPG_COLONS_UID_FIELD && !fields[GPG_COLONS_UID_FIELD].isEmpty()) {
                    return fields[GPG_COLONS_UID_FIELD];
                }
            }
        }
        return null;
    }

    // --- SignatureTool SPI ---

    @Override
    public String name() {
        return "gpg";
    }

    /**
     * {@inheritDoc}
     * <p>
     * Checks availability by running {@code gpg --version}.
     */
    @Override
    public boolean isAvailable() {
        return GpgRunner.isToolAvailable();
    }

    /**
     * {@inheritDoc}
     * <p>
     * Returns {@code true} if a key name was provided at construction time.
     * A {@code null} key name means GPG's default key is used, which is still
     * considered signing-capable.
     */
    @Override
    public boolean canSign() {
        return true;
    }

    @Override
    public SignatureFormat signatureFormat() {
        return format;
    }

    @Override
    public Set<String> supportedCredentialTypes() {
        return SUPPORTED_CREDENTIAL_TYPES;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Accepts {@link OpenPgpVerificationUnit}s with {@code packetVersion <= 4}.
     */
    @Override
    public boolean canVerify(VerificationUnit unit) {
        return unit instanceof OpenPgpVerificationUnit opgu
                && opgu.packetVersion() > 0
                && opgu.packetVersion() <= 4;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Writes the armored block to a temp file, verifies via GPG, and wraps
     * the result into an {@link OpenPgpVerifyResult}.
     */
    @Override
    public io.github.aloubyansky.sigmund.core.VerifyResult verify(Path artifactFile, VerificationUnit unit) {
        if (!(unit instanceof OpenPgpVerificationUnit opgu)) {
            return new OpenPgpVerifyResult(VerificationResult.SKIPPED, null, null, -1, null, null);
        }
        return verifyArmoredBlock(artifactFile, opgu);
    }

    @Override
    public List<Credential> extractCredentials(io.github.aloubyansky.sigmund.core.VerifyResult result) {
        if (result.result() != VerificationResult.PASS) {
            return List.of();
        }
        if (result instanceof OpenPgpVerifyResult opvr && opvr.fingerprint() != null) {
            String credType = opvr.version() < 6 ? "openpgp-v4" : "openpgp-v6";
            return List.of(new FingerprintCredential(credType, opvr.fingerprint()));
        }
        return List.of();
    }

    // --- KeyImporter SPI ---

    /**
     * {@inheritDoc}
     * <p>
     * Delegates to {@link #receiveKey(String, String)}.
     */
    @Override
    public boolean importKey(String keyId, String keyserver) {
        return receiveKey(keyId, keyserver);
    }

    // --- SignerIdentityResolver SPI ---

    /**
     * {@inheritDoc}
     * <p>
     * Delegates to {@link #listKeyUserId(String)}.
     */
    @Override
    public String lookupKeyUserId(String keyId) {
        return listKeyUserId(keyId);
    }

    // --- Private helpers for SPI ---

    private OpenPgpVerifyResult verifyArmoredBlock(Path artifactFile, OpenPgpVerificationUnit opgu) {
        Path sigFile = null;
        try {
            sigFile = Files.createTempFile("gpg-verify-", ".asc");
            Files.writeString(sigFile, opgu.armoredBlock());
            VerifyResult gpgResult = verifyFile(artifactFile, sigFile);
            return toOpenPgpVerifyResult(gpgResult, opgu.packetVersion());
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to create temp file for GPG verification", e);
        } finally {
            deleteSilently(sigFile);
        }
    }

    private OpenPgpVerifyResult toOpenPgpVerifyResult(VerifyResult gpgResult, int version) {
        return new OpenPgpVerifyResult(
                gpgResult.result(),
                gpgResult.signerUserId(),
                gpgResult.algorithm(),
                version,
                gpgResult.keyId(),
                gpgResult.keyId());
    }

    private static void deleteSilently(Path file) {
        if (file != null) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException ignored) {
            }
        }
    }

    private String[] buildSignCommand(Path artifactFile, Path outputSig) {
        List<String> command = new ArrayList<>();
        command.add(gpgExecutable);
        command.add("--batch");
        command.add("--yes");
        command.add("--armor");
        command.add("--detach-sign");

        if (keyName != null && !keyName.isEmpty()) {
            command.add("--local-user");
            command.add(keyName);
        }

        command.add("--output");
        command.add(outputSig.toString());
        command.add(artifactFile.toString());

        return command.toArray(new String[0]);
    }

    private String readSignatureFile(Path signatureFile) {
        try {
            return Files.readString(signatureFile);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(
                    "Failed to read signature file: " + signatureFile,
                    e);
        }
    }
}
