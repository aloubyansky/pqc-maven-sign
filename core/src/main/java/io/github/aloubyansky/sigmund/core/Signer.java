package io.github.aloubyansky.sigmund.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Producer use case — signing artifacts.
 * <p>
 * Signs an artifact with all configured tools, groups results by
 * {@link SignatureFormat}, and combines compatible formats into single files.
 *
 * <h3>Sign flow</h3>
 * <ol>
 * <li>Call {@code sign()} on each tool → {@link SignResult} with algorithm metadata</li>
 * <li>Group results by {@link SignatureFormat}</li>
 * <li>For combinable formats → merge into one output file</li>
 * <li>For non-combinable → write each as a separate file</li>
 * <li>Return {@link SigningOutput} with metadata per file</li>
 * </ol>
 *
 * @see SigningOutput
 */
public class Signer {

    private final List<SignatureTool> tools;

    /**
     * Creates a new signer with the given tools.
     *
     * @param tools the signing tools (must all have {@code canSign() → true})
     */
    Signer(List<SignatureTool> tools) {
        this.tools = List.copyOf(tools);
    }

    /**
     * Signs an artifact file and writes signature files to the output directory.
     *
     * @param artifactFile the file to sign
     * @param outputDir the directory to write signature files to
     * @return the signing output with metadata per produced file
     * @throws ToolExecutionException if signing fails
     */
    public SigningOutput sign(Path artifactFile, Path outputDir) {
        List<ToolSignResult> toolResults = signWithTools(artifactFile, outputDir);
        Map<SignatureFormat, List<ToolSignResult>> grouped = groupByFormat(toolResults);
        return combineAndWrite(artifactFile, outputDir, grouped);
    }

    private List<ToolSignResult> signWithTools(Path artifactFile, Path outputDir) {
        List<ToolSignResult> results = new ArrayList<>();
        for (SignatureTool tool : tools) {
            Path tempSig = createTempSigFile(outputDir, tool);
            SignResult result = tool.sign(artifactFile, tempSig);
            results.add(new ToolSignResult(tool, tempSig, result));
        }
        return results;
    }

    private Map<SignatureFormat, List<ToolSignResult>> groupByFormat(List<ToolSignResult> results) {
        Map<SignatureFormat, List<ToolSignResult>> grouped = new LinkedHashMap<>();
        for (ToolSignResult r : results) {
            grouped.computeIfAbsent(r.tool.signatureFormat(), k -> new ArrayList<>()).add(r);
        }
        return grouped;
    }

    private SigningOutput combineAndWrite(Path artifactFile, Path outputDir,
            Map<SignatureFormat, List<ToolSignResult>> grouped) {
        List<SignedFile> signedFiles = new ArrayList<>();
        String artifactName = artifactFile.getFileName().toString();

        for (var entry : grouped.entrySet()) {
            SignatureFormat format = entry.getKey();
            List<ToolSignResult> results = entry.getValue();

            if (format.supportsCombining() && results.size() > 1) {
                signedFiles.add(combineResults(artifactName, outputDir, format, results));
            } else {
                for (ToolSignResult r : results) {
                    Path finalPath = outputDir.resolve(artifactName + format.fileExtension());
                    moveFile(r.tempFile, finalPath);
                    signedFiles.add(new SignedFile(finalPath, r.tool.name(),
                            format.name(), r.result.algorithm()));
                }
            }
        }
        return new SigningOutput(signedFiles);
    }

    private SignedFile combineResults(String artifactName, Path outputDir,
            SignatureFormat format, List<ToolSignResult> results) {
        Path combinedPath = outputDir.resolve(artifactName + format.fileExtension());
        List<Path> tempFiles = results.stream().map(r -> r.tempFile).toList();
        format.combine(tempFiles, combinedPath);
        cleanupTempFiles(tempFiles);
        String algorithms = results.stream()
                .map(r -> r.result.algorithm())
                .reduce((a, b) -> a + "+" + b)
                .orElse("unknown");
        String toolNames = results.stream()
                .map(r -> r.tool.name())
                .reduce((a, b) -> a + "+" + b)
                .orElse("unknown");
        return new SignedFile(combinedPath, toolNames, format.name(), algorithms);
    }

    private Path createTempSigFile(Path outputDir, SignatureTool tool) {
        try {
            return Files.createTempFile(outputDir, "sig-" + tool.name() + "-", ".tmp");
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to create temp file for signing", e);
        }
    }

    private void moveFile(Path source, Path target) {
        try {
            Files.move(source, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new ToolExecutionException("Failed to move signature file", e);
        }
    }

    private void cleanupTempFiles(List<Path> files) {
        for (Path f : files) {
            try {
                Files.deleteIfExists(f);
            } catch (IOException ignored) {
            }
        }
    }

    private record ToolSignResult(SignatureTool tool, Path tempFile, SignResult result) {
    }
}
