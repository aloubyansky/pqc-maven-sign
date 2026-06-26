package io.github.aloubyansky.sigmund.core;

/**
 * The result of a signing operation, carrying metadata about the produced signature.
 * <p>
 * The actual signature file is written to the path provided to
 * {@link SignatureTool#sign(java.nio.file.Path, java.nio.file.Path)}.
 * This record carries only the algorithm used, since the caller already knows
 * the output path and the tool name.
 *
 * @param algorithm the algorithm actually used for signing
 *        (e.g., {@code "RSA"}, {@code "ML-DSA-87+Ed448"})
 */
public record SignResult(String algorithm) {
}
