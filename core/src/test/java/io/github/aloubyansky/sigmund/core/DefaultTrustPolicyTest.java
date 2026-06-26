package io.github.aloubyansky.sigmund.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class DefaultTrustPolicyTest {

    private static final SignerIdentity ALICE = new SignerIdentity("alice", "Alice",
            List.of(new FingerprintCredential("openpgp-v4", "4AEE18F83AFDEB23")));
    private static final SignerIdentity BOB = new SignerIdentity("bob", "Bob",
            List.of(new EmailCredential("bob@example.com")));

    @Nested
    class PatternMatching {

        @Test
        void exactNamespace() {
            var policy = policy(Map.of("org.example", List.of(ALICE)));
            var result = policy.expectedSigners(artifact("org.example", "lib", "1.0"));
            assertEquals(1, result.size());
            assertEquals("alice", result.get(0).id());
        }

        @Test
        void wildcardName() {
            var policy = policy(Map.of("org.example:*", List.of(ALICE)));
            var result = policy.expectedSigners(artifact("org.example", "any-lib", "1.0"));
            assertEquals(1, result.size());
        }

        @Test
        void exactNameAndNamespace() {
            var policy = policy(Map.of("org.example:lib", List.of(ALICE)));
            assertEquals(1, policy.expectedSigners(artifact("org.example", "lib", "1.0")).size());
            assertTrue(policy.expectedSigners(artifact("org.example", "other", "1.0")).isEmpty());
        }

        @Test
        void threePartPattern() {
            var policy = policy(Map.of("org.example:lib:2.0", List.of(ALICE)));
            assertEquals(1, policy.expectedSigners(artifact("org.example", "lib", "2.0")).size());
            assertTrue(policy.expectedSigners(artifact("org.example", "lib", "1.0")).isEmpty());
        }

        @Test
        void moreSpecificWins() {
            var policy = policy(Map.of(
                    "org.example:*", List.of(BOB),
                    "org.example:special-lib", List.of(ALICE)));
            var result = policy.expectedSigners(artifact("org.example", "special-lib", "1.0"));
            assertEquals(1, result.size());
            assertEquals("alice", result.get(0).id());
        }

        @Test
        void noMatch() {
            var policy = policy(Map.of("org.example:*", List.of(ALICE)));
            assertTrue(policy.expectedSigners(artifact("com.other", "lib", "1.0")).isEmpty());
        }

        @Test
        void namespaceWildcard() {
            var policy = policy(Map.of("org.example.*", List.of(ALICE)));
            assertEquals(1, policy.expectedSigners(artifact("org.example.sub", "lib", "1.0")).size());
            assertTrue(policy.expectedSigners(artifact("org.other", "lib", "1.0")).isEmpty());
        }
    }

    @Nested
    class UnsignedMatching {

        @Test
        void exactMatch() {
            var policy = new DefaultTrustPolicy(
                    Map.of(), List.of("org.example:unsigned-lib"), false, UntrustedPolicy.FAIL);
            assertTrue(policy.isUnsignedAllowed(artifact("org.example", "unsigned-lib", "1.0")));
            assertFalse(policy.isUnsignedAllowed(artifact("org.example", "other", "1.0")));
        }

        @Test
        void wildcardMatch() {
            var policy = new DefaultTrustPolicy(
                    Map.of(), List.of("org.test:*"), false, UntrustedPolicy.FAIL);
            assertTrue(policy.isUnsignedAllowed(artifact("org.test", "anything", "1.0")));
        }
    }

    @Nested
    class PolicySettings {

        @Test
        void requireAllEvidenceMatch() {
            var policy = new DefaultTrustPolicy(Map.of(), List.of(), true, UntrustedPolicy.FAIL);
            assertTrue(policy.requireAllEvidenceMatch());
        }

        @Test
        void untrustedPolicy() {
            var policy = new DefaultTrustPolicy(Map.of(), List.of(), false, UntrustedPolicy.WARN);
            assertEquals(UntrustedPolicy.WARN, policy.onUntrusted());
        }
    }

    private static DefaultTrustPolicy policy(Map<String, List<SignerIdentity>> trust) {
        return new DefaultTrustPolicy(trust, List.of(), false, UntrustedPolicy.FAIL);
    }

    private static ArtifactIdentity artifact(String ns, String name, String version) {
        return new ArtifactIdentity() {
            @Override
            public String namespace() {
                return ns;
            }

            @Override
            public String name() {
                return name;
            }

            @Override
            public String version() {
                return version;
            }
        };
    }
}
