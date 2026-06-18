package io.github.aloubyansky.pqc.maven.plugin;

import java.io.File;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.inject.Inject;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;

/**
 * Base class for Mojos that iterate over project dependencies and inspect their signatures.
 */
abstract class AbstractDependencyMojo extends AbstractMojo {

    static final Comparator<Artifact> ARTIFACT_ORDER = Comparator
            .comparing(Artifact::getGroupId)
            .thenComparing(Artifact::getArtifactId)
            .thenComparing(Artifact::getVersion);

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    protected MavenProject project;

    @Inject
    protected RepositorySystem repoSystem;

    @Parameter(defaultValue = "${repositorySystemSession}", readonly = true)
    protected RepositorySystemSession repoSession;

    @Parameter(defaultValue = "${project.remoteProjectRepositories}", readonly = true)
    protected List<RemoteRepository> remoteRepos;

    @Parameter(property = "pqc.fetchSignerInfo", defaultValue = "false")
    protected boolean fetchSignerInfo;

    @Parameter(property = "pqc.keyservers", defaultValue = "hkps://keyserver.ubuntu.com,hkps://keys.openpgp.org")
    protected String keyservers;

    @Parameter(property = "pqc.sqHome")
    protected File sqHome;

    @Parameter(property = "pqc.includeTestDependencies", defaultValue = "false")
    protected boolean includeTestDependencies;

    @Parameter(property = "pqc.skip", defaultValue = "false")
    protected boolean skip;

    Set<Artifact> resolveDependencies() {
        Set<Artifact> artifacts = project.getArtifacts();
        if (!includeTestDependencies) {
            artifacts = artifacts.stream()
                    .filter(a -> !Artifact.SCOPE_TEST.equals(a.getScope()))
                    .collect(Collectors.toCollection(() -> new TreeSet<>(ARTIFACT_ORDER)));
        } else {
            TreeSet<Artifact> sorted = new TreeSet<>(ARTIFACT_ORDER);
            sorted.addAll(artifacts);
            artifacts = sorted;
        }
        return artifacts;
    }
}
