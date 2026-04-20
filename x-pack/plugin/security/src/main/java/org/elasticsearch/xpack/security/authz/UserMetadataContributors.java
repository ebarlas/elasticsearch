/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.GroupedActionListener;
import org.elasticsearch.xpack.core.security.authz.store.UserMetadataContributor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Stateless helper that fans a request's set of {@link UserMetadataContributor} instances out in
 * parallel and merges their contributions into a single metadata map for the authorization-time
 * enrichment hook.
 * <p>
 * Per-request semantics:
 * <ul>
 *   <li>Contributor failures abort the entire request: the helper surfaces the first failure to
 *       its listener so the caller (the authorization service) can fail-closed rather than
 *       evaluate DLS templates against partial metadata.</li>
 *   <li>Key collisions across contributors (two contributors providing the same metadata key) are
 *       logged at {@code WARN}; the first writer wins and the request is allowed to proceed.
 *       Operators are expected to prevent collisions by namespacing keys per contributor.</li>
 *   <li>All keys returned by contributors are asserted to start with {@code "_"} -- assertions
 *       only, since the same invariant is enforced by
 *       {@link org.elasticsearch.xpack.core.security.SecurityContext#executeWithEnrichedUserMetadata}.</li>
 *   <li>Contributors are skipped (not invoked) when every key in their declared
 *       {@link UserMetadataContributor#contributedKeys()} set is already present in
 *       {@code existingMetadata}. This is the per-request idempotence hook: indices authorization
 *       fires once per shard sub-action, so without this check a single user search would invoke
 *       every contributor once per shard. See {@link UserMetadataContributor} for the full
 *       contract this filtering imposes on implementations.</li>
 * </ul>
 * <p>
 * There is no name-based registry: privileges carry direct references to contributor instances,
 * so the set of contributors to invoke for a given request is computed by
 * {@link org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl#collectMetadataContributors()}
 * and passed to {@link #merge(Set, Map, ActionListener)}.
 */
public final class UserMetadataContributors {

    private static final Logger logger = LogManager.getLogger(UserMetadataContributors.class);

    private UserMetadataContributors() {}

    /**
     * Asynchronously invokes every contributor in {@code contributors} whose declared
     * {@link UserMetadataContributor#contributedKeys()} are not already fully present in
     * {@code existingMetadata}, in parallel, and merges their results into a single map. The
     * listener receives the merged map (possibly empty) on success, or the first encountered
     * failure on error.
     * <p>
     * The returned map only contains entries from contributors that actually ran; the caller is
     * responsible for folding it on top of {@code existingMetadata} (typically via
     * {@link org.elasticsearch.xpack.core.security.SecurityContext#executeWithEnrichedUserMetadata}).
     *
     * @param contributors     the set of contributors attached to the authorized request's role
     * @param existingMetadata the current effective user's metadata, used to skip contributors
     *                         that have already run earlier in the same request lifecycle; pass
     *                         {@link Map#of()} to force every contributor to run
     * @param listener         receives the merged metadata, or a failure
     */
    public static void merge(
        Set<UserMetadataContributor> contributors,
        Map<String, Object> existingMetadata,
        ActionListener<Map<String, Object>> listener
    ) {
        if (contributors == null || contributors.isEmpty()) {
            listener.onResponse(Map.of());
            return;
        }

        final List<UserMetadataContributor> toInvoke = filterAlreadyContributed(contributors, existingMetadata);
        if (toInvoke.isEmpty()) {
            listener.onResponse(Map.of());
            return;
        }

        final GroupedActionListener<Map<String, Object>> group = new GroupedActionListener<>(
            toInvoke.size(),
            listener.map(UserMetadataContributors::mergeResults)
        );
        for (UserMetadataContributor contributor : toInvoke) {
            try {
                contributor.contribute(group);
            } catch (Exception e) {
                group.onFailure(e);
            }
        }
    }

    /**
     * Returns the contributors that still need to run: those whose declared
     * {@link UserMetadataContributor#contributedKeys()} are not <em>all</em> already present in
     * {@code existingMetadata}. The "all present" rule (rather than "any present") means a
     * contributor that partially succeeded earlier will be re-invoked to fill in the gaps; a
     * deterministic contributor will simply re-emit identical values for the keys it already
     * populated.
     */
    private static List<UserMetadataContributor> filterAlreadyContributed(
        Set<UserMetadataContributor> contributors,
        Map<String, Object> existingMetadata
    ) {
        if (existingMetadata == null || existingMetadata.isEmpty()) {
            return new ArrayList<>(contributors);
        }
        final List<UserMetadataContributor> toInvoke = new ArrayList<>(contributors.size());
        for (UserMetadataContributor contributor : contributors) {
            final Set<String> declared = contributor.contributedKeys();
            assert declared != null && declared.isEmpty() == false
                : "UserMetadataContributor " + contributor.getClass().getName() + " declared an empty contributedKeys() set";
            if (existingMetadata.keySet().containsAll(declared) == false) {
                toInvoke.add(contributor);
            } else if (logger.isTraceEnabled()) {
                logger.trace(
                    "skipping UserMetadataContributor [{}]: declared keys {} are already present in effective user metadata",
                    contributor.getClass().getName(),
                    declared
                );
            }
        }
        return toInvoke;
    }

    private static Map<String, Object> mergeResults(Collection<Map<String, Object>> results) {
        // LinkedHashMap so logging of "first writer wins" collisions is stable for tests.
        final Map<String, Object> merged = new LinkedHashMap<>();
        for (Map<String, Object> result : results) {
            if (result == null || result.isEmpty()) {
                continue;
            }
            for (Map.Entry<String, Object> entry : result.entrySet()) {
                final String key = entry.getKey();
                assert key != null && key.startsWith("_")
                    : "contributor returned metadata key [" + key + "] which does not start with '_'";
                final Object existing = merged.putIfAbsent(key, entry.getValue());
                if (existing != null) {
                    logger.warn(
                        "multiple UserMetadataContributor implementations contributed conflicting values for key [{}]; "
                            + "first value wins, request continues with possibly non-deterministic enrichment",
                        key
                    );
                }
            }
        }
        return merged;
    }
}
