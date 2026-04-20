/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz.store;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.xpack.core.security.user.User;

import java.util.Map;
import java.util.Set;

/**
 * SPI extension point for asynchronously contributing additional entries to {@link User#metadata()}
 * at authorization time so that DLS template queries can reference attributes that were not
 * available -- or were intentionally omitted -- at authentication time.
 * <p>
 * Contributors are referenced directly from
 * {@link org.elasticsearch.xpack.core.security.authz.RoleDescriptor.IndicesPrivileges}: when an
 * {@code ImplicitPrivilegesProvider} emits a privilege whose DLS template needs externally
 * looked-up data, it attaches the contributor instance directly to the privilege via
 * {@code IndicesPrivileges.Builder#metadataContributor(UserMetadataContributor)}. There is no
 * name-based registry: the privilege carries the reference, and the authorization hook fans the
 * request out to the unique set of contributors attached to all matching privileges.
 * <p>
 * <b>Equality-based merging.</b> Privileges with otherwise identical (indices, granted-fields,
 * denied-fields, query, privileges) tuples are merged into a single permission group only when
 * their contributors are {@link Object#equals equal}. The SPI contract is that equal
 * contributors produce the same contribution, so collapsing them is safe. Plugins that emit many
 * privileges sharing one conceptual contributor should either hand the same instance to every
 * privilege or implement {@code equals}/{@code hashCode} so that equivalent contributors compare
 * equal; otherwise the permissions will fragment and per-shard cache keys will diverge
 * unnecessarily.
 * <p>
 * <b>Resolving the user.</b> The framework does not pass the {@link User} through the SPI: the
 * contributor's signature is intentionally minimal. Implementations that need per-user data must
 * resolve the <em>effective</em> (impersonated under run-as) user from the current
 * {@link org.elasticsearch.xpack.core.security.SecurityContext} themselves -- typically via
 * {@code securityContext.getAuthentication().getEffectiveSubject().getUser()}. Reading the
 * authenticating user instead is a bug under run-as: DLS templates evaluate against the effective
 * user's metadata, so the contribution must too.
 * <p>
 * <b>Security and namespacing.</b> All keys returned by {@link #contribute} <em>must</em> begin
 * with an underscore ({@code "_"}). This matches the namespace already exposed by
 * {@link User#metadata()} to DLS templates and avoids collision with attributes the underlying
 * realm intentionally hid. The merge step asserts this invariant in development builds and skips
 * offending entries with a WARN log in production.
 * <p>
 * <b>Determinism, latency, and failures.</b> Contributors should be deterministic with respect to
 * the resolved {@link User} (so that the request cache differentiator and DLS query evaluator
 * agree on what was used) and should complete promptly: the authorized request blocks until all
 * contributors in scope have responded. Implementations that need to make remote calls should
 * apply their own bounded timeouts and surface failures via
 * {@link ActionListener#onFailure(Exception)} -- the merge step will fail the authorized request
 * rather than apply DLS templates against stale or partial metadata. In practice, contributors
 * are expected to be backed by an in-memory cache populated out-of-band; the synchronous-leaning
 * call site cannot tolerate per-request remote I/O on the transport thread.
 * <p>
 * <b>One invocation per request: the {@link #contributedKeys()} contract.</b> An indices
 * authorization runs once per child sub-action (per-shard query, per-shard fetch, the chunked
 * fetch coordination action, etc.) because the existing parent-skip optimization
 * ({@code PreAuthorizationUtils}) is disabled whenever DLS or FLS is in play. To keep contributor
 * invocations bounded to a single call per logical request, the framework filters the contributor
 * set against the effective user's existing {@link User#metadata()} before each merge step:
 * a contributor whose declared {@link #contributedKeys()} are <em>all</em> already present in the
 * metadata is skipped, on the assumption that an earlier authorization on this request already
 * ran it and the result was folded in via
 * {@link org.elasticsearch.xpack.core.security.SecurityContext#executeWithEnrichedUserMetadata}
 * (whose enriched {@link org.elasticsearch.xpack.core.security.authc.Authentication} flows to
 * downstream nodes via transport headers).
 * <p>
 * Implementation requirements that follow from this contract:
 * <ul>
 *   <li>{@link #contributedKeys()} must return a stable, non-empty set of {@code "_"}-prefixed
 *       keys describing every entry the contributor may produce.</li>
 *   <li>{@link #contribute} must, on success, return a map containing <em>all</em> of those keys
 *       (with empty/sentinel values when the lookup yields no data); otherwise the framework
 *       cannot tell that the contributor has run and will re-invoke it on subsequent
 *       authorizations.</li>
 *   <li>If a contributor returns keys outside its declared set, those keys still flow into
 *       {@link User#metadata()}, but they will never participate in the skip check and may be
 *       overwritten the next time the contributor runs.</li>
 * </ul>
 */
public interface UserMetadataContributor {

    /**
     * Asynchronously computes additional metadata entries to fold into the effective user's
     * {@link User#metadata() metadata}. The listener must be invoked exactly once. All keys in
     * the returned map must start with {@code "_"}.
     * <p>
     * On a successful response the returned map MUST contain every key declared by
     * {@link #contributedKeys()}. Missing declared keys cause the framework to re-invoke the
     * contributor on every subsequent authorization for this request, defeating the per-request
     * skip optimization.
     *
     * @param listener receives the additional metadata entries on success, or a failure that
     *                 will abort the authorized request
     */
    void contribute(ActionListener<Map<String, Object>> listener);

    /**
     * Declares the set of {@link User#metadata() metadata} keys this contributor is responsible
     * for populating. Used by the authorization layer to skip contributors whose keys are already
     * present in the effective user's metadata, so that contributors run at most once per logical
     * request even though indices authorization runs once per shard sub-action.
     * <p>
     * The set MUST be non-empty, every key MUST start with {@code "_"}, and the set MUST be
     * stable for the lifetime of the contributor instance (it is read on every authorization).
     */
    Set<String> contributedKeys();
}
