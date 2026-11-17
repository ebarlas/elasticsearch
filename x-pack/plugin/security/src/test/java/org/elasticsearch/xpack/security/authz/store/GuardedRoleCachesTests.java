/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.authz.store;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.cluster.metadata.ProjectId;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.authz.store.RoleKey;
import org.elasticsearch.xpack.core.security.test.TestRestrictedIndices;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

public class GuardedRoleCachesTests extends ESTestCase {

    private static final int UNBOUNDED = -1;
    private static final RoleKey R1 = roleKey("r1");
    private static final RoleKey R1_R2 = roleKey("r1", "r2");
    private static final RoleKey R2 = roleKey("r2");

    public void testLoadedRoleIsCachedAndServed() {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final Role role = role("r1", "r2");

        assertThat(caches.getRole(project, R1_R2), nullValue());
        assertThat(cache(caches, project, R1_R2, role, "m1"), sameInstance(role));

        assertThat(caches.getRole(project, R1_R2), sameInstance(role));
        assertThat(caches.getRole(project, R1), nullValue());
        assertThat(caches.getRole(randomUniqueProjectId(), R1_R2), nullValue());
        assertThat(caches.isNegativelyCached(project, "m1"), is(true));
        assertThat(caches.isNegativelyCached(project, "r1"), is(false));
        assertThat(caches.isNegativelyCached(randomUniqueProjectId(), "m1"), is(false));

        // served from the cache without loading
        final List<PendingLoad> loads = new ArrayList<>();
        final PlainActionFuture<Role> hit = new PlainActionFuture<>();
        caches.getOrLoad(project, R1_R2, recordingLoader(loads), hit);
        assertThat(hit.actionGet(), sameInstance(role));
        assertThat(loads.size(), is(0));
    }

    public void testConcurrentMissesShareOneLoad() {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final List<PendingLoad> loads = new ArrayList<>();
        final PlainActionFuture<Role> first = new PlainActionFuture<>();
        final PlainActionFuture<Role> second = new PlainActionFuture<>();

        caches.getOrLoad(project, R1, recordingLoader(loads), first);
        caches.getOrLoad(project, R1, recordingLoader(loads), second);
        assertThat(loads.size(), is(1));
        assertThat("a load in flight is not served as a cached role", caches.getRole(project, R1), nullValue());
        assertFalse(first.isDone());
        assertFalse(second.isDone());

        final Role role = role("r1");
        loads.getFirst().complete(role, "m1");
        assertThat(first.actionGet(), sameInstance(role));
        assertThat(second.actionGet(), sameInstance(role));
        assertThat(caches.getRole(project, R1), sameInstance(role));
        assertThat(caches.isNegativelyCached(project, "m1"), is(true));
    }

    public void testMissesForDifferentKeysOrProjectsDoNotShareALoad() {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final List<PendingLoad> loads = new ArrayList<>();

        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        caches.getOrLoad(project, R2, recordingLoader(loads), new PlainActionFuture<>());
        caches.getOrLoad(randomUniqueProjectId(), R1, recordingLoader(loads), new PlainActionFuture<>());
        assertThat(loads.size(), is(3));
    }

    // Every kind of invalidation that affects a key must remove its load, so that the load is not cached when it completes and a
    // later miss does not join it. One case per kind so that a failure names the kind.

    public void testLoadOverlappingInvalidateAllIsNotCached() {
        assertLoadOverlappingInvalidationIsNotCached((caches, project) -> caches.invalidateAll());
    }

    public void testLoadOverlappingInvalidateProjectIsNotCached() {
        assertLoadOverlappingInvalidationIsNotCached(GuardedRoleCaches::invalidateProject);
    }

    /**
     * Removing a project forgets its generation, so a load that captured that generation before the removal would compare equal
     * to the default again if the project had never been invalidated, as is the case here. Advancing the global generation on
     * removal is what keeps such a load from recording missing names for a project that no longer exists.
     */
    public void testLoadOverlappingRemoveProjectIsNotCached() {
        assertLoadOverlappingInvalidationIsNotCached(GuardedRoleCaches::removeProject);
    }

    public void testLoadOverlappingInvalidateRoleIsNotCached() {
        assertLoadOverlappingInvalidationIsNotCached((caches, project) -> caches.invalidateRole(project, "r1"));
    }

    public void testLoadOverlappingInvalidateClusterScopedRolesIsNotCached() {
        assertLoadOverlappingInvalidationIsNotCached((caches, project) -> caches.invalidateClusterScopedRoles(Set.of("r1")));
    }

    private static void assertLoadOverlappingInvalidationIsNotCached(BiConsumer<GuardedRoleCaches, ProjectId> invalidation) {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final List<PendingLoad> loads = new ArrayList<>();
        final PlainActionFuture<Role> before = new PlainActionFuture<>();
        final PlainActionFuture<Role> after = new PlainActionFuture<>();

        caches.getOrLoad(project, R1, recordingLoader(loads), before);
        invalidation.accept(caches, project);
        caches.getOrLoad(project, R1, recordingLoader(loads), after);
        assertThat("a miss after the invalidation must not join the earlier load", loads.size(), is(2));

        final Role stale = role("r1");
        loads.get(0).complete(stale, "m1");
        assertThat(before.actionGet(), sameInstance(stale));
        assertFalse(after.isDone());
        assertThat(caches.getRole(project, R1), nullValue());
        assertThat(caches.isNegativelyCached(project, "m1"), is(false));

        final Role current = role("r1");
        loads.get(1).complete(current, "m1");
        assertThat(after.actionGet(), sameInstance(current));
        assertThat(caches.getRole(project, R1), sameInstance(current));
        assertThat(caches.isNegativelyCached(project, "m1"), is(true));
    }

    // An invalidation that does not name the key leaves its load in place, so the role is still cached. The generation is tracked
    // per project, not per role, so the missing names the load found are discarded.

    public void testLoadOverlappingInvalidationOfUnrelatedRoleIsCachedWithoutMissingNames() {
        assertLoadOverlappingUnrelatedInvalidationIsCachedWithoutMissingNames(
            (caches, project) -> caches.invalidateRole(project, "unrelated")
        );
    }

    public void testLoadOverlappingInvalidationOfUnrelatedClusterScopedRolesIsCachedWithoutMissingNames() {
        assertLoadOverlappingUnrelatedInvalidationIsCachedWithoutMissingNames(
            (caches, project) -> caches.invalidateClusterScopedRoles(Set.of("unrelated"))
        );
    }

    private static void assertLoadOverlappingUnrelatedInvalidationIsCachedWithoutMissingNames(
        BiConsumer<GuardedRoleCaches, ProjectId> invalidation
    ) {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final List<PendingLoad> loads = new ArrayList<>();

        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        invalidation.accept(caches, project);
        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        assertThat(loads.size(), is(1));

        final Role role = role("r1");
        loads.getFirst().complete(role, "m1");
        assertThat(caches.getRole(project, R1), sameInstance(role));
        assertThat(caches.isNegativelyCached(project, "m1"), is(false));
    }

    // An invalidation scoped to another project must not affect this project's load.

    public void testLoadOverlappingInvalidateProjectOfAnotherProjectIsCached() {
        assertLoadOverlappingInvalidationOfAnotherProjectIsCached(GuardedRoleCaches::invalidateProject);
    }

    public void testLoadOverlappingInvalidateRoleInAnotherProjectIsCached() {
        assertLoadOverlappingInvalidationOfAnotherProjectIsCached((caches, otherProject) -> caches.invalidateRole(otherProject, "r1"));
    }

    private static void assertLoadOverlappingInvalidationOfAnotherProjectIsCached(BiConsumer<GuardedRoleCaches, ProjectId> invalidation) {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final List<PendingLoad> loads = new ArrayList<>();
        final Role role = role("r1");

        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        invalidation.accept(caches, randomUniqueProjectId());
        loads.getFirst().complete(role, "m1");
        assertThat(caches.getRole(project, R1), sameInstance(role));
        assertThat(caches.isNegativelyCached(project, "m1"), is(true));
    }

    public void testUncacheableRoleIsServedToEveryCallerAndNotRetained() {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final List<PendingLoad> loads = new ArrayList<>();
        final PlainActionFuture<Role> first = new PlainActionFuture<>();
        final PlainActionFuture<Role> second = new PlainActionFuture<>();

        caches.getOrLoad(project, R1, recordingLoader(loads), first);
        caches.getOrLoad(project, R1, recordingLoader(loads), second);
        final Role role = role("r1");
        loads.getFirst().listener().onResponse(new GuardedRoleCaches.LoadedRole(role, Set.of("m1"), false));
        assertThat(first.actionGet(), sameInstance(role));
        assertThat(second.actionGet(), sameInstance(role));
        assertThat(caches.getRole(project, R1), nullValue());
        assertThat(caches.isNegativelyCached(project, "m1"), is(false));
        assertInternedKeysMatchCachedRoles(caches, 0);

        // the next miss loads again
        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        assertThat(loads.size(), is(2));
    }

    public void testFailedLoadFailsEveryCallerAndIsNotRetained() {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final List<PendingLoad> loads = new ArrayList<>();
        final PlainActionFuture<Role> first = new PlainActionFuture<>();
        final PlainActionFuture<Role> second = new PlainActionFuture<>();

        caches.getOrLoad(project, R1, recordingLoader(loads), first);
        caches.getOrLoad(project, R1, recordingLoader(loads), second);
        final Exception failure = new ElasticsearchException("simulated");
        loads.getFirst().listener().onFailure(failure);
        assertThat(expectThrows(ElasticsearchException.class, first::actionGet), sameInstance(failure));
        assertThat(expectThrows(ElasticsearchException.class, second::actionGet), sameInstance(failure));
        assertInternedKeysMatchCachedRoles(caches, 0);

        // the next miss loads again
        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        assertThat(loads.size(), is(2));
    }

    public void testLoaderThatThrowsFailsTheLoad() {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final PlainActionFuture<Role> future = new PlainActionFuture<>();

        caches.getOrLoad(project, R1, listener -> { throw new ElasticsearchException("simulated"); }, future);
        assertThat(expectThrows(ElasticsearchException.class, future::actionGet).getMessage(), is("simulated"));
        assertInternedKeysMatchCachedRoles(caches, 0);
    }

    /**
     * Removing a failed or uncacheable load must not remove a newer load for the same key that replaced it after an invalidation.
     */
    public void testCompletingReplacedLoadLeavesNewerLoadInPlace() {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final List<PendingLoad> loads = new ArrayList<>();

        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        caches.invalidateAll();
        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        loads.get(0).listener().onFailure(new ElasticsearchException("simulated"));
        assertInternedKeysMatchCachedRoles(caches, 1);

        final Role role = role("r1");
        loads.get(1).complete(role);
        assertThat(caches.getRole(project, R1), sameInstance(role));
    }

    /**
     * A load in flight occupies a slot in the role cache. If it is evicted, its callers still receive its role, but the role is not
     * cached.
     */
    public void testEvictedLoadServesItsCallersButIsNotCached() {
        final GuardedRoleCaches caches = newCaches(1, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final List<PendingLoad> loads = new ArrayList<>();
        final PlainActionFuture<Role> future = new PlainActionFuture<>();

        caches.getOrLoad(project, R1, recordingLoader(loads), future);
        final Role roleB = role("b");
        cache(caches, project, roleKey("b"), roleB);
        assertInternedKeysMatchCachedRoles(caches, 1);

        final Role role = role("r1");
        loads.getFirst().complete(role);
        assertThat(future.actionGet(), sameInstance(role));
        assertThat(caches.getRole(project, R1), nullValue());
        assertThat(caches.getRole(project, roleKey("b")), sameInstance(roleB));
    }

    /**
     * The load runs detached from the caller that starts it, and every caller is completed in its own context, so neither the
     * load nor another caller observes a caller's headers.
     */
    public void testLoadIsDetachedAndCallersAreCompletedInTheirOwnContext() {
        final ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        final GuardedRoleCaches caches = new GuardedRoleCaches(UNBOUNDED, UNBOUNDED, threadContext);
        final ProjectId project = randomUniqueProjectId();
        final List<PendingLoad> loads = new ArrayList<>();
        final AtomicReference<String> loaderHeader = new AtomicReference<>("unset");
        final AtomicReference<String> firstHeader = new AtomicReference<>();
        final AtomicReference<String> secondHeader = new AtomicReference<>();

        for (var caller : List.of(new Tuple<>("first", firstHeader), new Tuple<>("second", secondHeader))) {
            try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
                threadContext.putHeader("caller", caller.v1());
                caches.getOrLoad(project, R1, listener -> {
                    loaderHeader.set(threadContext.getHeader("caller"));
                    loads.add(new PendingLoad(listener));
                }, ActionListener.running(() -> caller.v2().set(threadContext.getHeader("caller"))));
            }
        }
        assertThat(loads.size(), is(1));
        assertThat(loaderHeader.get(), nullValue());

        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            threadContext.putHeader("caller", "completer");
            loads.getFirst().complete(role("r1"));
        }
        assertThat(firstHeader.get(), is("first"));
        assertThat(secondHeader.get(), is("second"));
    }

    public void testInvalidateRoleRemovesEntriesNamingTheRoleInThatProjectOnly() {
        final ProjectId project = randomUniqueProjectId();
        final ProjectId otherProject = randomUniqueProjectId();
        final GuardedRoleCaches caches = populatedCaches(project, otherProject);

        caches.invalidateRole(project, "r1");
        assertThat(caches.getRole(project, R1), nullValue());
        assertThat(caches.getRole(project, R1_R2), nullValue());
        assertThat(caches.getRole(project, R2), notNullValue());
        assertThat(caches.getRole(otherProject, R1), notNullValue());
        assertThat(caches.isNegativelyCached(project, "m1"), is(true));

        caches.invalidateRole(project, "m1");
        assertThat(caches.isNegativelyCached(project, "m1"), is(false));
        assertThat(caches.isNegativelyCached(project, "m2"), is(true));
        assertThat(caches.isNegativelyCached(otherProject, "m1"), is(true));
    }

    public void testInvalidateClusterScopedRolesRemovesEntriesNamingTheRolesInEveryProject() {
        final ProjectId project = randomUniqueProjectId();
        final ProjectId otherProject = randomUniqueProjectId();
        final GuardedRoleCaches caches = populatedCaches(project, otherProject);

        caches.invalidateClusterScopedRoles(Set.of("r1", "m1"));

        assertThat(caches.getRole(project, R1), nullValue());
        assertThat(caches.getRole(project, R1_R2), nullValue());
        assertThat(caches.getRole(project, R2), notNullValue());
        assertThat(caches.getRole(otherProject, R1), nullValue());
        assertThat(caches.isNegativelyCached(project, "m1"), is(false));
        assertThat(caches.isNegativelyCached(otherProject, "m1"), is(false));
        assertThat(caches.isNegativelyCached(project, "m2"), is(true));
    }

    public void testInvalidateProjectRemovesEntriesOfThatProjectOnly() {
        assertProjectInvalidationRemovesEntriesOfThatProjectOnly(GuardedRoleCaches::invalidateProject);
    }

    public void testRemoveProjectRemovesEntriesOfThatProjectOnly() {
        assertProjectInvalidationRemovesEntriesOfThatProjectOnly(GuardedRoleCaches::removeProject);
    }

    private static void assertProjectInvalidationRemovesEntriesOfThatProjectOnly(BiConsumer<GuardedRoleCaches, ProjectId> invalidation) {
        final ProjectId project = randomUniqueProjectId();
        final ProjectId otherProject = randomUniqueProjectId();
        final GuardedRoleCaches caches = populatedCaches(project, otherProject);

        invalidation.accept(caches, project);

        assertThat(caches.getRole(project, R1), nullValue());
        assertThat(caches.getRole(project, R1_R2), nullValue());
        assertThat(caches.getRole(project, R2), nullValue());
        assertThat(caches.getRole(otherProject, R1), notNullValue());
        assertThat(caches.isNegativelyCached(project, "m1"), is(false));
        assertThat(caches.isNegativelyCached(project, "m2"), is(false));
        assertThat(caches.isNegativelyCached(otherProject, "m1"), is(true));
    }

    public void testInvalidateAllRemovesEverything() {
        final ProjectId project = randomUniqueProjectId();
        final ProjectId otherProject = randomUniqueProjectId();
        final GuardedRoleCaches caches = populatedCaches(project, otherProject);

        caches.invalidateAll();

        assertThat(caches.getRole(project, R1), nullValue());
        assertThat(caches.getRole(project, R1_R2), nullValue());
        assertThat(caches.getRole(project, R2), nullValue());
        assertThat(caches.getRole(otherProject, R1), nullValue());
        assertThat(caches.isNegativelyCached(project, "m1"), is(false));
        assertThat(caches.isNegativelyCached(project, "m2"), is(false));
        assertThat(caches.isNegativelyCached(otherProject, "m1"), is(false));
    }

    public void testLeastRecentlyUsedRoleIsEvictedBeyondMaximum() {
        final GuardedRoleCaches caches = newCaches(2, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final Role roleA = role("a");
        final Role roleC = role("c");
        cache(caches, project, roleKey("a"), roleA);
        cache(caches, project, roleKey("b"), role("b"));
        // reading a makes b the least recently used entry
        assertThat(caches.getRole(project, roleKey("a")), sameInstance(roleA));
        cache(caches, project, roleKey("c"), roleC);

        assertThat(caches.getRole(project, roleKey("b")), nullValue());
        assertThat(caches.getRole(project, roleKey("a")), sameInstance(roleA));
        assertThat(caches.getRole(project, roleKey("c")), sameInstance(roleC));
    }

    public void testLeastRecentlyUsedNegativeLookupIsEvictedBeyondMaximum() {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, 2);
        final ProjectId project = randomUniqueProjectId();
        cache(caches, project, roleKey("a"), role("a"), "m1");
        cache(caches, project, roleKey("b"), role("b"), "m2");
        // checking m1 makes m2 the least recently used entry
        assertThat(caches.isNegativelyCached(project, "m1"), is(true));
        cache(caches, project, roleKey("c"), role("c"), "m3");

        assertThat(caches.isNegativelyCached(project, "m2"), is(false));
        assertThat(caches.isNegativelyCached(project, "m1"), is(true));
        assertThat(caches.isNegativelyCached(project, "m3"), is(true));
    }

    /**
     * A zero maximum evicts a load as soon as it is inserted, so nothing is cached and concurrent misses do not share a load.
     */
    public void testZeroMaximumRetainsNothing() {
        final GuardedRoleCaches caches = newCaches(0, 0);
        final ProjectId project = randomUniqueProjectId();
        final Role role = role("r1");
        assertThat(cache(caches, project, R1, role, "m1"), sameInstance(role));

        assertThat(caches.getRole(project, R1), nullValue());
        assertThat(caches.isNegativelyCached(project, "m1"), is(false));

        final List<PendingLoad> loads = new ArrayList<>();
        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        assertThat(loads.size(), is(2));
    }

    public void testNegativeMaximumMeansNoLimit() {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final int count = 500;
        for (int i = 0; i < count; i++) {
            final String name = "role-" + i;
            cache(caches, project, roleKey(name), role(name), "missing-" + i);
        }
        for (int i = 0; i < count; i++) {
            assertThat(caches.getRole(project, roleKey("role-" + i)), notNullValue());
            assertThat(caches.isNegativelyCached(project, "missing-" + i), is(true));
        }
    }

    /**
     * Role keys are interned outside the role cache, so every way an entry leaves the role cache must also drop its token, and
     * a load that is invalidated, fails or is immediately evicted must not leave one behind.
     */
    public void testInternedKeysTrackCachedRoles() {
        final GuardedRoleCaches bounded = newCaches(2, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final ProjectId otherProject = randomUniqueProjectId();
        for (String name : new String[] { "a", "b", "c" }) {
            cache(bounded, project, roleKey(name), role(name));
        }
        assertInternedKeysMatchCachedRoles(bounded, 2);

        final GuardedRoleCaches caches = populatedCaches(project, otherProject);
        assertInternedKeysMatchCachedRoles(caches, 4);
        caches.invalidateRole(project, "r1");
        assertInternedKeysMatchCachedRoles(caches, 2);
        caches.invalidateClusterScopedRoles(Set.of("r1"));
        assertInternedKeysMatchCachedRoles(caches, 1);
        caches.invalidateProject(project);
        assertInternedKeysMatchCachedRoles(caches, 0);

        final List<PendingLoad> loads = new ArrayList<>();
        caches.getOrLoad(project, R1, recordingLoader(loads), new PlainActionFuture<>());
        assertInternedKeysMatchCachedRoles(caches, 1);
        caches.invalidateAll();
        loads.getFirst().complete(role("r1"));
        assertInternedKeysMatchCachedRoles(caches, 0);

        final GuardedRoleCaches retainsNothing = newCaches(0, 0);
        cache(retainsNothing, project, R1, role("r1"));
        assertInternedKeysMatchCachedRoles(retainsNothing, 0);
    }

    private static void assertInternedKeysMatchCachedRoles(GuardedRoleCaches caches, int expected) {
        assertThat(caches.cachedRoleKeys().size(), is(expected));
        assertThat(caches.internedKeyCount(), is(expected));
    }

    /**
     * Every operation runs under the monitor, so a read that arrives while an invalidation is scanning the caches waits for
     * the invalidation to finish and observes its result. This rules out, by construction, a concurrent read disturbing the scan.
     * <p>
     * The scan evaluates its predicate once per cached role, and for {@link GuardedRoleCaches#invalidateClusterScopedRoles} the
     * predicate iterates the caller-supplied set of changed role names. Instrumenting that set's iterator is therefore a
     * deterministic way to start the read at a precise point of the scan.
     */
    public void testReadWaitsForInvalidationInProgress() throws Exception {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        final ProjectId project = randomUniqueProjectId();
        final RoleKey keyA = roleKey("role-a");
        final RoleKey keyB = roleKey("role-b");
        cache(caches, project, keyA, role("role-a"));
        cache(caches, project, keyB, role("role-b"));

        final AtomicReference<Role> observed = new AtomicReference<>();
        final Thread reader = new Thread(() -> observed.set(caches.getRole(project, keyA)), "reader");
        final AtomicInteger scanVisits = new AtomicInteger();
        final Set<String> changedRoles = new HashSet<>(Set.of("role-a")) {
            @Override
            public Iterator<String> iterator() {
                if (scanVisits.incrementAndGet() == 1) {
                    // The scan is on its first key and holds the monitor; the reader must block until the scan completes
                    reader.start();
                    try {
                        assertBusy(() -> assertThat(reader.getState(), is(Thread.State.BLOCKED)));
                    } catch (Exception e) {
                        throw new AssertionError(e);
                    }
                }
                return super.iterator();
            }
        };
        caches.invalidateClusterScopedRoles(changedRoles);
        reader.join(10_000);
        assertFalse("the reader must complete once the invalidation has released the monitor", reader.isAlive());

        assertThat(
            "the instrumented set must be iterated once per cached role for this test to exercise the scan",
            scanVisits.get(),
            is(2)
        );
        assertThat("the read must observe the completed invalidation", observed.get(), nullValue());
        assertThat(caches.getRole(project, keyB), notNullValue());
    }

    /**
     * Caches, in {@code project}, the roles {r1}, {r1, r2} and {r2} with the missing names m1 and m2, and in {@code otherProject}
     * the role {r1} with the missing name m1.
     */
    private static GuardedRoleCaches populatedCaches(ProjectId project, ProjectId otherProject) {
        final GuardedRoleCaches caches = newCaches(UNBOUNDED, UNBOUNDED);
        cache(caches, project, R1, role("r1"), "m1");
        cache(caches, project, R1_R2, role("r1", "r2"), "m2");
        cache(caches, project, R2, role("r2"));
        cache(caches, otherProject, R1, role("r1"), "m1");
        return caches;
    }

    /**
     * Loads {@code role} for the key through a loader that completes immediately, and returns the role served to the caller.
     */
    private static Role cache(GuardedRoleCaches caches, ProjectId projectId, RoleKey roleKey, Role role, String... missingNames) {
        final PlainActionFuture<Role> future = new PlainActionFuture<>();
        caches.getOrLoad(
            projectId,
            roleKey,
            listener -> listener.onResponse(new GuardedRoleCaches.LoadedRole(role, Set.of(missingNames), true)),
            future
        );
        return future.actionGet();
    }

    private record PendingLoad(ActionListener<GuardedRoleCaches.LoadedRole> listener) {
        void complete(Role role, String... missingNames) {
            listener.onResponse(new GuardedRoleCaches.LoadedRole(role, Set.of(missingNames), true));
        }
    }

    private static GuardedRoleCaches.RoleLoader recordingLoader(List<PendingLoad> loads) {
        return listener -> loads.add(new PendingLoad(listener));
    }

    private static GuardedRoleCaches newCaches(int maximumRoles, int maximumNegativeLookups) {
        return new GuardedRoleCaches(maximumRoles, maximumNegativeLookups, new ThreadContext(Settings.EMPTY));
    }

    private static RoleKey roleKey(String... names) {
        return new RoleKey(Set.of(names), RoleKey.ROLES_STORE_SOURCE);
    }

    private static Role role(String... names) {
        return Role.builder(TestRestrictedIndices.RESTRICTED_INDICES, names).build();
    }
}
