/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.authz.store;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ContextPreservingActionListener;
import org.elasticsearch.action.support.SubscribableListener;
import org.elasticsearch.cluster.metadata.ProjectId;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.common.util.set.Sets;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.xpack.core.security.authz.permission.Role;
import org.elasticsearch.xpack.core.security.authz.store.RoleKey;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * Owns the role cache and the negative-lookup cache of the {@link CompositeRolesStore} and keeps them consistent with the role
 * sources across invalidations.
 * <p>
 * The role cache holds a {@link RoleLoad} per key, which is inserted on the first miss and completed when the role is built, so
 * concurrent misses for the same key share one resolution, and a burst of requests after an invalidation does not resolve and build
 * the same role once per request. A load that fails or whose role must not be cached is removed before its callers are completed,
 * so the next miss resolves again.
 * <p>
 * Every operation takes this object's monitor, and nothing expensive runs under it: resolving descriptors and building the role
 * happen outside it, and a read hashes and compares the role key, whose cost grows with the number of role names, before taking
 * the monitor. To make that possible, each cached role key is interned to an {@link InternedKey} whose equality is identity, and the
 * role cache is keyed by that token, so a lookup under the monitor costs the same regardless of the size of the key.
 * <p>
 * An invalidation removes the affected entries from both caches, whether their loads have completed or not, so a load that overlaps
 * an invalidation is no longer cached when it completes, and a caller that arrives after the invalidation starts a new load rather
 * than joining it. The names a load found missing are recorded only when it completes, so an invalidation also advances a
 * generation, which a load captures before it consults any role source. A load that finds the generation moved when it completes
 * records no missing names, since it cannot tell whether they were found missing before or after the invalidation.
 * <p>
 * There is one generation per project plus a global one, so an invalidation scoped to one project does not discard the missing
 * names found by loads in flight for other projects.
 */
final class GuardedRoleCaches {

    private static final Logger logger = LogManager.getLogger(GuardedRoleCaches.class);

    /**
     * The state of the caches as observed by a load before it consulted any role source.
     */
    private record Generation(long project, long global) {}

    /**
     * A cache key that scopes another key to a project.
     */
    record ProjectScoped<T>(ProjectId projectId, T value) {
        ProjectScoped {
            Objects.requireNonNull(projectId);
        }
    }

    /**
     * The canonical token for a cached role key. It does not override {@code equals} or {@code hashCode}, so a lookup by token
     * under the monitor is an identity comparison. Two tokens for equal keys can only cost a cache miss, never serve the wrong role.
     */
    static final class InternedKey {
        private final ProjectScoped<RoleKey> key;

        private InternedKey(ProjectScoped<RoleKey> key) {
            this.key = key;
        }
    }

    /**
     * What a {@link RoleLoader} built. {@code missingNames} are the role names that no source defined, and {@code cacheable} is
     * whether the role may be served to later callers and its missing names recorded.
     */
    record LoadedRole(Role role, Set<String> missingNames, boolean cacheable) {}

    /**
     * Resolves and builds a role that missed the cache.
     */
    @FunctionalInterface
    interface RoleLoader {
        void load(ActionListener<LoadedRole> listener);
    }

    /**
     * The entry for a key in the role cache, completed with the role once it has been built.
     */
    private static final class RoleLoad extends SubscribableListener<Role> {
        @Nullable
        Role completedRole() {
            if (isSuccess() == false) {
                return null;
            }
            try {
                return rawResult();
            } catch (Exception e) {
                throw new AssertionError("a successful load has a result", e);
            }
        }
    }

    private final ThreadContext threadContext;

    /**
     * Maps each key in {@link #roles} to its token. Read without the monitor, but only modified under it, alongside {@link #roles},
     * so it holds exactly the keys of {@link #roles}. A reader can find a token whose role has just been removed; it then misses.
     */
    private final ConcurrentHashMap<ProjectScoped<RoleKey>, InternedKey> interned = new ConcurrentHashMap<>();

    // All fields below are guarded by this object's monitor
    private final Map<InternedKey, RoleLoad> roles;
    private final Map<ProjectScoped<String>, Boolean> negativeLookups;
    private final Map<ProjectId, Long> projectGenerations = new HashMap<>();
    private long globalGeneration;

    /**
     * @param maximumRoles           the maximum number of cached roles, including loads in flight, or a negative value for no limit
     * @param maximumNegativeLookups the maximum number of cached negative lookups, or a negative value for no limit
     * @param threadContext          the context in which each caller of {@link #getOrLoad} is completed
     */
    GuardedRoleCaches(int maximumRoles, int maximumNegativeLookups, ThreadContext threadContext) {
        this.threadContext = Objects.requireNonNull(threadContext);
        this.roles = leastRecentlyUsedMap(maximumRoles, token -> interned.remove(token.key, token));
        this.negativeLookups = leastRecentlyUsedMap(maximumNegativeLookups, key -> {});
    }

    /**
     * A map ordered by most recent access that drops its least recently used entry once it holds more than {@code maximumSize}
     * entries, passing its key to {@code onEvict}. A negative maximum means no limit; zero means nothing is ever retained.
     */
    private static <K, V> Map<K, V> leastRecentlyUsedMap(int maximumSize, Consumer<K> onEvict) {
        return new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                if (maximumSize >= 0 && size() > maximumSize) {
                    onEvict.accept(eldest.getKey());
                    return true;
                }
                return false;
            }
        };
    }

    private static <T extends ProjectScoped<?>> Predicate<T> eq(ProjectId projectId) {
        return key -> key.projectId().equals(projectId);
    }

    /**
     * Removes the cached roles whose keys match, together with their tokens.
     */
    private void removeRoles(Predicate<ProjectScoped<RoleKey>> predicate) {
        assert Thread.holdsLock(this);
        final Iterator<InternedKey> iterator = roles.keySet().iterator();
        while (iterator.hasNext()) {
            final InternedKey token = iterator.next();
            if (predicate.test(token.key)) {
                iterator.remove();
                interned.remove(token.key, token);
            }
        }
    }

    /**
     * Completes {@code listener} with the cached role for the key, or otherwise with the role built by {@code loader}. Concurrent
     * misses for the same key share one invocation of {@code loader}, and all of them receive its role or failure.
     * <p>
     * A caller whose key has a completed load is completed inline. Otherwise it is completed on the thread that completes the load,
     * but in its own thread context. The load is shared, so it runs detached from the context of the caller that starts it; the
     * stash keeps the project id, which the loader needs to resolve the project's roles.
     */
    void getOrLoad(ProjectId projectId, RoleKey roleKey, RoleLoader loader, ActionListener<Role> listener) {
        // Hashing and comparing the key happen here, outside the monitor
        final ProjectScoped<RoleKey> key = new ProjectScoped<>(projectId, roleKey);
        final Lookup lookup = findOrInsert(key, interned.get(key));
        lookup.load().addListener(listener, EsExecutors.DIRECT_EXECUTOR_SERVICE, threadContext);
        if (lookup.inserted() == false) {
            return;
        }

        final RoleLoad newLoad = lookup.load();
        final InternedKey token = lookup.token();
        final Generation generation = lookup.generation();
        // Completed in an empty context, so callers cannot inherit response headers from the completing thread
        final ActionListener<LoadedRole> completionListener = new ContextPreservingActionListener<>(
            threadContext::newEmptyContext,
            ActionListener.wrap(loaded -> {
                complete(projectId, token, newLoad, generation, loaded);
                newLoad.onResponse(loaded.role());
            }, e -> {
                removeLoad(token, newLoad);
                newLoad.onFailure(e);
            })
        );
        try (ThreadContext.StoredContext ignored = threadContext.stashContext()) {
            ActionListener.run(completionListener, loader::load);
        }
    }

    /**
     * The entry a caller of {@link #getOrLoad} subscribes to. If the caller inserted it, and so must run the load, {@code token} and
     * {@code generation} are what the load needs to complete it; otherwise they are {@code null}.
     */
    private record Lookup(RoleLoad load, @Nullable InternedKey token, @Nullable Generation generation) {
        boolean inserted() {
            return token != null;
        }
    }

    /**
     * Returns the entry for {@code key}, inserting a new load if there is none. {@code existingToken} is the token for the key that
     * the caller read outside the monitor, if any; it may since have been removed.
     */
    private synchronized Lookup findOrInsert(ProjectScoped<RoleKey> key, @Nullable InternedKey existingToken) {
        final RoleLoad existing = existingToken == null ? null : roles.get(existingToken);
        if (existing != null) {
            return new Lookup(existing, null, null);
        }
        // Interned under the monitor so that the table never holds a token that is absent from the role cache. On a miss the key
        // is hashed under the monitor; a hit, the common case, does not pay for it.
        final InternedKey token = interned.computeIfAbsent(key, InternedKey::new);
        final RoleLoad raced = roles.get(token);
        if (raced != null) {
            return new Lookup(raced, null, null);
        }
        final RoleLoad load = new RoleLoad();
        roles.put(token, load);
        // Captured before any source is consulted (resolving the key reads the negative-lookup cache)
        return new Lookup(load, token, generation(key.projectId()));
    }

    /**
     * Removes the completed load from the role cache if its role must not be cached, and otherwise records the names it found
     * missing unless an invalidation has moved the generation since the load captured it.
     */
    private synchronized void complete(ProjectId projectId, InternedKey token, RoleLoad load, Generation generation, LoadedRole loaded) {
        if (loaded.cacheable() == false) {
            removeLoad(token, load);
            return;
        }
        if (generation.equals(generation(projectId)) == false) {
            logger.trace(
                "not caching missing roles [{}] in project [{}] because the caches were invalidated while they were resolved",
                loaded.missingNames(),
                projectId
            );
            return;
        }
        for (String name : loaded.missingNames()) {
            negativeLookups.put(new ProjectScoped<>(projectId, name), Boolean.TRUE);
        }
    }

    /**
     * Removes {@code load} from the role cache, unless an invalidation or eviction already has; in that case another load may now
     * occupy the key.
     */
    private synchronized void removeLoad(InternedKey token, RoleLoad load) {
        if (roles.remove(token, load)) {
            interned.remove(token.key, token);
        }
    }

    // for testing
    @Nullable
    Role getRole(ProjectId projectId, RoleKey roleKey) {
        final InternedKey token = interned.get(new ProjectScoped<>(projectId, roleKey));
        if (token == null) {
            return null;
        }
        final RoleLoad load;
        synchronized (this) {
            load = roles.get(token);
        }
        return load == null ? null : load.completedRole();
    }

    synchronized boolean isNegativelyCached(ProjectId projectId, String roleName) {
        // get rather than containsKey so that the lookup counts as an access for eviction purposes
        return negativeLookups.get(new ProjectScoped<>(projectId, roleName)) != null;
    }

    private Generation generation(ProjectId projectId) {
        assert Thread.holdsLock(this);
        return new Generation(projectGenerations.getOrDefault(projectId, 0L), globalGeneration);
    }

    synchronized void invalidateAll() {
        roles.clear();
        interned.clear();
        negativeLookups.clear();
        globalGeneration++;
    }

    synchronized void invalidateProject(ProjectId projectId) {
        removeRoles(eq(projectId));
        negativeLookups.keySet().removeIf(eq(projectId));
        projectGenerations.merge(projectId, 1L, Long::sum);
    }

    synchronized void removeProject(ProjectId projectId) {
        removeRoles(eq(projectId));
        negativeLookups.keySet().removeIf(eq(projectId));
        projectGenerations.remove(projectId);
        // Loads still in flight for the removed project captured a per-project generation that is now forgotten; advancing the
        // global generation keeps them from recording missing names
        globalGeneration++;
    }

    synchronized void invalidateRole(ProjectId projectId, String role) {
        removeRoles(key -> key.projectId().equals(projectId) && key.value().getNames().contains(role));
        negativeLookups.remove(new ProjectScoped<>(projectId, role));
        projectGenerations.merge(projectId, 1L, Long::sum);
    }

    synchronized void invalidateClusterScopedRoles(Set<String> names) {
        removeRoles(key -> Sets.haveEmptyIntersection(key.value().getNames(), names) == false);
        negativeLookups.keySet().removeIf(key -> names.contains(key.value()));
        globalGeneration++;
    }

    // for testing; includes loads in flight
    synchronized List<ProjectScoped<RoleKey>> cachedRoleKeys() {
        return roles.keySet().stream().map(token -> token.key).toList();
    }

    // for testing
    int internedKeyCount() {
        return interned.size();
    }
}
