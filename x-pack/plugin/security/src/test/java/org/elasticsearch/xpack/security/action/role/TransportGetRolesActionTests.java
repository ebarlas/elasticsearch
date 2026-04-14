/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.action.role;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.action.role.GetRolesRequest;
import org.elasticsearch.xpack.core.security.action.role.GetRolesResponse;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor.IndicesPrivileges;
import org.elasticsearch.xpack.core.security.authz.store.ReservedRolesStore;
import org.elasticsearch.xpack.core.security.authz.store.RoleRetrievalResult;
import org.elasticsearch.xpack.core.security.user.UsernamesField;
import org.elasticsearch.xpack.security.authz.ReservedRoleNameChecker;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;
import org.elasticsearch.xpack.security.authz.store.NativeRolesStore;
import org.junit.BeforeClass;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.elasticsearch.test.ActionListenerUtils.anyActionListener;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class TransportGetRolesActionTests extends ESTestCase {

    @BeforeClass
    public static void setUpClass() {
        // Initialize the reserved roles store so that static fields are populated.
        // In production code, this is guaranteed by how components are initialized by the Security plugin
        new ReservedRolesStore();
    }

    public void testReservedRoles() {
        NativeRolesStore rolesStore = mock(NativeRolesStore.class);
        TransportService transportService = new TransportService(
            Settings.EMPTY,
            mock(Transport.class),
            mock(ThreadPool.class),
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            x -> null,
            null,
            Collections.emptySet()
        );
        TransportGetRolesAction action = new TransportGetRolesAction(
            mock(ActionFilters.class),
            rolesStore,
            new ReservedRoleNameChecker.Default(),
            mock(CompositeRolesStore.class),
            transportService
        );

        final int size = randomIntBetween(1, ReservedRolesStore.names().size());
        final List<String> names = randomSubsetOf(size, ReservedRolesStore.names());

        final List<String> expectedNames = new ArrayList<>(names);

        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            assert args.length == 2;
            @SuppressWarnings("unchecked")
            ActionListener<RoleRetrievalResult> listener = (ActionListener<RoleRetrievalResult>) args[1];
            listener.onResponse(RoleRetrievalResult.success(Collections.emptySet()));
            return null;
        }).when(rolesStore).getRoleDescriptors(eq(new HashSet<>()), anyActionListener());

        GetRolesRequest request = new GetRolesRequest();
        request.names(names.toArray(Strings.EMPTY_ARRAY));

        final AtomicReference<Throwable> throwableRef = new AtomicReference<>();
        final AtomicReference<GetRolesResponse> responseRef = new AtomicReference<>();
        action.doExecute(mock(Task.class), request, new ActionListener<GetRolesResponse>() {
            @Override
            public void onResponse(GetRolesResponse response) {
                responseRef.set(response);
            }

            @Override
            public void onFailure(Exception e) {
                throwableRef.set(e);
            }
        });

        assertThat(throwableRef.get(), is(nullValue()));
        assertThat(responseRef.get(), is(notNullValue()));
        List<String> retrievedRoleNames = Arrays.asList(responseRef.get().roles())
            .stream()
            .map(RoleDescriptor::getName)
            .collect(Collectors.toList());
        assertThat(retrievedRoleNames, containsInAnyOrder(expectedNames.toArray(Strings.EMPTY_ARRAY)));
        verifyNoMoreInteractions(rolesStore);
    }

    public void testStoreRoles() {
        testStoreRoles(randomRoleDescriptors());
    }

    public void testStoreRolesWithInternalRoleNames() {
        testStoreRoles(
            randomNonEmptySubsetOf(
                Stream.of(
                    UsernamesField.SYSTEM_ROLE,
                    UsernamesField.XPACK_ROLE,
                    UsernamesField.ASYNC_SEARCH_ROLE,
                    UsernamesField.XPACK_SECURITY_ROLE,
                    UsernamesField.SECURITY_PROFILE_ROLE
                ).map(r -> new RoleDescriptor(r, null, null, null)).toList()
            )
        );
    }

    private void testStoreRoles(List<RoleDescriptor> storeRoleDescriptors) {
        NativeRolesStore rolesStore = mock(NativeRolesStore.class);
        TransportService transportService = new TransportService(
            Settings.EMPTY,
            mock(Transport.class),
            mock(ThreadPool.class),
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            x -> null,
            null,
            Collections.emptySet()
        );
        TransportGetRolesAction action = new TransportGetRolesAction(
            mock(ActionFilters.class),
            rolesStore,
            new ReservedRoleNameChecker.Default(),
            mock(CompositeRolesStore.class),
            transportService
        );

        GetRolesRequest request = new GetRolesRequest();
        request.names(storeRoleDescriptors.stream().map(RoleDescriptor::getName).collect(Collectors.toList()).toArray(Strings.EMPTY_ARRAY));

        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            assert args.length == 2;
            @SuppressWarnings("unchecked")
            ActionListener<RoleRetrievalResult> listener = (ActionListener<RoleRetrievalResult>) args[1];
            listener.onResponse(RoleRetrievalResult.success(new HashSet<>(storeRoleDescriptors)));
            return null;
        }).when(rolesStore).getRoleDescriptors(eq(new HashSet<>(Arrays.asList(request.names()))), anyActionListener());

        final AtomicReference<Throwable> throwableRef = new AtomicReference<>();
        final AtomicReference<GetRolesResponse> responseRef = new AtomicReference<>();
        action.doExecute(mock(Task.class), request, new ActionListener<GetRolesResponse>() {
            @Override
            public void onResponse(GetRolesResponse response) {
                responseRef.set(response);
            }

            @Override
            public void onFailure(Exception e) {
                throwableRef.set(e);
            }
        });

        assertThat(throwableRef.get(), is(nullValue()));
        assertThat(responseRef.get(), is(notNullValue()));
        List<String> retrievedRoleNames = Arrays.asList(responseRef.get().roles())
            .stream()
            .map(RoleDescriptor::getName)
            .collect(Collectors.toList());
        assertThat(retrievedRoleNames, containsInAnyOrder(request.names()));
    }

    public void testGetAllOrMix() {
        final boolean all = randomBoolean();
        final List<RoleDescriptor> storeRoleDescriptors = randomRoleDescriptors();
        final List<String> storeNames = storeRoleDescriptors.stream().map(RoleDescriptor::getName).collect(Collectors.toList());
        final List<String> reservedRoleNames = new ArrayList<>(ReservedRolesStore.names());

        final List<String> requestedNames = new ArrayList<>();
        List<String> specificStoreNames = new ArrayList<>();
        if (all == false) {
            requestedNames.addAll(randomSubsetOf(randomIntBetween(1, ReservedRolesStore.names().size()), ReservedRolesStore.names()));
            specificStoreNames.addAll(randomSubsetOf(randomIntBetween(1, storeNames.size()), storeNames));
            requestedNames.addAll(specificStoreNames);
        }

        NativeRolesStore rolesStore = mock(NativeRolesStore.class);
        TransportService transportService = new TransportService(
            Settings.EMPTY,
            mock(Transport.class),
            mock(ThreadPool.class),
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            x -> null,
            null,
            Collections.emptySet()
        );
        TransportGetRolesAction action = new TransportGetRolesAction(
            mock(ActionFilters.class),
            rolesStore,
            new ReservedRoleNameChecker.Default(),
            mock(CompositeRolesStore.class),
            transportService
        );

        final List<String> expectedNames = new ArrayList<>();
        if (all) {
            expectedNames.addAll(reservedRoleNames);
            expectedNames.addAll(storeNames);
        } else {
            expectedNames.addAll(requestedNames);
        }

        GetRolesRequest request = new GetRolesRequest();
        request.names(requestedNames.toArray(Strings.EMPTY_ARRAY));

        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            assert args.length == 2;
            @SuppressWarnings("unchecked")
            Set<String> requestedNames1 = (Set<String>) args[0];
            @SuppressWarnings("unchecked")
            ActionListener<RoleRetrievalResult> listener = (ActionListener<RoleRetrievalResult>) args[1];
            if (requestedNames1.size() == 0) {
                listener.onResponse(RoleRetrievalResult.success(new HashSet<>(storeRoleDescriptors)));
            } else {
                listener.onResponse(
                    RoleRetrievalResult.success(
                        storeRoleDescriptors.stream().filter(r -> requestedNames1.contains(r.getName())).collect(Collectors.toSet())
                    )
                );
            }
            return null;
        }).when(rolesStore).getRoleDescriptors(eq(new HashSet<>(specificStoreNames)), anyActionListener());

        final AtomicReference<Throwable> throwableRef = new AtomicReference<>();
        final AtomicReference<GetRolesResponse> responseRef = new AtomicReference<>();
        action.doExecute(mock(Task.class), request, new ActionListener<GetRolesResponse>() {
            @Override
            public void onResponse(GetRolesResponse response) {
                responseRef.set(response);
            }

            @Override
            public void onFailure(Exception e) {
                throwableRef.set(e);
            }
        });

        assertThat(throwableRef.get(), is(nullValue()));
        assertThat(responseRef.get(), is(notNullValue()));
        List<String> retrievedRoleNames = Arrays.asList(responseRef.get().roles())
            .stream()
            .map(RoleDescriptor::getName)
            .collect(Collectors.toList());
        assertThat(retrievedRoleNames, containsInAnyOrder(expectedNames.toArray(Strings.EMPTY_ARRAY)));

        if (all) {
            verify(rolesStore, times(1)).getRoleDescriptors(eq(new HashSet<>()), anyActionListener());
        } else {
            verify(rolesStore, times(1)).getRoleDescriptors(eq(new HashSet<>(specificStoreNames)), anyActionListener());
        }
    }

    public void testGetWithNativeOnly() {
        final boolean all = randomBoolean();
        final List<RoleDescriptor> storeRoleDescriptors = randomRoleDescriptors();
        final List<String> storeNames = storeRoleDescriptors.stream().map(RoleDescriptor::getName).collect(Collectors.toList());

        final List<String> requestedNames = new ArrayList<>();
        final List<String> requestedStoreNames = new ArrayList<>();
        if (all == false) {
            // Add some reserved roles; we don't expect these to be returned by the native role store
            requestedNames.addAll(randomSubsetOf(randomIntBetween(1, ReservedRolesStore.names().size()), ReservedRolesStore.names()));
            requestedStoreNames.addAll(randomSubsetOf(randomIntBetween(1, storeNames.size()), storeNames));
            requestedNames.addAll(requestedStoreNames);
        }

        final NativeRolesStore rolesStore = mockNativeRolesStore(requestedStoreNames, storeRoleDescriptors);

        final TransportService transportService = new TransportService(
            Settings.EMPTY,
            mock(Transport.class),
            mock(ThreadPool.class),
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            x -> null,
            null,
            Collections.emptySet()
        );
        final TransportGetRolesAction action = new TransportGetRolesAction(
            mock(ActionFilters.class),
            rolesStore,
            new ReservedRoleNameChecker.Default(),
            mock(CompositeRolesStore.class),
            transportService
        );

        final GetRolesRequest request = new GetRolesRequest();
        request.names(requestedNames.toArray(Strings.EMPTY_ARRAY));
        request.nativeOnly(true);

        final List<String> actualRoleNames = doExecuteSuccessfully(action, request);
        if (all) {
            assertThat(actualRoleNames, containsInAnyOrder(storeNames.toArray(Strings.EMPTY_ARRAY)));
            verify(rolesStore, times(1)).getRoleDescriptors(eq(new HashSet<>()), anyActionListener());
        } else {
            assertThat(actualRoleNames, containsInAnyOrder(requestedStoreNames.toArray(Strings.EMPTY_ARRAY)));
            verify(rolesStore, times(1)).getRoleDescriptors(eq(new HashSet<>(requestedStoreNames)), anyActionListener());
        }
    }

    public void testIncludeImplicitMergesImplicitPrivileges() {
        NativeRolesStore rolesStore = mock(NativeRolesStore.class);
        CompositeRolesStore compositeRolesStore = mock(CompositeRolesStore.class);
        TransportService transportService = new TransportService(
            Settings.EMPTY,
            mock(Transport.class),
            mock(ThreadPool.class),
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            x -> null,
            null,
            Collections.emptySet()
        );
        TransportGetRolesAction action = new TransportGetRolesAction(
            mock(ActionFilters.class),
            rolesStore,
            new ReservedRoleNameChecker.Default(),
            compositeRolesStore,
            transportService
        );

        RoleDescriptor roleWithAppPrivs = new RoleDescriptor(
            "test_role",
            null,
            new IndicesPrivileges[] {
                IndicesPrivileges.builder().indices("my-index-*").privileges("read").build() },
            new RoleDescriptor.ApplicationResourcePrivileges[] {
                RoleDescriptor.ApplicationResourcePrivileges.builder()
                    .application("kibana-.kibana")
                    .privileges("feature_alerting_read")
                    .resources("space:marketing")
                    .build() },
            null,
            null,
            null,
            null
        );

        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            ActionListener<RoleRetrievalResult> listener = (ActionListener<RoleRetrievalResult>) invocation.getArguments()[1];
            listener.onResponse(RoleRetrievalResult.success(Set.of(roleWithAppPrivs)));
            return null;
        }).when(rolesStore).getRoleDescriptors(eq(Set.of("test_role")), anyActionListener());

        // Mock resolveImplicitPrivileges to return an implicit alerts privilege
        IndicesPrivileges implicitAlerts = IndicesPrivileges.builder().indices(".alerts-*").privileges("read").query(
            "{\"terms\":{\"kibana.space_ids\":[\"marketing\"]}}"
        ).build();
        doAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            ActionListener<Map<String, Collection<IndicesPrivileges>>> listener =
                (ActionListener<Map<String, Collection<IndicesPrivileges>>>) invocation.getArguments()[1];
            listener.onResponse(Map.of("test_role", List.of(implicitAlerts)));
            return null;
        }).when(compositeRolesStore).resolveImplicitPrivileges(any(), anyActionListener());

        GetRolesRequest request = new GetRolesRequest();
        request.names("test_role");
        request.includeImplicit(true);

        final AtomicReference<Throwable> throwableRef = new AtomicReference<>();
        final AtomicReference<GetRolesResponse> responseRef = new AtomicReference<>();
        action.doExecute(mock(Task.class), request, new ActionListener<>() {
            @Override
            public void onResponse(GetRolesResponse response) {
                responseRef.set(response);
            }

            @Override
            public void onFailure(Exception e) {
                throwableRef.set(e);
            }
        });

        assertThat(throwableRef.get(), is(nullValue()));
        assertThat(responseRef.get(), is(notNullValue()));
        RoleDescriptor[] roles = responseRef.get().roles();
        assertThat(roles.length, is(1));
        RoleDescriptor result = roles[0];
        assertThat(result.getName(), is("test_role"));

        // Should have original + implicit indices privileges
        IndicesPrivileges[] indices = result.getIndicesPrivileges();
        assertThat(indices.length, is(2));

        // Original privilege is not implicit
        assertThat(indices[0].getIndices()[0], is("my-index-*"));
        assertThat(indices[0].isImplicitlyGranted(), is(false));

        // Implicit privilege is flagged
        assertThat(indices[1].getIndices()[0], is(".alerts-*"));
        assertThat(indices[1].isImplicitlyGranted(), is(true));
        assertThat(indices[1].getQuery().utf8ToString(), is("{\"terms\":{\"kibana.space_ids\":[\"marketing\"]}}"));

        // Application privileges are preserved
        assertThat(result.getApplicationPrivileges().length, is(1));
    }

    public void testMergeImplicitPrivileges() {
        RoleDescriptor original = new RoleDescriptor(
            "role1",
            new String[] { "monitor" },
            new IndicesPrivileges[] { IndicesPrivileges.builder().indices("data-*").privileges("read").build() },
            null
        );

        Collection<IndicesPrivileges> implicit = List.of(
            IndicesPrivileges.builder().indices(".alerts-*").privileges("read").build()
        );

        RoleDescriptor merged = TransportGetRolesAction.mergeImplicitPrivileges(original, implicit);

        assertThat(merged.getName(), is("role1"));
        assertThat(merged.getClusterPrivileges(), is(new String[] { "monitor" }));
        assertThat(merged.getIndicesPrivileges().length, is(2));
        assertThat(merged.getIndicesPrivileges()[0].getIndices()[0], is("data-*"));
        assertThat(merged.getIndicesPrivileges()[0].isImplicitlyGranted(), is(false));
        assertThat(merged.getIndicesPrivileges()[1].getIndices()[0], is(".alerts-*"));
        assertThat(merged.getIndicesPrivileges()[1].isImplicitlyGranted(), is(true));
    }

    private List<String> doExecuteSuccessfully(TransportGetRolesAction action, GetRolesRequest request) {
        final AtomicReference<Throwable> throwableRef = new AtomicReference<>();
        final AtomicReference<GetRolesResponse> responseRef = new AtomicReference<>();
        action.doExecute(mock(Task.class), request, new ActionListener<>() {
            @Override
            public void onResponse(GetRolesResponse response) {
                responseRef.set(response);
            }

            @Override
            public void onFailure(Exception e) {
                throwableRef.set(e);
            }
        });

        assertThat(throwableRef.get(), is(nullValue()));
        assertThat(responseRef.get(), is(notNullValue()));
        return Arrays.stream(responseRef.get().roles()).map(RoleDescriptor::getName).collect(Collectors.toList());
    }

    private NativeRolesStore mockNativeRolesStore(List<String> expectedStoreNames, List<RoleDescriptor> storeRoleDescriptors) {
        NativeRolesStore rolesStore = mock(NativeRolesStore.class);
        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            assert args.length == 2;
            @SuppressWarnings("unchecked")
            Set<String> requestedNames = (Set<String>) args[0];
            @SuppressWarnings("unchecked")
            ActionListener<RoleRetrievalResult> listener = (ActionListener<RoleRetrievalResult>) args[1];
            if (requestedNames.size() == 0) {
                listener.onResponse(RoleRetrievalResult.success(new HashSet<>(storeRoleDescriptors)));
            } else {
                listener.onResponse(
                    RoleRetrievalResult.success(
                        storeRoleDescriptors.stream().filter(r -> requestedNames.contains(r.getName())).collect(Collectors.toSet())
                    )
                );
            }
            return null;
        }).when(rolesStore).getRoleDescriptors(eq(new HashSet<>(expectedStoreNames)), anyActionListener());
        return rolesStore;
    }

    public void testException() {
        final Exception e = randomFrom(new ElasticsearchSecurityException(""), new IllegalStateException());
        final List<RoleDescriptor> storeRoleDescriptors = randomRoleDescriptors();
        NativeRolesStore rolesStore = mock(NativeRolesStore.class);
        TransportService transportService = new TransportService(
            Settings.EMPTY,
            mock(Transport.class),
            mock(ThreadPool.class),
            TransportService.NOOP_TRANSPORT_INTERCEPTOR,
            x -> null,
            null,
            Collections.emptySet()
        );
        TransportGetRolesAction action = new TransportGetRolesAction(
            mock(ActionFilters.class),
            rolesStore,
            new ReservedRoleNameChecker.Default(),
            mock(CompositeRolesStore.class),
            transportService
        );

        GetRolesRequest request = new GetRolesRequest();
        request.names(storeRoleDescriptors.stream().map(RoleDescriptor::getName).collect(Collectors.toList()).toArray(Strings.EMPTY_ARRAY));

        doAnswer(invocation -> {
            Object[] args = invocation.getArguments();
            assert args.length == 2;
            @SuppressWarnings("unchecked")
            ActionListener<RoleRetrievalResult> listener = (ActionListener<RoleRetrievalResult>) args[1];
            listener.onFailure(e);
            return null;
        }).when(rolesStore).getRoleDescriptors(eq(new HashSet<>(Arrays.asList(request.names()))), anyActionListener());

        final AtomicReference<Throwable> throwableRef = new AtomicReference<>();
        final AtomicReference<GetRolesResponse> responseRef = new AtomicReference<>();
        action.doExecute(mock(Task.class), request, new ActionListener<GetRolesResponse>() {
            @Override
            public void onResponse(GetRolesResponse response) {
                responseRef.set(response);
            }

            @Override
            public void onFailure(Exception e) {
                throwableRef.set(e);
            }
        });

        assertThat(throwableRef.get(), is(notNullValue()));
        assertThat(throwableRef.get(), is(e));
        assertThat(responseRef.get(), is(nullValue()));
    }

    private List<RoleDescriptor> randomRoleDescriptors() {
        int size = scaledRandomIntBetween(1, 10);
        List<RoleDescriptor> list = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            list.add(new RoleDescriptor("role_" + i, null, null, null));
        }
        return list;
    }
}
