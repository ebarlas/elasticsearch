/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.action.role;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.TransportAction;
import org.elasticsearch.common.util.concurrent.EsExecutors;
import org.elasticsearch.injection.guice.Inject;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.core.security.action.role.GetRolesAction;
import org.elasticsearch.xpack.core.security.action.role.GetRolesRequest;
import org.elasticsearch.xpack.core.security.action.role.GetRolesResponse;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor.IndicesPrivileges;
import org.elasticsearch.xpack.core.security.authz.store.ReservedRolesStore;
import org.elasticsearch.xpack.security.authz.ReservedRoleNameChecker;
import org.elasticsearch.xpack.security.authz.store.CompositeRolesStore;
import org.elasticsearch.xpack.security.authz.store.NativeRolesStore;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class TransportGetRolesAction extends TransportAction<GetRolesRequest, GetRolesResponse> {

    private final NativeRolesStore nativeRolesStore;
    private final ReservedRoleNameChecker reservedRoleNameChecker;
    private final CompositeRolesStore compositeRolesStore;

    @Inject
    public TransportGetRolesAction(
        ActionFilters actionFilters,
        NativeRolesStore nativeRolesStore,
        ReservedRoleNameChecker reservedRoleNameChecker,
        CompositeRolesStore compositeRolesStore,
        TransportService transportService
    ) {
        super(GetRolesAction.NAME, actionFilters, transportService.getTaskManager(), EsExecutors.DIRECT_EXECUTOR_SERVICE);
        this.nativeRolesStore = nativeRolesStore;
        this.reservedRoleNameChecker = reservedRoleNameChecker;
        this.compositeRolesStore = compositeRolesStore;
    }

    @Override
    protected void doExecute(Task task, final GetRolesRequest request, final ActionListener<GetRolesResponse> listener) {
        final String[] requestedRoles = request.names();
        final boolean specificRolesRequested = requestedRoles != null && requestedRoles.length > 0;

        final ActionListener<GetRolesResponse> responseListener;
        if (request.includeImplicit()) {
            responseListener = listener.delegateFailureAndWrap(
                (delegate, response) -> addImplicitPrivilegesToResponse(response, delegate)
            );
        } else {
            responseListener = listener;
        }

        if (request.nativeOnly()) {
            final Set<String> rolesToSearchFor = specificRolesRequested
                ? Arrays.stream(requestedRoles).filter(r -> false == reservedRoleNameChecker.isReserved(r)).collect(Collectors.toSet())
                : Collections.emptySet();
            if (specificRolesRequested && rolesToSearchFor.isEmpty()) {
                // specific roles were requested, but they were all reserved, no need to hit the native store
                responseListener.onResponse(new GetRolesResponse());
            } else {
                getNativeRoles(rolesToSearchFor, responseListener);
            }
            return;
        }

        final Set<String> rolesToSearchFor = new LinkedHashSet<>();
        final Set<RoleDescriptor> reservedRoles = new LinkedHashSet<>();
        if (specificRolesRequested) {
            for (String role : requestedRoles) {
                if (reservedRoleNameChecker.isReserved(role)) {
                    RoleDescriptor rd = ReservedRolesStore.roleDescriptor(role);
                    if (rd != null) {
                        reservedRoles.add(rd);
                    }
                } else {
                    rolesToSearchFor.add(role);
                }
            }
        } else {
            reservedRoles.addAll(ReservedRolesStore.roleDescriptors());
        }

        if (specificRolesRequested && rolesToSearchFor.isEmpty()) {
            // specific roles were requested, but they were built in only, no need to hit the store
            responseListener.onResponse(new GetRolesResponse(reservedRoles.toArray(new RoleDescriptor[0])));
        } else {
            getNativeRoles(rolesToSearchFor, reservedRoles, responseListener);
        }
    }

    private void addImplicitPrivilegesToResponse(GetRolesResponse response, ActionListener<GetRolesResponse> listener) {
        RoleDescriptor[] roles = response.roles();
        if (roles.length == 0) {
            listener.onResponse(response);
            return;
        }
        compositeRolesStore.resolveImplicitPrivileges(Arrays.asList(roles), listener.delegateFailureAndWrap((delegate, implicitMap) -> {
            if (implicitMap.isEmpty()) {
                delegate.onResponse(response);
                return;
            }
            RoleDescriptor[] augmented = new RoleDescriptor[roles.length];
            for (int i = 0; i < roles.length; i++) {
                Collection<IndicesPrivileges> implicit = implicitMap.get(roles[i].getName());
                if (implicit == null || implicit.isEmpty()) {
                    augmented[i] = roles[i];
                } else {
                    augmented[i] = mergeImplicitPrivileges(roles[i], implicit);
                }
            }
            delegate.onResponse(new GetRolesResponse(augmented));
        }));
    }

    static RoleDescriptor mergeImplicitPrivileges(RoleDescriptor original, Collection<IndicesPrivileges> implicitPrivileges) {
        IndicesPrivileges[] implicitWithFlag = implicitPrivileges.stream()
            .map(
                p -> IndicesPrivileges.builder()
                    .indices(p.getIndices())
                    .privileges(p.getPrivileges())
                    .grantedFields(p.getGrantedFields())
                    .deniedFields(p.getDeniedFields())
                    .query(p.getQuery())
                    .allowRestrictedIndices(p.allowRestrictedIndices())
                    .implicitlyGranted(true)
                    .build()
            )
            .toArray(IndicesPrivileges[]::new);

        IndicesPrivileges[] merged = Stream.concat(Stream.of(original.getIndicesPrivileges()), Stream.of(implicitWithFlag))
            .toArray(IndicesPrivileges[]::new);

        return new RoleDescriptor(
            original.getName(),
            original.getClusterPrivileges(),
            merged,
            original.getApplicationPrivileges(),
            original.getConditionalClusterPrivileges(),
            original.getRunAs(),
            original.getMetadata(),
            original.getTransientMetadata(),
            original.getRemoteIndicesPrivileges(),
            original.getRemoteClusterPermissions(),
            original.getRestriction(),
            original.getDescription()
        );
    }

    private void getNativeRoles(Set<String> rolesToSearchFor, ActionListener<GetRolesResponse> listener) {
        getNativeRoles(rolesToSearchFor, new LinkedHashSet<>(), listener);
    }

    private void getNativeRoles(Set<String> rolesToSearchFor, Set<RoleDescriptor> foundRoles, ActionListener<GetRolesResponse> listener) {
        nativeRolesStore.getRoleDescriptors(rolesToSearchFor, ActionListener.wrap((retrievalResult) -> {
            if (retrievalResult.isSuccess()) {
                foundRoles.addAll(retrievalResult.getDescriptors());
                listener.onResponse(new GetRolesResponse(foundRoles.toArray(new RoleDescriptor[0])));
            } else {
                listener.onFailure(retrievalResult.getFailure());
            }
        }, listener::onFailure));
    }
}
