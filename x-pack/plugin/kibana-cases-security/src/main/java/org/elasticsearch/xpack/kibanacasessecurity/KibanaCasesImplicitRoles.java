/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.kibanacasessecurity;

import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.store.ImplicitRoleDescriptorContributor;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Implicitly grants index privileges to users whose roles include Kibana application privileges
 * with the {@code cases:read} action.
 * <p>
 * Cases analytics indices encode the space in the index name (e.g.
 * {@code .internal.cases.teamred-securitysolution}), so access control is achieved via
 * space-scoped index patterns rather than DLS. For a user with access to space "default",
 * this contributor grants read on {@code .internal.cases*.default-*}. For the wildcard
 * resource ({@code *}), it grants read on {@code .internal.cases*}.
 */
public class KibanaCasesImplicitRoles implements ImplicitRoleDescriptorContributor {

    static final String KIBANA_APPLICATION = "kibana-.kibana";
    static final String RESOURCE_PREFIX = "space:";
    static final String ALL_RESOURCES = "*";

    static final String CASES_ACTION = "cases:read";

    /** Matches all cases analytics indices across all spaces and solutions. */
    static final String ALL_CASES_PATTERN = ".internal.cases*";

    @Override
    public Collection<RoleDescriptor.IndicesPrivileges> getImplicitIndicesPrivileges(
        Collection<RoleDescriptor> roleDescriptors,
        Collection<ApplicationPrivilegeDescriptor> storedApplicationPrivileges
    ) {
        Set<String> matchingPrivilegeNames = storedApplicationPrivileges.stream()
            .filter(d -> KIBANA_APPLICATION.equals(d.getApplication()))
            .filter(d -> d.getActions().contains(CASES_ACTION))
            .map(ApplicationPrivilegeDescriptor::getName)
            .collect(Collectors.toSet());

        if (matchingPrivilegeNames.isEmpty()) {
            return List.of();
        }

        Set<String> spaceIds = new HashSet<>();
        boolean allSpaces = false;

        for (RoleDescriptor descriptor : roleDescriptors) {
            for (RoleDescriptor.ApplicationResourcePrivileges appPriv : descriptor.getApplicationPrivileges()) {
                if (KIBANA_APPLICATION.equals(appPriv.getApplication()) == false) {
                    continue;
                }

                boolean hasMatchingPrivilege = false;
                for (String privName : appPriv.getPrivileges()) {
                    if (matchingPrivilegeNames.contains(privName)) {
                        hasMatchingPrivilege = true;
                        break;
                    }
                }

                if (hasMatchingPrivilege) {
                    for (String resource : appPriv.getResources()) {
                        if (ALL_RESOURCES.equals(resource)) {
                            allSpaces = true;
                        } else if (resource.startsWith(RESOURCE_PREFIX)) {
                            spaceIds.add(resource.substring(RESOURCE_PREFIX.length()));
                        }
                    }
                }
            }
        }

        if (allSpaces == false && spaceIds.isEmpty()) {
            return List.of();
        }

        String[] indexPatterns;
        if (allSpaces) {
            indexPatterns = new String[] { ALL_CASES_PATTERN };
        } else {
            indexPatterns = buildSpaceIndexPatterns(spaceIds);
        }

        List<RoleDescriptor.IndicesPrivileges> result = new ArrayList<>(1);
        result.add(RoleDescriptor.IndicesPrivileges.builder().indices(indexPatterns).privileges("read").build());
        return result;
    }

    /**
     * Builds index patterns that scope access to the given spaces. Each space produces a pattern
     * like {@code .internal.cases*.{spaceId}-*} which matches all cases index types
     * (cases, cases-attachments, cases-comments, cases-activity) for that space.
     */
    static String[] buildSpaceIndexPatterns(Set<String> spaceIds) {
        return spaceIds.stream().map(space -> ".internal.cases*." + space + "-*").toArray(String[]::new);
    }
}
