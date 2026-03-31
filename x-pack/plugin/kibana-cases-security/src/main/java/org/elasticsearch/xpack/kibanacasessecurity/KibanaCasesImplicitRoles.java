/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.kibanacasessecurity;

import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.store.ImplicitPrivilegesProvider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Implicitly grants read access to Cases analytics indices based on Kibana application privileges.
 * <p>
 * Cases analytics indices encode the space and solution in the index name
 * (e.g. {@code .internal.cases.default-securitysolution}). Both dimensions are extracted from
 * the role's resources using {@code space:} and {@code solution:} prefixes:
 * <ul>
 *   <li>{@code space:default} + {@code solution:securitySolution}
 *       → {@code .internal.cases*.default-securitysolution}</li>
 *   <li>{@code space:default} (no solution) → {@code .internal.cases*.default-*}</li>
 *   <li>{@code *} → {@code .internal.cases*}</li>
 * </ul>
 */
public class KibanaCasesImplicitRoles implements ImplicitPrivilegesProvider {

    static final String KIBANA_APPLICATION = "kibana-.kibana";
    static final String SPACE_PREFIX = "space:";
    static final String SOLUTION_PREFIX = "solution:";
    static final String ALL_RESOURCES = "*";
    static final String CASES_ACTION = "cases:read";

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

        Set<String> spaces = new HashSet<>();
        Set<String> solutions = new HashSet<>();
        boolean allResources = false;

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
                if (hasMatchingPrivilege == false) {
                    continue;
                }

                for (String resource : appPriv.getResources()) {
                    if (ALL_RESOURCES.equals(resource)) {
                        allResources = true;
                    } else if (resource.startsWith(SPACE_PREFIX)) {
                        spaces.add(resource.substring(SPACE_PREFIX.length()));
                    } else if (resource.startsWith(SOLUTION_PREFIX)) {
                        solutions.add(resource.substring(SOLUTION_PREFIX.length()).toLowerCase(Locale.ROOT));
                    }
                }
            }
        }

        String[] patterns = buildIndexPatterns(spaces, solutions, allResources);
        if (patterns.length == 0) {
            return List.of();
        }

        return List.of(RoleDescriptor.IndicesPrivileges.builder().indices(patterns).privileges("read").build());
    }

    static String[] buildIndexPatterns(Set<String> spaces, Set<String> solutions, boolean allResources) {
        if (allResources) {
            return new String[] { ".internal.cases*" };
        }
        if (spaces.isEmpty()) {
            return new String[0];
        }
        if (solutions.isEmpty()) {
            return spaces.stream().map(s -> ".internal.cases*." + s + "-*").toArray(String[]::new);
        }
        List<String> patterns = new ArrayList<>();
        for (String space : spaces) {
            for (String solution : solutions) {
                patterns.add(".internal.cases*." + space + "-" + solution);
            }
        }
        return patterns.toArray(String[]::new);
    }
}
