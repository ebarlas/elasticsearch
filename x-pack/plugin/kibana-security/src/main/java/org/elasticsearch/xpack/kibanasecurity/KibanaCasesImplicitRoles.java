/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.kibanasecurity;

import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.store.ImplicitPrivilegesProvider;

import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
    static final String CASES_ACTION = "cases:read";
    static final String CASES_INDEX_PREFIX = ".internal.cases*";
    static final String SPACE_PREFIX = "space:";
    static final String SOLUTION_PREFIX = "solution:";
    static final String ALL_RESOURCES = "*";
    static final String INDEX_READ_PRIVILEGE = "read";

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

        Set<String> resources = roleDescriptors.stream()
            .flatMap(rd -> Stream.of(rd.getApplicationPrivileges()))
            .filter(p -> KIBANA_APPLICATION.equals(p.getApplication()))
            .filter(p -> Stream.of(p.getPrivileges()).anyMatch(matchingPrivilegeNames::contains))
            .flatMap(p -> Stream.of(p.getResources()))
            .collect(Collectors.toSet());
        if (resources.isEmpty()) {
            return List.of();
        }
        if (resources.contains(ALL_RESOURCES)) {
            return List.of(RoleDescriptor.IndicesPrivileges.builder().indices(CASES_INDEX_PREFIX).privileges(INDEX_READ_PRIVILEGE).build());
        }

        String[] patterns = buildIndexPatterns(resources);
        if (patterns.length == 0) {
            return List.of();
        }

        return List.of(RoleDescriptor.IndicesPrivileges.builder().indices(patterns).privileges(INDEX_READ_PRIVILEGE).build());
    }

    static String[] buildIndexPatterns(Set<String> resources) {
        Set<String> spaces = resources.stream()
            .filter(r -> r.startsWith(SPACE_PREFIX))
            .map(r -> r.substring(SPACE_PREFIX.length()))
            .collect(Collectors.toSet());
        if (spaces.isEmpty()) {
            return new String[0];
        }

        Set<String> solutions = resources.stream()
            .filter(r -> r.startsWith(SOLUTION_PREFIX))
            .map(r -> r.substring(SOLUTION_PREFIX.length()).toLowerCase(Locale.ROOT))
            .collect(Collectors.toSet());
        if (solutions.isEmpty()) {
            return spaces.stream().map(s -> CASES_INDEX_PREFIX + "." + s + "-*").toArray(String[]::new);
        }

        return spaces.stream()
            .flatMap(space -> solutions.stream().map(solution -> CASES_INDEX_PREFIX + "." + space + "-" + solution))
            .toArray(String[]::new);
    }
}
