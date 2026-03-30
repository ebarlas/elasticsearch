/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.kibanacasessecurity;

import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

public class KibanaCasesImplicitRolesTests extends ESTestCase {

    private final KibanaCasesImplicitRoles contributor = new KibanaCasesImplicitRoles();

    public void testSingleSpaceGrantsSpaceScopedIndexPattern() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "feature_cases_read", Set.of("cases:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("feature_cases_read", "space:default"));

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, storedPrivileges);

        assertThat(result, hasSize(1));
        RoleDescriptor.IndicesPrivileges privilege = result.iterator().next();
        assertThat(privilege.getIndices(), arrayContaining(".internal.cases*.default-*"));
        assertThat(privilege.getPrivileges(), arrayContaining("read"));
        assertThat(privilege.getQuery(), is(nullValue()));
    }

    public void testMultipleSpacesAcrossRolesAreMerged() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "cases_read", Set.of("cases:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "role_1",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("cases_read")
                        .resources("space:foo", "space:bar")
                        .build() },
                null,
                null,
                null,
                null
            ),
            new RoleDescriptor(
                "role_2",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("cases_read")
                        .resources("space:baz")
                        .build() },
                null,
                null,
                null,
                null
            )
        );

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, storedPrivileges);

        assertThat(result, hasSize(1));
        RoleDescriptor.IndicesPrivileges privilege = result.iterator().next();
        assertThat(
            privilege.getIndices(),
            arrayContainingInAnyOrder(".internal.cases*.foo-*", ".internal.cases*.bar-*", ".internal.cases*.baz-*")
        );
        assertThat(privilege.getQuery(), is(nullValue()));
    }

    public void testWildcardResourceGrantsAllCasesPattern() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "cases_read", Set.of("cases:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("cases_read", "*"));

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, storedPrivileges);

        assertThat(result, hasSize(1));
        RoleDescriptor.IndicesPrivileges privilege = result.iterator().next();
        assertThat(privilege.getIndices(), arrayContaining(".internal.cases*"));
        assertThat(privilege.getQuery(), is(nullValue()));
    }

    public void testWildcardTakesPrecedenceOverSpecificSpaces() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "cases_read", Set.of("cases:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "role_1",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("cases_read")
                        .resources("*")
                        .build() },
                null,
                null,
                null,
                null
            ),
            new RoleDescriptor(
                "role_2",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("cases_read")
                        .resources("space:foo")
                        .build() },
                null,
                null,
                null,
                null
            )
        );

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, storedPrivileges);

        assertThat(result, hasSize(1));
        RoleDescriptor.IndicesPrivileges privilege = result.iterator().next();
        assertThat(privilege.getIndices(), arrayContaining(".internal.cases*"));
    }

    public void testNonMatchingApplicationReturnsEmpty() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("other-app", "cases_read", Set.of("cases:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "test_role",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("other-app")
                        .privileges("cases_read")
                        .resources("space:default")
                        .build() },
                null,
                null,
                null,
                null
            )
        );

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, storedPrivileges);

        assertThat(result, is(empty()));
    }

    public void testNonMatchingActionReturnsEmpty() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "cases_write", Set.of("cases:write"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("cases_write", "space:default"));

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, storedPrivileges);

        assertThat(result, is(empty()));
    }

    public void testResourcesWithoutSpacePrefixAreIgnored() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "cases_read", Set.of("cases:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("cases_read", "no-prefix-resource"));

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, storedPrivileges);

        assertThat(result, is(empty()));
    }

    public void testEmptyRoleDescriptorsReturnsEmpty() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "cases_read", Set.of("cases:read"), Map.of())
        );

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(List.of(), storedPrivileges);

        assertThat(result, is(empty()));
    }

    public void testEmptyStoredPrivilegesReturnsEmpty() {
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("cases_read", "space:default"));

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, List.of());

        assertThat(result, is(empty()));
    }

    public void testPrivilegeWithMultipleActionsIncludingCasesRead() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor(
                "kibana-.kibana",
                "feature_all",
                Set.of("cases:read", "cases:write", "alerts:read"),
                Map.of()
            )
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("feature_all", "space:marketing"));

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, storedPrivileges);

        assertThat(result, hasSize(1));
        RoleDescriptor.IndicesPrivileges privilege = result.iterator().next();
        assertThat(privilege.getIndices(), arrayContaining(".internal.cases*.marketing-*"));
    }

    public void testBuildSpaceIndexPatterns() {
        String[] patterns = KibanaCasesImplicitRoles.buildSpaceIndexPatterns(Set.of("default"));
        assertThat(patterns, arrayContaining(".internal.cases*.default-*"));
    }

    public void testBuildSpaceIndexPatternsMultipleSpaces() {
        String[] patterns = KibanaCasesImplicitRoles.buildSpaceIndexPatterns(Set.of("foo", "bar"));
        Arrays.sort(patterns);
        assertThat(patterns, arrayContaining(".internal.cases*.bar-*", ".internal.cases*.foo-*"));
    }

    public void testNoDlsIsUsed() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "cases_read", Set.of("cases:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("cases_read", "space:default"));

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, storedPrivileges);

        assertThat(result, hasSize(1));
        RoleDescriptor.IndicesPrivileges privilege = result.iterator().next();
        assertThat(privilege.getQuery(), is(nullValue()));
        assertThat(privilege.getGrantedFields(), is(nullValue()));
        assertThat(privilege.getDeniedFields(), is(nullValue()));
        assertFalse(privilege.isUsingFieldLevelSecurity());
    }

    private static RoleDescriptor roleWithAppPrivilege(String privilegeName, String... resources) {
        return new RoleDescriptor(
            "test_role",
            null,
            null,
            new RoleDescriptor.ApplicationResourcePrivileges[] {
                RoleDescriptor.ApplicationResourcePrivileges.builder()
                    .application("kibana-.kibana")
                    .privileges(privilegeName)
                    .resources(resources)
                    .build() },
            null,
            null,
            null,
            null
        );
    }
}
