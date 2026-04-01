/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.kibanasecurity;

import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;

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

    private static final List<ApplicationPrivilegeDescriptor> STORED_PRIVILEGES = List.of(
        new ApplicationPrivilegeDescriptor("kibana-.kibana", "feature_cases_read", Set.of("cases:read"), Map.of())
    );

    // -- buildIndexPatterns --

    public void testBuildPatternsSpaceOnly() {
        assertThat(
            KibanaCasesImplicitRoles.buildIndexPatterns(Set.of("space:default")),
            arrayContaining(".internal.cases*.default-*")
        );
    }

    public void testBuildPatternsSpaceAndSolution() {
        assertThat(
            KibanaCasesImplicitRoles.buildIndexPatterns(Set.of("space:default", "solution:securitysolution")),
            arrayContaining(".internal.cases*.default-securitysolution")
        );
    }

    public void testBuildPatternsCrossProduct() {
        assertThat(
            KibanaCasesImplicitRoles.buildIndexPatterns(Set.of("space:foo", "space:bar", "solution:securitysolution")),
            arrayContainingInAnyOrder(".internal.cases*.foo-securitysolution", ".internal.cases*.bar-securitysolution")
        );
    }

    public void testBuildPatternsNoSpacesReturnsEmpty() {
        assertThat(KibanaCasesImplicitRoles.buildIndexPatterns(Set.of("solution:securitysolution")).length, is(0));
    }

    // -- integration via getImplicitIndicesPrivileges --

    public void testSpaceAndSolution() {
        var result = contributor.getImplicitIndicesPrivileges(
            List.of(roleWithResources("feature_cases_read", "space:default", "solution:securitySolution")),
            STORED_PRIVILEGES
        );

        assertThat(result, hasSize(1));
        var priv = result.iterator().next();
        assertThat(priv.getIndices(), arrayContaining(".internal.cases*.default-securitysolution"));
        assertThat(priv.getPrivileges(), arrayContaining("read"));
        assertThat(priv.getQuery(), is(nullValue()));
    }

    public void testSpaceOnlyGrantsAllSolutions() {
        var result = contributor.getImplicitIndicesPrivileges(
            List.of(roleWithResources("feature_cases_read", "space:default")),
            STORED_PRIVILEGES
        );

        assertThat(result, hasSize(1));
        assertThat(result.iterator().next().getIndices(), arrayContaining(".internal.cases*.default-*"));
    }

    public void testWildcardGrantsEverything() {
        var result = contributor.getImplicitIndicesPrivileges(
            List.of(roleWithResources("feature_cases_read", "*")),
            STORED_PRIVILEGES
        );

        assertThat(result, hasSize(1));
        assertThat(result.iterator().next().getIndices(), arrayContaining(".internal.cases*"));
    }

    public void testMultipleSpacesAndSolutions() {
        var result = contributor.getImplicitIndicesPrivileges(
            List.of(roleWithResources("feature_cases_read", "space:foo", "space:bar", "solution:securitySolution", "solution:observability")),
            STORED_PRIVILEGES
        );

        assertThat(result, hasSize(1));
        assertThat(
            result.iterator().next().getIndices(),
            arrayContainingInAnyOrder(
                ".internal.cases*.foo-securitysolution",
                ".internal.cases*.foo-observability",
                ".internal.cases*.bar-securitysolution",
                ".internal.cases*.bar-observability"
            )
        );
    }

    public void testSpacesMergedAcrossRoles() {
        var result = contributor.getImplicitIndicesPrivileges(
            List.of(
                roleWithResources("feature_cases_read", "space:foo", "solution:securitySolution"),
                roleWithResources("feature_cases_read", "space:bar", "solution:securitySolution")
            ),
            STORED_PRIVILEGES
        );

        assertThat(result, hasSize(1));
        assertThat(
            result.iterator().next().getIndices(),
            arrayContainingInAnyOrder(".internal.cases*.foo-securitysolution", ".internal.cases*.bar-securitysolution")
        );
    }

    public void testSolutionLowercased() {
        var result = contributor.getImplicitIndicesPrivileges(
            List.of(roleWithResources("feature_cases_read", "space:default", "solution:SecuritySolution")),
            STORED_PRIVILEGES
        );

        assertThat(result, hasSize(1));
        assertThat(result.iterator().next().getIndices(), arrayContaining(".internal.cases*.default-securitysolution"));
    }

    public void testNonMatchingApplicationReturnsEmpty() {
        var stored = List.of(
            new ApplicationPrivilegeDescriptor("other-app", "cases_read", Set.of("cases:read"), Map.of())
        );
        var result = contributor.getImplicitIndicesPrivileges(
            List.of(new RoleDescriptor("r", null, null, new RoleDescriptor.ApplicationResourcePrivileges[] {
                RoleDescriptor.ApplicationResourcePrivileges.builder()
                    .application("other-app")
                    .privileges("cases_read")
                    .resources("space:default")
                    .build() }, null, null, null, null)),
            stored
        );
        assertThat(result, is(empty()));
    }

    public void testNonMatchingActionReturnsEmpty() {
        var stored = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "cases_write", Set.of("cases:write"), Map.of())
        );
        assertThat(
            contributor.getImplicitIndicesPrivileges(List.of(roleWithResources("cases_write", "space:default")), stored),
            is(empty())
        );
    }

    public void testEmptyRoleDescriptorsReturnsEmpty() {
        assertThat(contributor.getImplicitIndicesPrivileges(List.of(), STORED_PRIVILEGES), is(empty()));
    }

    public void testEmptyStoredPrivilegesReturnsEmpty() {
        assertThat(
            contributor.getImplicitIndicesPrivileges(List.of(roleWithResources("feature_cases_read", "space:default")), List.of()),
            is(empty())
        );
    }

    public void testResourcesWithoutPrefixAreIgnored() {
        assertThat(
            contributor.getImplicitIndicesPrivileges(
                List.of(roleWithResources("feature_cases_read", "no-prefix")),
                STORED_PRIVILEGES
            ),
            is(empty())
        );
    }

    public void testNoDlsOrFls() {
        var result = contributor.getImplicitIndicesPrivileges(
            List.of(roleWithResources("feature_cases_read", "space:default", "solution:securitySolution")),
            STORED_PRIVILEGES
        );
        assertThat(result, hasSize(1));
        var priv = result.iterator().next();
        assertThat(priv.getQuery(), is(nullValue()));
        assertThat(priv.getGrantedFields(), is(nullValue()));
        assertThat(priv.getDeniedFields(), is(nullValue()));
    }

    private static RoleDescriptor roleWithResources(String privilegeName, String... resources) {
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
