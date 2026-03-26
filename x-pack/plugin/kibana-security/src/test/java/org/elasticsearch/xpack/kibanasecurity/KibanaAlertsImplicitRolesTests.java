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

import org.elasticsearch.xpack.kibanasecurity.KibanaAlertsImplicitRoles.ImplicitResourceConfig;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.arrayContainingInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

public class KibanaAlertsImplicitRolesTests extends ESTestCase {

    private final KibanaAlertsImplicitRoles contributor = new KibanaAlertsImplicitRoles();

    public void testSingleSpaceGrantsDlsQuery() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "feature_alerting_read", Set.of("alerts:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "test_role",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("feature_alerting_read")
                        .resources("space:default")
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
        assertThat(privilege.getIndices(), arrayContaining(".alerts-*"));
        assertThat(privilege.getPrivileges(), arrayContaining("read"));
        assertThat(privilege.getQuery(), is(notNullValue()));
        String query = privilege.getQuery().utf8ToString();
        assertTrue(query.contains("kibana.space_ids"));
        assertTrue(query.contains("default"));
    }

    public void testMultipleSpacesAcrossRolesAreMerged() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "alerting_read", Set.of("alerts:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "role_1",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("alerting_read")
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
                        .privileges("alerting_read")
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
        String query = privilege.getQuery().utf8ToString();
        assertTrue(query.contains("kibana.space_ids"));
        assertTrue(query.contains("foo"));
        assertTrue(query.contains("bar"));
        assertTrue(query.contains("baz"));
    }

    public void testWildcardResourceGrantsFullAccessWithoutDls() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "alerting_read", Set.of("alerts:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "test_role",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("alerting_read")
                        .resources("*")
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
        assertThat(privilege.getIndices(), arrayContaining(".alerts-*"));
        assertThat(privilege.getPrivileges(), arrayContaining("read"));
        assertThat(privilege.getQuery(), is(nullValue()));
    }

    public void testWildcardTakesPrecedenceOverSpecificSpaces() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "alerting_read", Set.of("alerts:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "role_1",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("alerting_read")
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
                        .privileges("alerting_read")
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
        assertThat(result.iterator().next().getQuery(), is(nullValue()));
    }

    public void testNonMatchingApplicationReturnsEmpty() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("other-app", "alerting_read", Set.of("alerts:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "test_role",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("other-app")
                        .privileges("alerting_read")
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
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "alerting_write", Set.of("alerts:write"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "test_role",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("alerting_write")
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

    public void testResourcesWithoutSpacePrefixAreIgnored() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "alerting_read", Set.of("alerts:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "test_role",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("alerting_read")
                        .resources("no-prefix-resource")
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

    public void testEmptyRoleDescriptorsReturnsEmpty() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "alerting_read", Set.of("alerts:read"), Map.of())
        );

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(List.of(), storedPrivileges);

        assertThat(result, is(empty()));
    }

    public void testEmptyStoredPrivilegesReturnsEmpty() {
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "test_role",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("alerting_read")
                        .resources("space:default")
                        .build() },
                null,
                null,
                null,
                null
            )
        );

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, List.of());

        assertThat(result, is(empty()));
    }

    public void testPrivilegeWithMultipleActionsIncludingAlertsRead() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor(
                "kibana-.kibana",
                "feature_all",
                Set.of("alerts:read", "alerts:write", "rules:read"),
                Map.of()
            )
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(
            new RoleDescriptor(
                "test_role",
                null,
                null,
                new RoleDescriptor.ApplicationResourcePrivileges[] {
                    RoleDescriptor.ApplicationResourcePrivileges.builder()
                        .application("kibana-.kibana")
                        .privileges("feature_all")
                        .resources("space:marketing")
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
        String query = privilege.getQuery().utf8ToString();
        assertTrue(query.contains("marketing"));
    }

    public void testBuildSpaceIdsDlsQuery() {
        String query = KibanaAlertsImplicitRoles.buildSpaceIdsDlsQuery(Set.of("default"));
        assertTrue(query.contains("terms"));
        assertTrue(query.contains("kibana.space_ids"));
        assertTrue(query.contains("default"));
    }

    public void testAlertsConfigHasNoFieldLevelSecurity() {
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "alerting_read", Set.of("alerts:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("alerting_read", "space:default"));

        Collection<RoleDescriptor.IndicesPrivileges> result = contributor.getImplicitIndicesPrivileges(roleDescriptors, storedPrivileges);

        assertThat(result, hasSize(1));
        RoleDescriptor.IndicesPrivileges privilege = result.iterator().next();
        assertThat(privilege.getGrantedFields(), is(nullValue()));
        assertThat(privilege.getDeniedFields(), is(nullValue()));
        assertFalse(privilege.isUsingFieldLevelSecurity());
    }

    public void testConfigWithDeniedFieldsSetsFieldLevelSecurity() {
        ImplicitResourceConfig config = new ImplicitResourceConfig(
            "rules:read",
            ".kibana-alerting-rules-*",
            new String[] { "*" },
            new String[] { "encrypted_credentials", "config.secrets" }
        );
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "rules_read", Set.of("rules:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("rules_read", "space:default"));

        RoleDescriptor.IndicesPrivileges privilege = KibanaAlertsImplicitRoles.buildPrivilegeForConfig(
            config,
            roleDescriptors,
            storedPrivileges
        );

        assertThat(privilege, is(notNullValue()));
        assertThat(privilege.getIndices(), arrayContaining(".kibana-alerting-rules-*"));
        assertThat(privilege.getGrantedFields(), arrayContaining("*"));
        assertThat(privilege.getDeniedFields(), arrayContainingInAnyOrder("encrypted_credentials", "config.secrets"));
        assertTrue(privilege.isUsingFieldLevelSecurity());
        String query = privilege.getQuery().utf8ToString();
        assertTrue(query.contains("default"));
    }

    public void testConfigWithDeniedFieldsAndWildcardResourceHasNoQuery() {
        ImplicitResourceConfig config = new ImplicitResourceConfig(
            "rules:read",
            ".kibana-alerting-rules-*",
            new String[] { "*" },
            new String[] { "encrypted_credentials" }
        );
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "rules_read", Set.of("rules:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("rules_read", "*"));

        RoleDescriptor.IndicesPrivileges privilege = KibanaAlertsImplicitRoles.buildPrivilegeForConfig(
            config,
            roleDescriptors,
            storedPrivileges
        );

        assertThat(privilege, is(notNullValue()));
        assertThat(privilege.getQuery(), is(nullValue()));
        assertThat(privilege.getDeniedFields(), arrayContaining("encrypted_credentials"));
    }

    public void testConfigWithNoMatchingActionReturnsNull() {
        ImplicitResourceConfig config = new ImplicitResourceConfig("rules:read", ".kibana-alerting-rules-*", null, null);
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "alerting_read", Set.of("alerts:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("alerting_read", "space:default"));

        RoleDescriptor.IndicesPrivileges privilege = KibanaAlertsImplicitRoles.buildPrivilegeForConfig(
            config,
            roleDescriptors,
            storedPrivileges
        );

        assertThat(privilege, is(nullValue()));
    }

    public void testMultipleConfigsProduceMultiplePrivileges() {
        ImplicitResourceConfig alertsConfig = new ImplicitResourceConfig("alerts:read", ".alerts-*", null, null);
        ImplicitResourceConfig rulesConfig = new ImplicitResourceConfig(
            "rules:read",
            ".kibana-alerting-rules-*",
            new String[] { "*" },
            new String[] { "encrypted_credentials" }
        );
        Collection<ApplicationPrivilegeDescriptor> storedPrivileges = List.of(
            new ApplicationPrivilegeDescriptor("kibana-.kibana", "feature_all", Set.of("alerts:read", "rules:read"), Map.of())
        );
        Collection<RoleDescriptor> roleDescriptors = List.of(roleWithAppPrivilege("feature_all", "space:marketing"));

        RoleDescriptor.IndicesPrivileges alertsPrivilege = KibanaAlertsImplicitRoles.buildPrivilegeForConfig(
            alertsConfig,
            roleDescriptors,
            storedPrivileges
        );
        RoleDescriptor.IndicesPrivileges rulesPrivilege = KibanaAlertsImplicitRoles.buildPrivilegeForConfig(
            rulesConfig,
            roleDescriptors,
            storedPrivileges
        );

        assertThat(alertsPrivilege, is(notNullValue()));
        assertThat(alertsPrivilege.getIndices(), arrayContaining(".alerts-*"));
        assertThat(alertsPrivilege.getGrantedFields(), is(nullValue()));
        assertThat(alertsPrivilege.getDeniedFields(), is(nullValue()));

        assertThat(rulesPrivilege, is(notNullValue()));
        assertThat(rulesPrivilege.getIndices(), arrayContaining(".kibana-alerting-rules-*"));
        assertThat(rulesPrivilege.getDeniedFields(), arrayContaining("encrypted_credentials"));

        String alertsQuery = alertsPrivilege.getQuery().utf8ToString();
        String rulesQuery = rulesPrivilege.getQuery().utf8ToString();
        assertTrue(alertsQuery.contains("marketing"));
        assertTrue(rulesQuery.contains("marketing"));
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
