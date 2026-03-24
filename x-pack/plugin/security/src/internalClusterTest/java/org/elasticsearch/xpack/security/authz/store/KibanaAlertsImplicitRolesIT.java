/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.store;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.test.SecuritySingleNodeTestCase;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesAction;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesRequest;
import org.elasticsearch.xpack.core.security.action.role.GetRolesRequestBuilder;
import org.elasticsearch.xpack.core.security.action.role.GetRolesResponse;
import org.elasticsearch.xpack.core.security.action.role.PutRoleRequestBuilder;
import org.elasticsearch.xpack.core.security.action.user.PutUserRequestBuilder;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.junit.Before;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Collections.emptyMap;
import static org.elasticsearch.test.SecuritySettingsSourceField.TEST_PASSWORD_SECURE_STRING;
import static org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken.basicAuthHeaderValue;
import static org.hamcrest.Matchers.equalTo;

/**
 * Integration test verifying that the implicit roles mechanism grants read access to {@code .alerts-*}
 * indices (with DLS filtering by space) when a user has {@code kibana-.kibana} application privileges
 * with the {@code alerts:read} action.
 */
public class KibanaAlertsImplicitRolesIT extends SecuritySingleNodeTestCase {

    private static final String ALERTS_INDEX = ".alerts-test";
    private static final String ALERTS_USER = "alerts_user";
    private static final String ALERTS_ROLE = "alerts_role";

    @Before
    public void setupTestData() throws Exception {
        final Client adminClient = client();

        final PutPrivilegesRequest putPrivilegesRequest = new PutPrivilegesRequest();
        putPrivilegesRequest.setPrivileges(
            java.util.List.of(
                new ApplicationPrivilegeDescriptor("kibana-.kibana", "feature_alerting_read", Set.of("alerts:read"), emptyMap())
            )
        );
        adminClient.execute(PutPrivilegesAction.INSTANCE, putPrivilegesRequest).actionGet();

        new PutRoleRequestBuilder(adminClient).source(ALERTS_ROLE, new BytesArray("""
            {
              "applications": [
                {
                  "application": "kibana-.kibana",
                  "privileges": ["feature_alerting_read"],
                  "resources": ["space:default"]
                }
              ]
            }
            """), XContentType.JSON).get();

        new PutUserRequestBuilder(adminClient).username(ALERTS_USER)
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles(ALERTS_ROLE)
            .get();

        indicesAdmin().prepareDelete(ALERTS_INDEX)
            .setIndicesOptions(org.elasticsearch.action.support.IndicesOptions.lenientExpandOpen())
            .get();
        indicesAdmin().prepareCreate(ALERTS_INDEX).get();

        adminClient.prepareIndex(ALERTS_INDEX)
            .setId("alert-default-1")
            .setSource(Map.of("kibana.space_ids", java.util.List.of("default"), "message", "alert in default space"))
            .get();

        adminClient.prepareIndex(ALERTS_INDEX)
            .setId("alert-marketing-1")
            .setSource(Map.of("kibana.space_ids", java.util.List.of("marketing"), "message", "alert in marketing space"))
            .get();

        adminClient.prepareIndex(ALERTS_INDEX)
            .setId("alert-both-1")
            .setSource(
                Map.of("kibana.space_ids", java.util.List.of("default", "marketing"), "message", "alert in both default and marketing")
            )
            .get();

        adminClient.prepareIndex(ALERTS_INDEX)
            .setId("alert-sales-1")
            .setSource(Map.of("kibana.space_ids", java.util.List.of("sales"), "message", "alert in sales space"))
            .get();

        indicesAdmin().prepareRefresh(ALERTS_INDEX).get();
        ensureGreen(ALERTS_INDEX);
    }

    public void testUserCanSearchAlertsWithDlsFiltering() {
        Client alertsUserClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue(ALERTS_USER, new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );

        SearchResponse response = alertsUserClient.prepareSearch(ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(response.getFailedShards(), equalTo(0));

            Set<String> returnedIds = Arrays.stream(response.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());

            assertThat(
                "User with space:default should see alerts in default space and both spaces, but not marketing-only",
                returnedIds,
                equalTo(Set.of("alert-default-1", "alert-both-1"))
            );

            assertThat(response.getHits().getTotalHits().value(), equalTo(2L));
        } finally {
            response.decRef();
        }
    }

    public void testUserWithoutAlertsPrivilegeCannotSearchAlerts() throws Exception {
        new PutRoleRequestBuilder(client()).source("no_alerts_role", new BytesArray("""
            {
              "applications": [
                {
                  "application": "kibana-.kibana",
                  "privileges": ["feature_alerting_read"],
                  "resources": ["space:marketing"]
                }
              ]
            }
            """), XContentType.JSON).get();

        new PutUserRequestBuilder(client()).username("marketing_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("no_alerts_role")
            .get();

        Client marketingClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue("marketing_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );

        SearchResponse response = marketingClient.prepareSearch(ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(response.getFailedShards(), equalTo(0));

            Set<String> returnedIds = Arrays.stream(response.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());

            assertThat(
                "User with space:marketing should see only marketing and both-space alerts",
                returnedIds,
                equalTo(Set.of("alert-marketing-1", "alert-both-1"))
            );
        } finally {
            response.decRef();
        }
    }

    public void testUserWithWildcardResourceSeesAllAlerts() throws Exception {
        new PutRoleRequestBuilder(client()).source("all_spaces_role", new BytesArray("""
            {
              "applications": [
                {
                  "application": "kibana-.kibana",
                  "privileges": ["feature_alerting_read"],
                  "resources": ["*"]
                }
              ]
            }
            """), XContentType.JSON).get();

        new PutUserRequestBuilder(client()).username("all_spaces_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("all_spaces_role")
            .get();

        Client allSpacesClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue("all_spaces_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );

        SearchResponse response = allSpacesClient.prepareSearch(ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(response.getFailedShards(), equalTo(0));

            Set<String> returnedIds = Arrays.stream(response.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());

            assertThat(
                "User with wildcard resource should see all alerts",
                returnedIds,
                equalTo(Set.of("alert-default-1", "alert-marketing-1", "alert-both-1", "alert-sales-1"))
            );
        } finally {
            response.decRef();
        }
    }

    public void testUserWithNoMatchingPrivilegeIsDenied() throws Exception {
        new PutRoleRequestBuilder(client()).source("no_alerts_priv_role", new BytesArray("""
            {
              "cluster": [],
              "indices": []
            }
            """), XContentType.JSON).get();

        new PutUserRequestBuilder(client()).username("no_priv_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("no_alerts_priv_role")
            .get();

        Client noPrivClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue("no_priv_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );

        expectThrows(ElasticsearchSecurityException.class, () -> noPrivClient.prepareSearch(ALERTS_INDEX).get());
    }

    /**
     * Req 1.a: The translation uses the user's role definition and the application privilege's actions.
     * Only roles referencing {@code kibana-.kibana} app privileges whose stored definition includes the
     * {@code alerts:read} action produce implicit index privileges. Wrong action or wrong application → denied.
     */
    public void testReq1a_translationUsesRoleDefinitionAndAppPrivilegeActions() throws Exception {
        final Client admin = client();

        final PutPrivilegesRequest privReq = new PutPrivilegesRequest();
        privReq.setPrivileges(
            java.util.List.of(
                new ApplicationPrivilegeDescriptor("kibana-.kibana", "feature_alerting_write", Set.of("alerts:write"), emptyMap()),
                new ApplicationPrivilegeDescriptor("other-app", "other_alerting_read", Set.of("alerts:read"), emptyMap())
            )
        );
        admin.execute(PutPrivilegesAction.INSTANCE, privReq).actionGet();

        // Positive: correct app (kibana-.kibana) + correct action (alerts:read) → DLS-filtered access
        Client correctClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue(ALERTS_USER, new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );
        SearchResponse correctResp = correctClient.prepareSearch(ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(correctResp.getFailedShards(), equalTo(0));
            Set<String> ids = Arrays.stream(correctResp.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());
            assertThat("Correct app+action grants DLS-filtered access to space:default", ids, equalTo(Set.of("alert-default-1", "alert-both-1")));
        } finally {
            correctResp.decRef();
        }

        // Negative: correct app + WRONG action (alerts:write, not alerts:read) → denied
        new PutRoleRequestBuilder(admin).source("req1a_write_role", new BytesArray("""
            {
              "applications": [{
                "application": "kibana-.kibana",
                "privileges": ["feature_alerting_write"],
                "resources": ["space:default"]
              }]
            }
            """), XContentType.JSON).get();
        new PutUserRequestBuilder(admin).username("req1a_write_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1a_write_role")
            .get();
        Client writeClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue("req1a_write_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );
        expectThrows(ElasticsearchSecurityException.class, () -> writeClient.prepareSearch(ALERTS_INDEX).get());

        // Negative: WRONG app (other-app) + correct action (alerts:read) → denied
        new PutRoleRequestBuilder(admin).source("req1a_other_app_role", new BytesArray("""
            {
              "applications": [{
                "application": "other-app",
                "privileges": ["other_alerting_read"],
                "resources": ["space:default"]
              }]
            }
            """), XContentType.JSON).get();
        new PutUserRequestBuilder(admin).username("req1a_other_app_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1a_other_app_role")
            .get();
        Client otherAppClient = client().filterWithHeader(
            Map.of(
                "Authorization",
                basicAuthHeaderValue("req1a_other_app_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars()))
            )
        );
        expectThrows(ElasticsearchSecurityException.class, () -> otherAppClient.prepareSearch(ALERTS_INDEX).get());
    }

    /**
     * Req 1.b: The translation extracts the space-id from the resource using the {@code space:} prefix.
     * The prefix is matched but not captured — {@code space:marketing} yields space-id {@code marketing}.
     * Resources without the {@code space:} prefix are ignored and do not contribute to implicit access.
     */
    public void testReq1b_spaceIdExtractedFromResourcePrefix() throws Exception {
        final Client admin = client();

        // Positive: space:marketing → DLS filters to marketing space
        new PutRoleRequestBuilder(admin).source("req1b_marketing_role", new BytesArray("""
            {
              "applications": [{
                "application": "kibana-.kibana",
                "privileges": ["feature_alerting_read"],
                "resources": ["space:marketing"]
              }]
            }
            """), XContentType.JSON).get();
        new PutUserRequestBuilder(admin).username("req1b_marketing_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1b_marketing_role")
            .get();

        Client marketingClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue("req1b_marketing_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );
        SearchResponse marketingResp = marketingClient.prepareSearch(ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(marketingResp.getFailedShards(), equalTo(0));
            Set<String> ids = Arrays.stream(marketingResp.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());
            assertThat(
                "space:marketing strips prefix and DLS filters to marketing space-id",
                ids,
                equalTo(Set.of("alert-marketing-1", "alert-both-1"))
            );
        } finally {
            marketingResp.decRef();
        }

        // Negative: resource without space: prefix → ignored, no implicit access
        new PutRoleRequestBuilder(admin).source("req1b_no_prefix_role", new BytesArray("""
            {
              "applications": [{
                "application": "kibana-.kibana",
                "privileges": ["feature_alerting_read"],
                "resources": ["no-prefix-resource"]
              }]
            }
            """), XContentType.JSON).get();
        new PutUserRequestBuilder(admin).username("req1b_no_prefix_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1b_no_prefix_role")
            .get();

        Client noPrefixClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue("req1b_no_prefix_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );
        expectThrows(ElasticsearchSecurityException.class, () -> noPrefixClient.prepareSearch(ALERTS_INDEX).get());
    }

    /**
     * Req 1.c: When the resources field includes {@code *}, the user is authorized to access all spaces.
     * No DLS query is applied and the user sees every document in the alerts index.
     */
    public void testReq1c_wildcardResourceMatchesAllDocuments() throws Exception {
        final Client admin = client();

        new PutRoleRequestBuilder(admin).source("req1c_all_role", new BytesArray("""
            {
              "applications": [{
                "application": "kibana-.kibana",
                "privileges": ["feature_alerting_read"],
                "resources": ["*"]
              }]
            }
            """), XContentType.JSON).get();
        new PutUserRequestBuilder(admin).username("req1c_all_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1c_all_role")
            .get();

        Client allClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue("req1c_all_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );
        SearchResponse resp = allClient.prepareSearch(ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(resp.getFailedShards(), equalTo(0));
            Set<String> ids = Arrays.stream(resp.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());
            assertThat(
                "Wildcard resource grants access to all documents without DLS filtering",
                ids,
                equalTo(Set.of("alert-default-1", "alert-marketing-1", "alert-both-1", "alert-sales-1"))
            );
        } finally {
            resp.decRef();
        }
    }

    /**
     * Req 1.d: A single role with multiple application privilege entries must merge the spaces.
     * The user sees documents from all spaces granted across the entries.
     */
    public void testReq1d_singleRoleMultipleAppPrivilegesMergesSpaces() throws Exception {
        final Client admin = client();

        new PutRoleRequestBuilder(admin).source("req1d_multi_priv_role", new BytesArray("""
            {
              "applications": [
                {
                  "application": "kibana-.kibana",
                  "privileges": ["feature_alerting_read"],
                  "resources": ["space:default", "space:marketing"]
                },
                {
                  "application": "kibana-.kibana",
                  "privileges": ["feature_alerting_read"],
                  "resources": ["space:sales"]
                }
              ]
            }
            """), XContentType.JSON).get();
        new PutUserRequestBuilder(admin).username("req1d_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1d_multi_priv_role")
            .get();

        Client multiPrivClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue("req1d_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );
        SearchResponse resp = multiPrivClient.prepareSearch(ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(resp.getFailedShards(), equalTo(0));
            Set<String> ids = Arrays.stream(resp.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());
            assertThat(
                "Single role with multiple app-priv entries merges all spaces (default, marketing, sales)",
                ids,
                equalTo(Set.of("alert-default-1", "alert-marketing-1", "alert-both-1", "alert-sales-1"))
            );
        } finally {
            resp.decRef();
        }
    }

    /**
     * Req 1.e: Multiple roles each with relevant application privileges merge their spaces.
     * A user assigned role_1 (space:default) and role_2 (space:marketing) sees documents from both spaces.
     */
    public void testReq1e_multipleRolesWithAppPrivilegesMergeSpaces() throws Exception {
        final Client admin = client();

        new PutRoleRequestBuilder(admin).source("req1e_role_1", new BytesArray("""
            {
              "applications": [{
                "application": "kibana-.kibana",
                "privileges": ["feature_alerting_read"],
                "resources": ["space:default"]
              }]
            }
            """), XContentType.JSON).get();

        new PutRoleRequestBuilder(admin).source("req1e_role_2", new BytesArray("""
            {
              "applications": [{
                "application": "kibana-.kibana",
                "privileges": ["feature_alerting_read"],
                "resources": ["space:sales"]
              }]
            }
            """), XContentType.JSON).get();

        new PutUserRequestBuilder(admin).username("req1e_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1e_role_1", "req1e_role_2")
            .get();

        Client multiRoleClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue("req1e_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );
        SearchResponse resp = multiRoleClient.prepareSearch(ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(resp.getFailedShards(), equalTo(0));
            Set<String> ids = Arrays.stream(resp.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());
            assertThat(
                "Two roles granting space:default and space:sales merge into union of both spaces",
                ids,
                equalTo(Set.of("alert-default-1", "alert-both-1", "alert-sales-1"))
            );
        } finally {
            resp.decRef();
        }
    }

    /**
     * Req 1.f: Only {@code *} is supported as the resource wildcard. When a user has both {@code *}
     * and specific {@code space:foo} resources, the wildcard takes precedence and the user sees all
     * documents without DLS filtering. The resource pattern {@code space:*} is NOT treated as a wildcard.
     */
    public void testReq1f_wildcardTakesPrecedenceOverSpecificSpaces() throws Exception {
        final Client admin = client();

        // * alongside space:default → wildcard takes precedence, all documents visible
        new PutRoleRequestBuilder(admin).source("req1f_mixed_role", new BytesArray("""
            {
              "applications": [
                {
                  "application": "kibana-.kibana",
                  "privileges": ["feature_alerting_read"],
                  "resources": ["*"]
                },
                {
                  "application": "kibana-.kibana",
                  "privileges": ["feature_alerting_read"],
                  "resources": ["space:default"]
                }
              ]
            }
            """), XContentType.JSON).get();
        new PutUserRequestBuilder(admin).username("req1f_mixed_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1f_mixed_role")
            .get();

        Client mixedClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue("req1f_mixed_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );
        SearchResponse mixedResp = mixedClient.prepareSearch(ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(mixedResp.getFailedShards(), equalTo(0));
            Set<String> ids = Arrays.stream(mixedResp.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());
            assertThat(
                "Wildcard * takes precedence — user sees all documents",
                ids,
                equalTo(Set.of("alert-default-1", "alert-marketing-1", "alert-both-1", "alert-sales-1"))
            );
        } finally {
            mixedResp.decRef();
        }

        // space:* is NOT treated as a wildcard — it is not a valid resource and grants no access
        new PutRoleRequestBuilder(admin).source("req1f_space_star_role", new BytesArray("""
            {
              "applications": [{
                "application": "kibana-.kibana",
                "privileges": ["feature_alerting_read"],
                "resources": ["space:*"]
              }]
            }
            """), XContentType.JSON).get();
        new PutUserRequestBuilder(admin).username("req1f_space_star_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1f_space_star_role")
            .get();

        Client spaceStarClient = client().filterWithHeader(
            Map.of(
                "Authorization",
                basicAuthHeaderValue("req1f_space_star_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars()))
            )
        );
        SearchResponse spaceStarResp = spaceStarClient.prepareSearch(ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(spaceStarResp.getFailedShards(), equalTo(0));
            Set<String> spaceStarIds = Arrays.stream(spaceStarResp.getHits().getHits())
                .map(SearchHit::getId)
                .collect(Collectors.toSet());
            assertThat(
                "space:* is treated as literal space-id '*', not a wildcard — DLS filters to space_ids containing '*'",
                spaceStarIds.isEmpty(),
                equalTo(true)
            );
        } finally {
            spaceStarResp.decRef();
        }
    }

    /**
     * Req 1.g: Only an exact action match of {@code alerts:read} triggers implicit access.
     * Stored privileges with wildcarded actions like {@code alerts:*} or {@code *} do not match.
     */
    public void testReq1g_exactPrivilegeActionMatchRequired() throws Exception {
        final Client admin = client();

        // Register stored privileges with wildcarded actions
        final PutPrivilegesRequest privReq = new PutPrivilegesRequest();
        privReq.setPrivileges(
            java.util.List.of(
                new ApplicationPrivilegeDescriptor("kibana-.kibana", "alerts_wildcard", Set.of("alerts:*"), emptyMap()),
                new ApplicationPrivilegeDescriptor("kibana-.kibana", "full_wildcard", Set.of("*"), emptyMap())
            )
        );
        admin.execute(PutPrivilegesAction.INSTANCE, privReq).actionGet();

        // alerts:* action → should NOT match alerts:read
        new PutRoleRequestBuilder(admin).source("req1g_alerts_star_role", new BytesArray("""
            {
              "applications": [{
                "application": "kibana-.kibana",
                "privileges": ["alerts_wildcard"],
                "resources": ["space:default"]
              }]
            }
            """), XContentType.JSON).get();
        new PutUserRequestBuilder(admin).username("req1g_alerts_star_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1g_alerts_star_role")
            .get();

        Client alertsStarClient = client().filterWithHeader(
            Map.of(
                "Authorization",
                basicAuthHeaderValue("req1g_alerts_star_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars()))
            )
        );
        expectThrows(
            ElasticsearchSecurityException.class,
            () -> alertsStarClient.prepareSearch(ALERTS_INDEX).get()
        );

        // * action → should NOT match alerts:read
        new PutRoleRequestBuilder(admin).source("req1g_full_star_role", new BytesArray("""
            {
              "applications": [{
                "application": "kibana-.kibana",
                "privileges": ["full_wildcard"],
                "resources": ["space:default"]
              }]
            }
            """), XContentType.JSON).get();
        new PutUserRequestBuilder(admin).username("req1g_full_star_user")
            .password(TEST_PASSWORD_SECURE_STRING, getFastStoredHashAlgoForTests())
            .roles("req1g_full_star_role")
            .get();

        Client fullStarClient = client().filterWithHeader(
            Map.of(
                "Authorization",
                basicAuthHeaderValue("req1g_full_star_user", new SecureString(TEST_PASSWORD_SECURE_STRING.getChars()))
            )
        );
        expectThrows(
            ElasticsearchSecurityException.class,
            () -> fullStarClient.prepareSearch(ALERTS_INDEX).get()
        );
    }

    /**
     * Req 3: The Get Roles HTTP API must NOT return implicit index privileges derived from
     * application privileges. The role descriptor returned by the API should contain only the
     * explicitly configured privileges.
     */
    public void testReq3_getRolesApiDoesNotExposeImplicitIndexPrivileges() throws Exception {
        // ALERTS_ROLE has only application privileges — verify the user can actually search
        Client alertsClient = client().filterWithHeader(
            Map.of("Authorization", basicAuthHeaderValue(ALERTS_USER, new SecureString(TEST_PASSWORD_SECURE_STRING.getChars())))
        );
        SearchResponse searchResp = alertsClient.prepareSearch(ALERTS_INDEX).setSize(1).get();
        try {
            assertThat("Implicit access should work", searchResp.getHits().getTotalHits().value(), equalTo(2L));
        } finally {
            searchResp.decRef();
        }

        // Now fetch the role via the Get Roles API and verify no index privileges leak
        GetRolesResponse rolesResp = new GetRolesRequestBuilder(client()).names(ALERTS_ROLE).get();
        assertTrue("Role should exist", rolesResp.hasRoles());
        RoleDescriptor descriptor = rolesResp.roles()[0];
        assertThat("Role name should match", descriptor.getName(), equalTo(ALERTS_ROLE));

        RoleDescriptor.IndicesPrivileges[] indicesPrivileges = descriptor.getIndicesPrivileges();
        for (RoleDescriptor.IndicesPrivileges priv : indicesPrivileges) {
            for (String index : priv.getIndices()) {
                assertFalse(
                    "Get Roles API must not expose implicit .alerts-* index privileges, but found: " + index,
                    index.startsWith(".alerts")
                );
            }
        }
    }
}
