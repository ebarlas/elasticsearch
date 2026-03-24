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
import org.elasticsearch.xpack.core.security.action.role.PutRoleRequestBuilder;
import org.elasticsearch.xpack.core.security.action.user.PutUserRequestBuilder;
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
                equalTo(Set.of("alert-default-1", "alert-marketing-1", "alert-both-1"))
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
}
