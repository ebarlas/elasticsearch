/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.store;

import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.Response;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.client.WarningsHandler;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.test.TestSecurityClient;
import org.elasticsearch.test.cluster.ElasticsearchCluster;
import org.elasticsearch.test.cluster.local.distribution.DistributionType;
import org.elasticsearch.test.cluster.util.resource.Resource;
import org.elasticsearch.test.rest.ESRestTestCase;
import org.elasticsearch.xcontent.ObjectPath;
import org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken;
import org.elasticsearch.xpack.core.security.user.User;
import org.junit.Before;
import org.junit.ClassRule;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

/**
 * Integration test verifying that the {@code kibana-security} module's implicit role contribution
 * works end-to-end in a real cluster deployment. The cluster runs in a separate process with the
 * {@code x-pack-kibana-security} module installed, so the SPI-based {@code ImplicitPrivilegesProvider}
 * must be discovered via {@code META-INF/services} for the test to pass.
 * <p>
 * A single representative scenario is tested: a user with Kibana application privileges for
 * {@code alerts:read} in a specific space gets implicit read access to {@code .alerts-*} with
 * DLS filtering by space.
 */
public class KibanaImplicitRolesRestIT extends ESRestTestCase {

    private static final String ADMIN_USER = "admin_user";
    private static final SecureString ADMIN_PASSWORD = new SecureString("admin-password".toCharArray());

    private static final String ALERTS_USER = "alerts_user";
    private static final SecureString ALERTS_PASSWORD = new SecureString("alerts-password".toCharArray());

    private static final String NO_PRIV_USER = "no_priv_user";
    private static final SecureString NO_PRIV_PASSWORD = new SecureString("no-priv-password".toCharArray());

    private static final String ALERTS_INDEX = ".alerts-test";

    @ClassRule
    public static ElasticsearchCluster cluster = ElasticsearchCluster.local()
        .nodes(1)
        .distribution(DistributionType.DEFAULT)
        .setting("xpack.license.self_generated.type", "basic")
        .setting("xpack.security.enabled", "true")
        .setting("xpack.security.http.ssl.enabled", "false")
        .setting("xpack.security.transport.ssl.enabled", "false")
        .setting("xpack.security.authc.api_key.enabled", "true")
        .rolesFile(Resource.fromClasspath("roles.yml"))
        .user(ADMIN_USER, ADMIN_PASSWORD.toString(), "superuser", true)
        .build();

    private TestSecurityClient securityClient;

    @Override
    protected String getTestRestCluster() {
        return cluster.getHttpAddresses();
    }

    @Override
    protected Settings restAdminSettings() {
        String token = basicAuthHeaderValue(ADMIN_USER, ADMIN_PASSWORD);
        return Settings.builder().put(ThreadContext.PREFIX + ".Authorization", token).build();
    }

    @Before
    public void setupTestData() throws Exception {
        securityClient = new TestSecurityClient(adminClient());

        // Register the stored application privilege whose actions include alerts:read
        securityClient.putApplicationPrivilege("kibana-.kibana", "feature_alerting_read", new String[] { "alerts:read" });

        // Create the alerts_role (references the app privilege for space:default) — defined in roles.yml
        // Create users: one with alerts_role, one with no relevant privileges
        securityClient.putUser(new User(ALERTS_USER, "alerts_role"), ALERTS_PASSWORD);
        securityClient.putUser(new User(NO_PRIV_USER), NO_PRIV_PASSWORD);

        // Create and populate the alerts index (wipeCluster in @After removes it between test methods)
        RequestOptions permissive = RequestOptions.DEFAULT.toBuilder().setWarningsHandler(WarningsHandler.PERMISSIVE).build();

        Request createIndex = new Request("PUT", ALERTS_INDEX);
        createIndex.setOptions(permissive);
        adminClient().performRequest(createIndex);

        indexAlert("alert-default-1", List.of("default"), "alert in default space");
        indexAlert("alert-marketing-1", List.of("marketing"), "alert in marketing space");
        indexAlert("alert-both-1", List.of("default", "marketing"), "alert in both spaces");

        Request refresh = new Request("POST", ALERTS_INDEX + "/_refresh");
        refresh.setOptions(permissive);
        adminClient().performRequest(refresh);
    }

    /**
     * Verifies the full implicit roles pipeline: SPI discovery of the kibana-security module's
     * contributor, application privilege resolution, implicit index privilege generation with DLS,
     * and search-time enforcement. The user has {@code alerts:read} for {@code space:default},
     * so they should see only documents whose {@code kibana.space_ids} includes "default".
     */
    public void testImplicitAlertsAccessWithDlsFiltering() throws Exception {
        RequestOptions alertsAuth = requestOptionsForUser(ALERTS_USER, ALERTS_PASSWORD);

        Request search = new Request("GET", ALERTS_INDEX + "/_search");
        search.addParameter("size", "10");
        search.setOptions(alertsAuth);

        Response response = client().performRequest(search);
        Map<String, Object> responseMap = entityAsMap(response);

        int failedShards = ObjectPath.eval("_shards.failed", responseMap);
        assertThat(failedShards, equalTo(0));

        List<Map<String, Object>> hits = ObjectPath.eval("hits.hits", responseMap);
        Set<String> returnedIds = hits.stream().map(h -> (String) h.get("_id")).collect(Collectors.toSet());

        assertThat(
            "User with space:default should see default-space and both-space alerts only",
            returnedIds,
            equalTo(Set.of("alert-default-1", "alert-both-1"))
        );
    }

    /**
     * Verifies that a user without any Kibana application privileges is denied access to the
     * alerts index entirely — confirming that implicit access requires the correct app privilege.
     */
    public void testUserWithoutAppPrivilegeIsDenied() {
        RequestOptions noPrivAuth = requestOptionsForUser(NO_PRIV_USER, NO_PRIV_PASSWORD);

        Request search = new Request("GET", ALERTS_INDEX + "/_search");
        search.setOptions(noPrivAuth);

        ResponseException e = expectThrows(ResponseException.class, () -> client().performRequest(search));
        assertThat(e.getResponse().getStatusLine().getStatusCode(), equalTo(403));
        assertThat(e.getMessage(), containsString("is unauthorized"));
    }

    private void indexAlert(String id, List<String> spaceIds, String message) throws IOException {
        Request index = new Request("PUT", ALERTS_INDEX + "/_doc/" + id);
        index.setOptions(RequestOptions.DEFAULT.toBuilder().setWarningsHandler(WarningsHandler.PERMISSIVE).build());
        index.setJsonEntity("""
            {"kibana.space_ids": %s, "message": "%s"}
            """.formatted(spaceIds.stream().map(s -> "\"" + s + "\"").collect(Collectors.joining(",", "[", "]")), message));
        adminClient().performRequest(index);
    }

    private static RequestOptions requestOptionsForUser(String username, SecureString password) {
        return RequestOptions.DEFAULT.toBuilder()
            .addHeader("Authorization", UsernamePasswordToken.basicAuthHeaderValue(username, password))
            .setWarningsHandler(WarningsHandler.PERMISSIVE)
            .build();
    }
}
