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
 * Integration test verifying that the {@code kibana-cases-security} module's implicit role
 * contribution works end-to-end in a real cluster deployment. The cluster runs in a separate
 * process with the {@code x-pack-kibana-cases-security} module installed, so the SPI-based
 * {@code ImplicitRoleDescriptorContributor} must be discovered via {@code META-INF/services}
 * for the test to pass.
 * <p>
 * Cases analytics indices encode the space in the index name (e.g.
 * {@code .internal.cases.default-securitysolution}), so access control is pattern-based
 * rather than DLS-based. A user with {@code cases:read} for {@code space:default} gets
 * implicit read on {@code .internal.cases*.default-*} and cannot access indices for other spaces.
 */
public class KibanaCasesImplicitRolesRestIT extends ESRestTestCase {

    private static final String ADMIN_USER = "admin_user";
    private static final SecureString ADMIN_PASSWORD = new SecureString("admin-password".toCharArray());

    private static final String CASES_USER = "cases_user";
    private static final SecureString CASES_PASSWORD = new SecureString("cases-password".toCharArray());

    private static final String NO_PRIV_USER = "no_priv_user";
    private static final SecureString NO_PRIV_PASSWORD = new SecureString("no-priv-password".toCharArray());

    /** Cases index in the default space for the security solution */
    private static final String CASES_DEFAULT = ".internal.cases.default-securitysolution";
    /** Cases index in the marketing space for the security solution */
    private static final String CASES_MARKETING = ".internal.cases.marketing-securitysolution";
    /** Cases attachments index in the default space */
    private static final String CASES_ATTACHMENTS_DEFAULT = ".internal.cases-attachments.default-securitysolution";

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

        // Register the stored application privilege whose actions include cases:read
        securityClient.putApplicationPrivilege("kibana-.kibana", "feature_cases_read", new String[] { "cases:read" });

        // Create users: one with cases_role (defined in roles.yml for space:default), one with no privileges
        securityClient.putUser(new User(CASES_USER, "cases_role"), CASES_PASSWORD);
        securityClient.putUser(new User(NO_PRIV_USER), NO_PRIV_PASSWORD);

        // Create per-space cases analytics indices and populate with test data
        RequestOptions permissive = RequestOptions.DEFAULT.toBuilder().setWarningsHandler(WarningsHandler.PERMISSIVE).build();

        for (String index : List.of(CASES_DEFAULT, CASES_MARKETING, CASES_ATTACHMENTS_DEFAULT)) {
            Request createIndex = new Request("PUT", index);
            createIndex.setOptions(permissive);
            adminClient().performRequest(createIndex);
        }

        indexDoc(CASES_DEFAULT, "case-1", """
            {"title": "case in default space", "status": "open"}""");
        indexDoc(CASES_MARKETING, "case-2", """
            {"title": "case in marketing space", "status": "open"}""");
        indexDoc(CASES_ATTACHMENTS_DEFAULT, "attachment-1", """
            {"case_id": "case-1", "type": "file"}""");

        for (String index : List.of(CASES_DEFAULT, CASES_MARKETING, CASES_ATTACHMENTS_DEFAULT)) {
            Request refresh = new Request("POST", index + "/_refresh");
            refresh.setOptions(permissive);
            adminClient().performRequest(refresh);
        }
    }

    /**
     * Verifies that a user with {@code cases:read} for {@code space:default} can search
     * cases indices in the default space.
     */
    public void testImplicitCasesAccessForDefaultSpace() throws Exception {
        RequestOptions casesAuth = requestOptionsForUser(CASES_USER, CASES_PASSWORD);

        Request search = new Request("GET", CASES_DEFAULT + "/_search");
        search.setOptions(casesAuth);

        Response response = client().performRequest(search);
        Map<String, Object> responseMap = entityAsMap(response);

        int failedShards = ObjectPath.eval("_shards.failed", responseMap);
        assertThat(failedShards, equalTo(0));

        List<Map<String, Object>> hits = ObjectPath.eval("hits.hits", responseMap);
        assertThat(hits.size(), equalTo(1));
        assertThat(hits.get(0).get("_id"), equalTo("case-1"));
    }

    /**
     * Verifies that the implicit pattern also covers other index types (e.g. attachments)
     * in the same space.
     */
    public void testImplicitAccessCoversAttachmentsIndex() throws Exception {
        RequestOptions casesAuth = requestOptionsForUser(CASES_USER, CASES_PASSWORD);

        Request search = new Request("GET", CASES_ATTACHMENTS_DEFAULT + "/_search");
        search.setOptions(casesAuth);

        Response response = client().performRequest(search);
        Map<String, Object> responseMap = entityAsMap(response);

        List<Map<String, Object>> hits = ObjectPath.eval("hits.hits", responseMap);
        assertThat(hits.size(), equalTo(1));
        assertThat(hits.get(0).get("_id"), equalTo("attachment-1"));
    }

    /**
     * Verifies that a user with {@code cases:read} for {@code space:default} is denied
     * access to a cases index in a different space (marketing).
     */
    public void testAccessDeniedForOtherSpace() {
        RequestOptions casesAuth = requestOptionsForUser(CASES_USER, CASES_PASSWORD);

        Request search = new Request("GET", CASES_MARKETING + "/_search");
        search.setOptions(casesAuth);

        ResponseException e = expectThrows(ResponseException.class, () -> client().performRequest(search));
        assertThat(e.getResponse().getStatusLine().getStatusCode(), equalTo(403));
        assertThat(e.getMessage(), containsString("is unauthorized"));
    }

    /**
     * Verifies that a user without any Kibana application privileges is denied access entirely.
     */
    public void testUserWithoutAppPrivilegeIsDenied() {
        RequestOptions noPrivAuth = requestOptionsForUser(NO_PRIV_USER, NO_PRIV_PASSWORD);

        Request search = new Request("GET", CASES_DEFAULT + "/_search");
        search.setOptions(noPrivAuth);

        ResponseException e = expectThrows(ResponseException.class, () -> client().performRequest(search));
        assertThat(e.getResponse().getStatusLine().getStatusCode(), equalTo(403));
        assertThat(e.getMessage(), containsString("is unauthorized"));
    }

    private void indexDoc(String index, String id, String body) throws IOException {
        Request req = new Request("PUT", index + "/_doc/" + id);
        req.setOptions(RequestOptions.DEFAULT.toBuilder().setWarningsHandler(WarningsHandler.PERMISSIVE).build());
        req.setJsonEntity(body);
        adminClient().performRequest(req);
    }

    private static RequestOptions requestOptionsForUser(String username, SecureString password) {
        return RequestOptions.DEFAULT.toBuilder()
            .addHeader("Authorization", UsernamePasswordToken.basicAuthHeaderValue(username, password))
            .setWarningsHandler(WarningsHandler.PERMISSIVE)
            .build();
    }
}
