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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

/**
 * Integration test verifying that the {@code kibana-cases-security} module's implicit role
 * contribution works end-to-end with solution-level gating via {@code solution:} resources.
 * <p>
 * The role grants {@code cases:read} with {@code space:default} and
 * {@code solution:securitySolution}, so the user should only access
 * {@code .internal.cases*.default-securitysolution} indices.
 */
public class KibanaCasesImplicitRolesRestIT extends ESRestTestCase {

    private static final String ADMIN_USER = "admin_user";
    private static final SecureString ADMIN_PASSWORD = new SecureString("admin-password".toCharArray());

    private static final String CASES_USER = "cases_user";
    private static final SecureString CASES_PASSWORD = new SecureString("cases-password".toCharArray());

    private static final String NO_PRIV_USER = "no_priv_user";
    private static final SecureString NO_PRIV_PASSWORD = new SecureString("no-priv-password".toCharArray());

    private static final String CASES_DEFAULT_SECURITY = ".internal.cases.default-securitysolution";
    private static final String CASES_DEFAULT_OBS = ".internal.cases.default-observability";
    private static final String CASES_MARKETING_SECURITY = ".internal.cases.marketing-securitysolution";
    private static final String ATTACHMENTS_DEFAULT_SECURITY = ".internal.cases-attachments.default-securitysolution";

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

        securityClient.putApplicationPrivilege("kibana-.kibana", "feature_cases_read", new String[] { "cases:read" });
        securityClient.putUser(new User(CASES_USER, "sec_cases_default_role"), CASES_PASSWORD);
        securityClient.putUser(new User(NO_PRIV_USER), NO_PRIV_PASSWORD);

        RequestOptions permissive = RequestOptions.DEFAULT.toBuilder().setWarningsHandler(WarningsHandler.PERMISSIVE).build();
        for (String index : List.of(CASES_DEFAULT_SECURITY, CASES_DEFAULT_OBS, CASES_MARKETING_SECURITY, ATTACHMENTS_DEFAULT_SECURITY)) {
            Request createIndex = new Request("PUT", index);
            createIndex.setOptions(permissive);
            adminClient().performRequest(createIndex);
        }

        indexDoc(CASES_DEFAULT_SECURITY, "case-1", """
            {"title": "security case in default space"}""");
        indexDoc(CASES_DEFAULT_OBS, "case-2", """
            {"title": "observability case in default space"}""");
        indexDoc(CASES_MARKETING_SECURITY, "case-3", """
            {"title": "security case in marketing space"}""");
        indexDoc(ATTACHMENTS_DEFAULT_SECURITY, "att-1", """
            {"case_id": "case-1", "type": "file"}""");

        for (String index : List.of(CASES_DEFAULT_SECURITY, CASES_DEFAULT_OBS, CASES_MARKETING_SECURITY, ATTACHMENTS_DEFAULT_SECURITY)) {
            Request refresh = new Request("POST", index + "/_refresh");
            refresh.setOptions(permissive);
            adminClient().performRequest(refresh);
        }
    }

    public void testAccessGrantedForMatchingSpaceAndSolution() throws Exception {
        var hits = searchHits(CASES_USER, CASES_PASSWORD, CASES_DEFAULT_SECURITY);
        assertThat(hits.size(), equalTo(1));
        assertThat(hits.get(0).get("_id"), equalTo("case-1"));
    }

    public void testAccessCoversAttachmentsForSameSpaceAndSolution() throws Exception {
        var hits = searchHits(CASES_USER, CASES_PASSWORD, ATTACHMENTS_DEFAULT_SECURITY);
        assertThat(hits.size(), equalTo(1));
        assertThat(hits.get(0).get("_id"), equalTo("att-1"));
    }

    public void testAccessDeniedForDifferentSolution() {
        assertSearchDenied(CASES_USER, CASES_PASSWORD, CASES_DEFAULT_OBS);
    }

    public void testAccessDeniedForDifferentSpace() {
        assertSearchDenied(CASES_USER, CASES_PASSWORD, CASES_MARKETING_SECURITY);
    }

    public void testUserWithoutAppPrivilegeIsDenied() {
        assertSearchDenied(NO_PRIV_USER, NO_PRIV_PASSWORD, CASES_DEFAULT_SECURITY);
    }

    private List<Map<String, Object>> searchHits(String user, SecureString password, String index) throws IOException {
        Request search = new Request("GET", index + "/_search");
        search.setOptions(requestOptionsForUser(user, password));
        Response response = client().performRequest(search);
        return ObjectPath.eval("hits.hits", entityAsMap(response));
    }

    private void assertSearchDenied(String user, SecureString password, String index) {
        Request search = new Request("GET", index + "/_search");
        search.setOptions(requestOptionsForUser(user, password));
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
