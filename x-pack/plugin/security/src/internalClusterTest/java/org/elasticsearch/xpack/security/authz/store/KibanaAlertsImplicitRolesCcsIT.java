/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.store;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.action.admin.indices.delete.DeleteIndexRequest;
import org.elasticsearch.action.admin.indices.get.GetIndexRequest;
import org.elasticsearch.action.admin.indices.get.GetIndexResponse;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.client.internal.OriginSettingClient;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.test.AbstractMultiClustersTestCase;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.test.NodeConfigurationSource;
import org.elasticsearch.test.SecuritySettingsSource;
import org.elasticsearch.test.SecuritySettingsSourceField;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesAction;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesRequest;
import org.elasticsearch.xpack.core.security.action.role.PutRoleRequestBuilder;
import org.elasticsearch.xpack.core.security.action.user.PutUserRequestBuilder;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Collections.emptyMap;
import static org.elasticsearch.test.SecuritySettingsSourceField.TEST_PASSWORD_SECURE_STRING;
import static org.elasticsearch.xpack.core.ClientHelper.MONITORING_ORIGIN;
import static org.elasticsearch.xpack.core.ClientHelper.SECURITY_ORIGIN;
import static org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken.BASIC_AUTH_HEADER;
import static org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken.basicAuthHeaderValue;
import static org.elasticsearch.xpack.security.support.SecuritySystemIndices.SECURITY_MAIN_ALIAS;
import static org.hamcrest.Matchers.equalTo;

/**
 * Integration test verifying that implicit roles (via {@code KibanaAlertsImplicitRoles}) work
 * correctly across clusters in RCS 1.0 (legacy CCS) mode. The same application privileges,
 * roles, and users must be configured on both the local and remote clusters for implicit access
 * to function, since the remote cluster resolves DLS queries from its own role stores.
 */
@ESTestCase.WithoutEntitlements
public class KibanaAlertsImplicitRolesCcsIT extends AbstractMultiClustersTestCase {

    private static final String REMOTE_CLUSTER = "remote_cluster";
    private static final String ALERTS_INDEX = ".alerts-test";
    private static final String ALERTS_USER = "alerts_ccs_user";
    private static final String ALERTS_ROLE = "alerts_ccs_role";

    @Override
    protected List<String> remoteClusterAlias() {
        return List.of(REMOTE_CLUSTER);
    }

    @Override
    protected Map<String, Boolean> skipUnavailableForRemoteClusters() {
        return Map.of(REMOTE_CLUSTER, false);
    }

    @Override
    protected boolean reuseClusters() {
        return false;
    }

    @Override
    protected NodeConfigurationSource nodeConfigurationSource() {
        return new CustomSecuritySettingsSource(false, createTempDir(), ESIntegTestCase.Scope.TEST);
    }

    @Override
    protected String internalClientOrigin() {
        return MONITORING_ORIGIN;
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        setupTestData();
    }

    @After
    public void cleanupSecurityIndex() {
        deleteSecurityIndex(LOCAL_CLUSTER);
        deleteSecurityIndex(REMOTE_CLUSTER);
    }

    /**
     * When the same user, role, and app privilege exist on both local and remote clusters,
     * a legacy CCS search should succeed and return DLS-filtered results.
     */
    public void testLegacyCcsSearchRemoteAlertsWithImplicitAccess() {
        Client userClient = client().filterWithHeader(
            Map.of(BASIC_AUTH_HEADER, basicAuthHeaderValue(ALERTS_USER, TEST_PASSWORD_SECURE_STRING))
        );

        SearchResponse response = userClient.prepareSearch(REMOTE_CLUSTER + ":" + ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(response.getFailedShards(), equalTo(0));

            Set<String> returnedIds = Arrays.stream(response.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());

            assertThat(
                "User with space:default on remote cluster should see only default-space alerts via implicit DLS",
                returnedIds,
                equalTo(Set.of("alert-default-1", "alert-both-1"))
            );

            assertThat(response.getHits().getTotalHits().value(), equalTo(2L));
        } finally {
            response.decRef();
        }
    }

    /**
     * When a user has app privileges only on the local cluster (not the remote), the remote
     * cluster independently resolves the role and finds it missing. With {@code skip_unavailable=false}
     * the CCS search is denied because the user has no index privileges on the remote cluster.
     */
    public void testLegacyCcsUserWithoutRemoteRoleIsDenied() throws Exception {
        Client localAdmin = adminClient(LOCAL_CLUSTER);

        new PutRoleRequestBuilder(localAdmin).source("local_only_alerts_role", new BytesArray("""
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

        new PutUserRequestBuilder(localAdmin).username("local_only_user")
            .password(TEST_PASSWORD_SECURE_STRING, SecuritySettingsSource.HASHER)
            .roles("local_only_alerts_role")
            .get();

        Client localOnlyClient = client().filterWithHeader(
            Map.of(BASIC_AUTH_HEADER, basicAuthHeaderValue("local_only_user", TEST_PASSWORD_SECURE_STRING))
        );

        expectThrows(ElasticsearchSecurityException.class, () -> localOnlyClient.prepareSearch(REMOTE_CLUSTER + ":" + ALERTS_INDEX).get());
    }

    /**
     * When the user has the alerts privilege for multiple spaces on the remote cluster,
     * the DLS query should include all granted spaces. This verifies that the implicit
     * role contributor correctly merges space IDs from different app privilege entries.
     */
    public void testLegacyCcsSearchRemoteAlertsMultipleSpaces() throws Exception {
        for (String cluster : List.of(LOCAL_CLUSTER, REMOTE_CLUSTER)) {
            Client admin = adminClient(cluster);

            new PutRoleRequestBuilder(admin).source("multi_space_role", new BytesArray("""
                {
                  "applications": [
                    {
                      "application": "kibana-.kibana",
                      "privileges": ["feature_alerting_read"],
                      "resources": ["space:default", "space:marketing"]
                    }
                  ]
                }
                """), XContentType.JSON).get();

            new PutUserRequestBuilder(admin).username("multi_space_user")
                .password(TEST_PASSWORD_SECURE_STRING, SecuritySettingsSource.HASHER)
                .roles("multi_space_role")
                .get();
        }

        Client multiSpaceClient = client().filterWithHeader(
            Map.of(BASIC_AUTH_HEADER, basicAuthHeaderValue("multi_space_user", TEST_PASSWORD_SECURE_STRING))
        );

        SearchResponse response = multiSpaceClient.prepareSearch(REMOTE_CLUSTER + ":" + ALERTS_INDEX).setSize(10).get();
        try {
            assertThat(response.getFailedShards(), equalTo(0));

            Set<String> returnedIds = Arrays.stream(response.getHits().getHits()).map(SearchHit::getId).collect(Collectors.toSet());

            assertThat(
                "User with space:default and space:marketing should see all three alerts (default, marketing, and both)",
                returnedIds,
                equalTo(Set.of("alert-default-1", "alert-marketing-1", "alert-both-1"))
            );

            assertThat(response.getHits().getTotalHits().value(), equalTo(3L));
        } finally {
            response.decRef();
        }
    }

    private void setupTestData() throws IOException {
        registerAppPrivilegesAndRoleAndUser(LOCAL_CLUSTER);
        registerAppPrivilegesAndRoleAndUser(REMOTE_CLUSTER);
        indexAlertsOnRemoteCluster();
    }

    private Client adminClient(String clusterAlias) {
        return client(clusterAlias).filterWithHeader(
            Map.of(BASIC_AUTH_HEADER, basicAuthHeaderValue(SecuritySettingsSource.TEST_USER_NAME, TEST_PASSWORD_SECURE_STRING))
        );
    }

    private void registerAppPrivilegesAndRoleAndUser(String clusterAlias) throws IOException {
        Client admin = adminClient(clusterAlias);

        PutPrivilegesRequest putPrivilegesRequest = new PutPrivilegesRequest();
        putPrivilegesRequest.setPrivileges(
            List.of(new ApplicationPrivilegeDescriptor("kibana-.kibana", "feature_alerting_read", Set.of("alerts:read"), emptyMap()))
        );
        admin.execute(PutPrivilegesAction.INSTANCE, putPrivilegesRequest).actionGet();

        new PutRoleRequestBuilder(admin).source(ALERTS_ROLE, new BytesArray("""
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

        new PutUserRequestBuilder(admin).username(ALERTS_USER)
            .password(TEST_PASSWORD_SECURE_STRING, SecuritySettingsSource.HASHER)
            .roles(ALERTS_ROLE)
            .get();
    }

    private void indexAlertsOnRemoteCluster() {
        Client remoteAdmin = client(REMOTE_CLUSTER);

        remoteAdmin.admin().indices().prepareCreate(ALERTS_INDEX).get();

        remoteAdmin.prepareIndex(ALERTS_INDEX)
            .setId("alert-default-1")
            .setSource(Map.of("kibana.space_ids", List.of("default"), "message", "alert in default space"))
            .get();

        remoteAdmin.prepareIndex(ALERTS_INDEX)
            .setId("alert-marketing-1")
            .setSource(Map.of("kibana.space_ids", List.of("marketing"), "message", "alert in marketing space"))
            .get();

        remoteAdmin.prepareIndex(ALERTS_INDEX)
            .setId("alert-both-1")
            .setSource(Map.of("kibana.space_ids", List.of("default", "marketing"), "message", "alert in both spaces"))
            .get();

        remoteAdmin.admin().indices().prepareRefresh(ALERTS_INDEX).get();
        ensureGreen(ALERTS_INDEX, remoteAdmin);
    }

    private void ensureGreen(String index, Client client) {
        client.admin().cluster().prepareHealth(TEST_REQUEST_TIMEOUT, index).setWaitForGreenStatus().get();
    }

    private void deleteSecurityIndex(String clusterAlias) {
        Client client = new OriginSettingClient(client(clusterAlias), SECURITY_ORIGIN);

        GetIndexRequest getIndexRequest = new GetIndexRequest(TEST_REQUEST_TIMEOUT);
        getIndexRequest.indices(SECURITY_MAIN_ALIAS);
        getIndexRequest.indicesOptions(IndicesOptions.lenientExpandOpen());
        GetIndexResponse getIndexResponse = client.admin().indices().getIndex(getIndexRequest).actionGet(TEST_REQUEST_TIMEOUT);

        if (getIndexResponse.getIndices().length > 0) {
            DeleteIndexRequest deleteIndexRequest = new DeleteIndexRequest(getIndexResponse.getIndices());
            client.admin().indices().delete(deleteIndexRequest).actionGet(TEST_REQUEST_TIMEOUT);
        }
    }

    private static class CustomSecuritySettingsSource extends SecuritySettingsSource {
        private static final String TEST_ROLE_YML = """
            user:
              cluster: [ ALL ]
              indices:
                - names: '*'
                  allow_restricted_indices: true
                  privileges: [ ALL ]
            """;

        private static final String CONFIG_STANDARD_ROLES_YML = TEST_ROLE_YML + "\n" + SecuritySettingsSourceField.ES_TEST_ROOT_ROLE_YML;

        private CustomSecuritySettingsSource(boolean sslEnabled, Path parentFolder, ESIntegTestCase.Scope scope) {
            super(sslEnabled, parentFolder, scope);
        }

        @Override
        protected String configRoles() {
            return CONFIG_STANDARD_ROLES_YML;
        }
    }
}
