/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.remotecluster;

import org.elasticsearch.client.Request;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.ResponseException;
import org.elasticsearch.core.Strings;
import org.elasticsearch.test.cluster.ElasticsearchCluster;
import org.junit.ClassRule;
import org.junit.rules.RuleChain;
import org.junit.rules.TestRule;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

/**
 * RCS 2.0 REST test demonstrating the implicit privileges forwarding gap.
 * <p>
 * In RCS 2.0, the querying cluster projects the user's {@code remote_indices} into a
 * {@code _remote_user} descriptor, which is intersected with the cross-cluster API key
 * on the fulfilling cluster. The {@link org.elasticsearch.xpack.kibanasecurity.KibanaAlertsImplicitRoles}
 * contributor only adds to {@code indices()} (local), not {@code remoteIndices()}, so the
 * forwarded descriptor lacks the implicit {@code .alerts-*} privilege.
 * <p>
 * This test verifies that a user who has implicit access locally (via app privileges
 * with {@code alerts:read}) gets a 403 when doing CCS over RCS 2.0 because the
 * implicit privilege is not forwarded to the remote cluster.
 */
public class RemoteClusterSecurityImplicitRolesRestIT extends AbstractRemoteClusterSecurityTestCase {

    private static final AtomicReference<Map<String, Object>> API_KEY_REFERENCE = new AtomicReference<>();

    private static final String API_KEY_ACCESS = """
        {
            "search": [
              {
                  "names": [".alerts-*"]
              }
            ]
        }""";

    static {
        fulfillingCluster = ElasticsearchCluster.local()
            .name("fulfilling-cluster")
            .apply(commonClusterConfig)
            .setting("remote_cluster_server.enabled", "true")
            .setting("remote_cluster.port", "0")
            .setting("xpack.security.remote_cluster_server.ssl.enabled", "true")
            .setting("xpack.security.remote_cluster_server.ssl.key", "remote-cluster.key")
            .setting("xpack.security.remote_cluster_server.ssl.certificate", "remote-cluster.crt")
            .keystore("xpack.security.remote_cluster_server.ssl.secure_key_passphrase", "remote-cluster-password")
            .build();

        queryCluster = ElasticsearchCluster.local()
            .name("query-cluster")
            .apply(commonClusterConfig)
            .setting("xpack.security.remote_cluster_client.ssl.enabled", "true")
            .setting("xpack.security.remote_cluster_client.ssl.certificate_authorities", "remote-cluster-ca.crt")
            .keystore("cluster.remote." + REMOTE_CLUSTER_ALIAS + ".credentials", () -> {
                if (API_KEY_REFERENCE.get() == null) {
                    API_KEY_REFERENCE.set(createCrossClusterAccessApiKey(API_KEY_ACCESS));
                }
                return (String) API_KEY_REFERENCE.get().get("encoded");
            })
            .build();
    }

    @ClassRule
    public static TestRule clusterRule = RuleChain.outerRule(fulfillingCluster).around(queryCluster);

    /**
     * The user has app privileges that grant implicit local access to {@code .alerts-*}, but the
     * {@code _remote_user} descriptor forwarded over RCS 2.0 does not include this implicit
     * privilege. The CCS search should fail with 403.
     */
    public void testRcs2ImplicitAccessNotForwardedToRemoteCluster() throws Exception {
        configureRemoteCluster();

        indexAlertsOnFulfillingCluster();

        registerAppPrivilegeOnQueryCluster();
        createImplicitOnlyRoleAndUserOnQueryCluster();

        final Request searchRequest = new Request(
            "GET",
            Strings.format("/%s:%s/_search?ccs_minimize_roundtrips=%s", REMOTE_CLUSTER_ALIAS, ".alerts-test", randomBoolean())
        );
        searchRequest.setOptions(
            RequestOptions.DEFAULT.toBuilder().addHeader("Authorization", basicAuthHeaderValue("implicit_alerts_user", PASS))
        );

        ResponseException exception = expectThrows(ResponseException.class, () -> client().performRequest(searchRequest));
        assertThat(exception.getResponse().getStatusLine().getStatusCode(), equalTo(403));
        assertThat(exception.getMessage(), containsString("is unauthorized for user [implicit_alerts_user]"));
    }

    private void indexAlertsOnFulfillingCluster() throws IOException {
        final Request bulkRequest = new Request("POST", "/_bulk?refresh=true");
        bulkRequest.setJsonEntity("""
            { "index": { "_index": ".alerts-test", "_id": "alert-default-1" } }
            { "kibana.space_ids": ["default"], "message": "alert in default space" }
            { "index": { "_index": ".alerts-test", "_id": "alert-marketing-1" } }
            { "kibana.space_ids": ["marketing"], "message": "alert in marketing space" }
            """);
        assertOK(performRequestAgainstFulfillingCluster(bulkRequest));
    }

    private void registerAppPrivilegeOnQueryCluster() throws IOException {
        final Request putPrivilegeRequest = new Request("PUT", "/_security/privilege");
        putPrivilegeRequest.setJsonEntity("""
            {
              "kibana-.kibana": {
                "feature_alerting_read": {
                  "actions": ["alerts:read"]
                }
              }
            }
            """);
        assertOK(adminClient().performRequest(putPrivilegeRequest));
    }

    private void createImplicitOnlyRoleAndUserOnQueryCluster() throws IOException {
        final Request putRoleRequest = new Request("PUT", "/_security/role/implicit_alerts_role");
        putRoleRequest.setJsonEntity("""
            {
              "applications": [
                {
                  "application": "kibana-.kibana",
                  "privileges": ["feature_alerting_read"],
                  "resources": ["space:default"]
                }
              ]
            }
            """);
        assertOK(adminClient().performRequest(putRoleRequest));

        final Request putUserRequest = new Request("PUT", "/_security/user/implicit_alerts_user");
        putUserRequest.setJsonEntity(Strings.format("""
            {
              "password": "%s",
              "roles": ["implicit_alerts_role"]
            }""", PASS));
        assertOK(adminClient().performRequest(putUserRequest));
    }
}
