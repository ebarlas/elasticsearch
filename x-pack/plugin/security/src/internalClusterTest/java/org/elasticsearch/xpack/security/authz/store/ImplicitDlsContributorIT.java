/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz.store;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.search.SearchResponse;
import org.elasticsearch.action.search.TransportSearchAction;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.query.QueryBuilders;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.script.mustache.MustachePlugin;
import org.elasticsearch.search.SearchHit;
import org.elasticsearch.search.builder.SearchSourceBuilder;
import org.elasticsearch.test.SecurityIntegTestCase;
import org.elasticsearch.test.SecuritySettingsSource;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.ClientHelper;
import org.elasticsearch.xpack.core.security.SecurityExtension;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesAction;
import org.elasticsearch.xpack.core.security.action.privilege.PutPrivilegesRequest;
import org.elasticsearch.xpack.core.security.action.role.PutRoleRequestBuilder;
import org.elasticsearch.xpack.core.security.action.user.PutUserRequestBuilder;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.store.ImplicitPrivilegesProvider;
import org.elasticsearch.xpack.core.security.authz.store.UserMetadataContributor;
import org.elasticsearch.xpack.security.LocalStateSecurity;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.elasticsearch.test.SecuritySettingsSourceField.TEST_PASSWORD_SECURE_STRING;
import static org.elasticsearch.xpack.core.ClientHelper.SECURITY_ORIGIN;
import static org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken.BASIC_AUTH_HEADER;
import static org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken.basicAuthHeaderValue;
import static org.hamcrest.Matchers.equalTo;

/**
 * Integration test exercising the full implicit-DLS-with-metadata-contributor flow end to end:
 * <ol>
 *   <li>An {@link ImplicitPrivilegesProvider} inspects a role's Kibana application privileges
 *       and, when it finds {@code kibana-.kibana / ml_read} granted on {@code space:<name>}
 *       resources, synthesizes an in-memory {@link RoleDescriptor.IndicesPrivileges} for the
 *       {@code ml_results} index.</li>
 *   <li>The synthesized privilege carries (a) a templated DLS query
 *       {@code {"terms": {"ml_job_id": {{#toJson}}_user.metadata._ml_job_ids{{/toJson}}}}}
 *       and (b) a {@link UserMetadataContributor} closed over the resolved space ids.</li>
 *   <li>At authorization time, the contributor runs a {@code SECURITY_ORIGIN}-scoped search
 *       against {@code ml_jobs} for jobs whose {@code namespaces} field contains any of the
 *       user's spaces, returning the discovered job ids as {@code _ml_job_ids} metadata.</li>
 *   <li>The DLS template is then rendered against the enriched user metadata and applied to
 *       the {@code ml_results} search, scoping the results to the user's space.</li>
 * </ol>
 * The user is granted only the application privilege at role-PUT time -- no explicit indices
 * privileges. All access to {@code ml_results} flows through the implicit privilege.
 */
public class ImplicitDlsContributorIT extends SecurityIntegTestCase {

    static final String KIBANA_APPLICATION = "kibana-.kibana";
    static final String ML_READ_PRIVILEGE_NAME = "ml_read";
    static final String ML_READ_ACTION = "ml:read";
    static final String SPACE_RESOURCE_PREFIX = "space:";

    private static final String ML_JOBS_INDEX = "ml_jobs";
    private static final String ML_RESULTS_INDEX = "ml_results";

    private static final String ML_USER = "ml_user";
    private static final String ML_ROLE = "ml_role";
    private static final String SPACE = "myspace";

    @Override
    protected boolean addMockHttpTransport() {
        return false;
    }

    @Override
    protected Settings nodeSettings(int nodeOrdinal, Settings otherSettings) {
        // The new chunked fetch phase introduces an `internal:data/read/search/fetch/coordination`
        // sub-action that the standard `read` IndexPrivilege automaton does not match
        // (`indices:data/read/*`). Until that is reconciled, disable the chunked fetch phase so
        // the user's implicit `read` on `ml_results` covers the whole search. See
        // SearchService#FETCH_PHASE_CHUNKED_ENABLED.
        return Settings.builder()
            .put(super.nodeSettings(nodeOrdinal, otherSettings))
            .put("search.fetch_phase_chunked_enabled", false)
            .build();
    }

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        final List<Class<? extends Plugin>> plugins = new ArrayList<>(super.nodePlugins());
        plugins.remove(LocalStateSecurity.class);
        plugins.add(LocalStateWithImplicitDlsExtension.class);
        plugins.add(MustachePlugin.class);
        return List.copyOf(plugins);
    }

    @Override
    protected Class<?> xpackPluginClass() {
        return LocalStateWithImplicitDlsExtension.class;
    }

    public void testImplicitDlsContributorScopesMlResultsToUserSpace() throws Exception {
        registerKibanaMlReadApplicationPrivilege();
        putRoleWithKibanaMlReadOnSpace(ML_ROLE, SPACE);
        putUser(ML_USER, ML_ROLE);
        createMlIndices();
        indexMlJobs();
        indexMlResults();
        refreshMlIndices();

        Client userClient = client().filterWithHeader(
            Map.of(BASIC_AUTH_HEADER, basicAuthHeaderValue(ML_USER, TEST_PASSWORD_SECURE_STRING))
        );

        // Reset right before the request under test so we measure invocations attributable to
        // this single search only. Setup work above (registering privileges, indexing test data)
        // does not authorize against ml_results so it cannot trigger the contributor.
        MlJobIdsContributor.INVOCATION_COUNT.set(0);

        SearchResponse response = userClient.prepareSearch(ML_RESULTS_INDEX).setSize(50).get();
        try {
            if (response.getFailedShards() != 0) {
                StringBuilder sb = new StringBuilder("shard failures:\n");
                for (var f : response.getShardFailures()) {
                    sb.append("  - ").append(f.toString()).append("\n");
                }
                fail(sb.toString());
            }

            Set<String> returnedIds = Arrays.stream(response.getHits().getHits())
                .map(SearchHit::getId)
                .collect(Collectors.toSet());

            // jobs j1 and j2 are in "myspace"; j3 is in "other"; j4 has no namespaces.
            // results r1a, r1b -> j1, r2 -> j2, r3 -> j3, r4 -> j4.
            // Expectation: only the results whose ml_job_id is among the contributor-supplied ids
            // for "myspace" survive the DLS template.
            assertThat(
                "User in space:myspace should see only ml_results docs whose ml_job_id is in jobs[namespaces=myspace]",
                returnedIds,
                equalTo(Set.of("r1a", "r1b", "r2"))
            );
            assertThat(response.getHits().getTotalHits().value(), equalTo(3L));
        } finally {
            response.decRef();
        }

        // Per-request idempotence: every shard sub-action of the search runs through indices
        // authorization (PreAuthorizationUtils disables its parent-skip optimization whenever DLS
        // is in play), but UserMetadataContributors.merge filters out contributors whose declared
        // contributedKeys() are already present in the effective user's metadata. The first
        // authorization on the coordinator runs the contributor and folds _ml_job_ids into the
        // enriched Authentication; every subsequent shard-level authorization sees that key and
        // skips. Anything other than 1 here means the skip path regressed, the contributor stopped
        // declaring its keys, or the enriched Authentication is no longer flowing across hops --
        // all of which would re-introduce N+1 lookups against ml_jobs per user search.
        assertThat(
            "MlJobIdsContributor must run exactly once per user search (skip-on-already-enriched)",
            MlJobIdsContributor.INVOCATION_COUNT.get(),
            equalTo(1)
        );
    }

    private void registerKibanaMlReadApplicationPrivilege() {
        PutPrivilegesRequest putPrivileges = new PutPrivilegesRequest();
        putPrivileges.setPrivileges(
            List.of(
                new ApplicationPrivilegeDescriptor(
                    KIBANA_APPLICATION,
                    ML_READ_PRIVILEGE_NAME,
                    Set.of(ML_READ_ACTION),
                    Map.of()
                )
            )
        );
        client().execute(PutPrivilegesAction.INSTANCE, putPrivileges).actionGet();
    }

    private void putRoleWithKibanaMlReadOnSpace(String roleName, String space) throws java.io.IOException {
        // Role grants ONLY the Kibana application privilege. There is NO explicit indices
        // privilege -- every read on ml_results must flow through the implicit privilege emitted
        // by TestMlImplicitPrivilegesProvider.
        String body = String.format(java.util.Locale.ROOT, """
            {
              "applications": [
                {
                  "application": "%s",
                  "privileges": ["%s"],
                  "resources": ["%s%s"]
                }
              ]
            }
            """, KIBANA_APPLICATION, ML_READ_PRIVILEGE_NAME, SPACE_RESOURCE_PREFIX, space);
        new PutRoleRequestBuilder(client()).source(roleName, new BytesArray(body), XContentType.JSON).get();
    }

    private void putUser(String username, String role) {
        new PutUserRequestBuilder(client()).username(username)
            .password(TEST_PASSWORD_SECURE_STRING, SecuritySettingsSource.HASHER)
            .roles(role)
            .get();
    }

    private void createMlIndices() {
        client().admin()
            .indices()
            .prepareCreate(ML_JOBS_INDEX)
            .setMapping("ml_job_id", "type=keyword", "namespaces", "type=keyword")
            .get();
        client().admin()
            .indices()
            .prepareCreate(ML_RESULTS_INDEX)
            .setMapping("ml_job_id", "type=keyword", "value", "type=keyword")
            .get();
    }

    private void indexMlJobs() {
        client().prepareIndex(ML_JOBS_INDEX).setId("j1").setSource("ml_job_id", "j1", "namespaces", List.of("myspace")).get();
        client().prepareIndex(ML_JOBS_INDEX).setId("j2").setSource("ml_job_id", "j2", "namespaces", List.of("myspace", "other")).get();
        client().prepareIndex(ML_JOBS_INDEX).setId("j3").setSource("ml_job_id", "j3", "namespaces", List.of("other")).get();
        client().prepareIndex(ML_JOBS_INDEX).setId("j4").setSource("ml_job_id", "j4", "namespaces", List.of()).get();
    }

    private void indexMlResults() {
        client().prepareIndex(ML_RESULTS_INDEX).setId("r1a").setSource("ml_job_id", "j1", "value", "v1a").get();
        client().prepareIndex(ML_RESULTS_INDEX).setId("r1b").setSource("ml_job_id", "j1", "value", "v1b").get();
        client().prepareIndex(ML_RESULTS_INDEX).setId("r2").setSource("ml_job_id", "j2", "value", "v2").get();
        client().prepareIndex(ML_RESULTS_INDEX).setId("r3").setSource("ml_job_id", "j3", "value", "v3").get();
        client().prepareIndex(ML_RESULTS_INDEX).setId("r4").setSource("ml_job_id", "j4", "value", "v4").get();
    }

    private void refreshMlIndices() {
        client().admin().indices().prepareRefresh(ML_JOBS_INDEX, ML_RESULTS_INDEX).get();
    }

    /**
     * Test plugin that swaps the default {@link LocalStateSecurity} for one whose
     * {@code securityExtensions()} returns our test extension carrying the
     * {@link TestMlImplicitPrivilegesProvider}.
     */
    public static class LocalStateWithImplicitDlsExtension extends LocalStateSecurity {
        public LocalStateWithImplicitDlsExtension(Settings settings, Path configPath) throws Exception {
            super(settings, configPath);
        }

        @Override
        protected List<SecurityExtension> securityExtensions() {
            return List.of(new TestMlImplicitExtension());
        }
    }

    /** {@link SecurityExtension} that registers the test {@link ImplicitPrivilegesProvider}. */
    public static class TestMlImplicitExtension implements SecurityExtension {
        @Override
        public List<ImplicitPrivilegesProvider> getImplicitPrivilegesProviders(SecurityComponents components) {
            // Capture the node Client so the contributor can search ml_jobs at request time
            // under SECURITY_ORIGIN (which bypasses any DLS that might attach to ml_jobs in
            // production deployments).
            return List.of(new TestMlImplicitPrivilegesProvider(components.client()));
        }
    }

    /**
     * Provider that detects the role's Kibana {@code ml_read} application privileges, extracts
     * the spaces from the {@code space:<name>} resources, and synthesizes a single in-memory
     * {@link RoleDescriptor.IndicesPrivileges} on {@code ml_results} carrying both a templated
     * DLS query and a freshly-constructed {@link UserMetadataContributor} closed over those
     * spaces. A new contributor instance is returned on every call -- the test's contributor
     * does not override {@code equals}, so two such instances would not merge in
     * {@code CompositeRolesStore}; the test only exercises a single role build so this isn't
     * relevant here. Production providers should either cache contributor instances by the
     * spaces key or implement {@code equals}/{@code hashCode} so equivalent contributors merge;
     * see {@code UserMetadataContributor} javadoc.
     */
    public static class TestMlImplicitPrivilegesProvider implements ImplicitPrivilegesProvider {

        private static final String DLS_TEMPLATE_SOURCE =
            "{\"template\":{\"source\":\"{\\\"terms\\\":{\\\"ml_job_id\\\":{{#toJson}}_user.metadata._ml_job_ids{{/toJson}}}}\"}}";

        private final Client client;

        public TestMlImplicitPrivilegesProvider(Client client) {
            this.client = client;
        }

        @Override
        public Collection<RoleDescriptor.IndicesPrivileges> getImplicitIndicesPrivileges(
            RoleDescriptor roleDescriptor,
            Collection<ApplicationPrivilegeDescriptor> storedApplicationPrivileges
        ) {
            Set<String> matchingPrivilegeNames = storedApplicationPrivileges.stream()
                .filter(d -> KIBANA_APPLICATION.equals(d.getApplication()))
                .filter(d -> d.getActions().contains(ML_READ_ACTION))
                .map(ApplicationPrivilegeDescriptor::getName)
                .collect(Collectors.toSet());
            if (matchingPrivilegeNames.isEmpty()) {
                return List.of();
            }

            Set<String> spaces = Stream.of(roleDescriptor.getApplicationPrivileges())
                .filter(p -> KIBANA_APPLICATION.equals(p.getApplication()))
                .filter(p -> Stream.of(p.getPrivileges()).anyMatch(matchingPrivilegeNames::contains))
                .flatMap(p -> Stream.of(p.getResources()))
                .filter(r -> r.startsWith(SPACE_RESOURCE_PREFIX))
                .map(r -> r.substring(SPACE_RESOURCE_PREFIX.length()))
                .collect(Collectors.toSet());
            if (spaces.isEmpty()) {
                return List.of();
            }

            UserMetadataContributor contributor = new MlJobIdsContributor(client, spaces);

            return List.of(
                RoleDescriptor.IndicesPrivileges.builder()
                    .indices(ML_RESULTS_INDEX)
                    .privileges("read")
                    .query(new BytesArray(DLS_TEMPLATE_SOURCE))
                    .metadataContributor(contributor)
                    .build()
            );
        }
    }

    /**
     * Contributes {@code _ml_job_ids} to the effective user's metadata by querying the
     * {@code ml_jobs} index for documents whose {@code namespaces} field intersects the
     * provider-supplied spaces. Runs under {@link ClientHelper#SECURITY_ORIGIN} so the lookup is
     * not itself filtered by any DLS that might apply to {@code ml_jobs} in production.
     * <p>
     * The {@link #contributedKeys()} declaration is what enables the per-request skip in
     * {@code UserMetadataContributors.merge}: once the first authorization on this request has
     * folded {@code _ml_job_ids} into the effective user's metadata, every subsequent indices
     * authorization (per-shard query, per-shard fetch, fetch coordination) sees the key and
     * does not re-invoke the contributor.
     */
    static class MlJobIdsContributor implements UserMetadataContributor {

        static final String CONTRIBUTED_KEY = "_ml_job_ids";

        /**
         * Process-wide counter used by the test to assert the per-request idempotence guarantee.
         * Tests must reset this immediately before the request under measurement.
         */
        static final AtomicInteger INVOCATION_COUNT = new AtomicInteger(0);

        private final Client client;
        private final Set<String> spaces;

        MlJobIdsContributor(Client client, Set<String> spaces) {
            this.client = client;
            this.spaces = spaces;
        }

        @Override
        public Set<String> contributedKeys() {
            return Set.of(CONTRIBUTED_KEY);
        }

        @Override
        public void contribute(ActionListener<Map<String, Object>> listener) {
            INVOCATION_COUNT.incrementAndGet();
            SearchRequest request = new SearchRequest(ML_JOBS_INDEX).source(
                SearchSourceBuilder.searchSource()
                    .query(QueryBuilders.termsQuery("namespaces", spaces.toArray(new String[0])))
                    .fetchSource(new String[] { "ml_job_id" }, null)
                    .size(1000)
            );
            ClientHelper.executeAsyncWithOrigin(
                client,
                SECURITY_ORIGIN,
                TransportSearchAction.TYPE,
                request,
                listener.delegateFailureAndWrap((delegate, response) -> {
                    Set<String> jobIds = new HashSet<>();
                    for (SearchHit hit : response.getHits().getHits()) {
                        Object value = hit.getSourceAsMap().get("ml_job_id");
                        if (value != null) {
                            jobIds.add(value.toString());
                        }
                    }
                    // Sorted for determinism: the rendered DLS template embeds the JSON list
                    // directly into the query, and a stable order keeps the resulting query
                    // (and any downstream cache key) stable across runs.
                    //
                    // We always emit CONTRIBUTED_KEY (with an empty list when there are no
                    // matches) so that the framework's skip-on-already-enriched check in
                    // UserMetadataContributors.merge can recognize this contributor as having
                    // already run on the next authorization. Returning Map.of() on an empty
                    // result would defeat the per-request skip.
                    delegate.onResponse(Map.of(CONTRIBUTED_KEY, new ArrayList<>(new TreeSet<>(jobIds))));
                })
            );
        }
    }
}
