/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.lessons;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.lucene.util.RamUsageEstimator;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.IndexingPressure;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.test.SecurityIntegTestCase;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xpack.core.security.action.apikey.CreateApiKeyRequestBuilder;
import org.elasticsearch.xpack.core.security.action.apikey.CreateApiKeyResponse;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.junit.After;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import static org.elasticsearch.test.hamcrest.ElasticsearchAssertions.assertAcked;
import static org.elasticsearch.test.SecuritySettingsSource.ES_TEST_ROOT_USER;
import static org.elasticsearch.test.SecuritySettingsSourceField.TEST_PASSWORD_SECURE_STRING;
import static org.elasticsearch.xpack.core.security.authc.support.UsernamePasswordToken.basicAuthHeaderValue;

/**
 * Lesson scaffolding (temporary). Every lesson runs the same two-node, single-process cluster with security enabled and the
 * {@link LessonProbe} installed, so that a lesson reads as a short script: set up a key, send a bulk, look at what happened.
 *
 * <p>Topology: node 0 is the <b>coordinator</b> (the lesson sends its bulk here) and holds no shard; node 1 is the <b>data node</b>
 * holding the single primary of {@link #INDEX}. Every bulk therefore crosses the transport once, which is the path the
 * accounting change cares about.
 *
 * <p>Read the lessons in the IDE: the narrative is in the Javadoc and comments. The console is the running commentary alongside
 * it, in a fixed tag vocabulary (see {@link #say} and the helpers around it) designed to be filtered with {@code .*LESSON.*} and
 * highlighted per tag.
 */
public abstract class LessonCase extends SecurityIntegTestCase {

    static final Logger logger = LogManager.getLogger("org.elasticsearch.xpack.security.lessons");
    static final String INDEX = "lesson-idx";

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        final List<Class<? extends Plugin>> plugins = new ArrayList<>(super.nodePlugins());
        plugins.add(LessonProbe.class);
        return List.copyOf(plugins);
    }

    @Override
    protected boolean addMockHttpTransport() {
        return false; // real HTTP, for the lessons that use the REST layer
    }

    @Before
    public void resetLessonProbe() {
        LessonProbe.reset();
    }

    @After
    public void releaseLessonProbe() {
        LessonProbe.releaseParked();
        LessonProbe.reset();
    }

    // ---- topology ---------------------------------------------------------------------------------------------------------

    static String coordinator() {
        return internalCluster().getNodeNames()[0];
    }

    static String dataNode() {
        return internalCluster().getNodeNames()[1];
    }

    static ThreadContext threadContext(String node) {
        return internalCluster().getInstance(ThreadPool.class, node).getThreadContext();
    }

    static IndexingPressure pressure(String node) {
        return internalCluster().getInstance(IndexingPressure.class, node);
    }

    /** Creates {@link #INDEX} with one primary, no replicas, pinned to the data node. */
    void createIndexOnDataNode() {
        assertAcked(
            asRoot(coordinator()).admin()
                .indices()
                .prepareCreate(INDEX)
                .setSettings(indexSettings(1, 0).put("index.routing.allocation.require._name", dataNode()))
        );
        ensureGreen(INDEX);
    }

    /** Creates {@link #INDEX} with its primary on the coordinator, so the whole write is node-local. */
    void createIndexOnCoordinator() {
        assertAcked(
            asRoot(coordinator()).admin()
                .indices()
                .prepareCreate(INDEX)
                .setSettings(indexSettings(1, 0).put("index.routing.allocation.require._name", coordinator()))
        );
        ensureGreen(INDEX);
    }

    // ---- identities -------------------------------------------------------------------------------------------------------

    static String rootAuthorization() {
        return basicAuthHeaderValue(ES_TEST_ROOT_USER, TEST_PASSWORD_SECURE_STRING);
    }

    static Client asRoot(String node) {
        return as(node, rootAuthorization());
    }

    /** A node client that runs every request with the given {@code Authorization} header, going through security as REST would. */
    static Client as(String node, String authorization) {
        return internalCluster().client(node).filterWithHeader(Map.of("Authorization", authorization));
    }

    /** Creates an API key owned by the root user and returns the {@code Authorization} header value that authenticates as it. */
    String createApiKey(String name, RoleDescriptor... roleDescriptors) {
        final CreateApiKeyResponse response = new CreateApiKeyRequestBuilder(asRoot(coordinator())).setName(name)
            .setRoleDescriptors(List.of(roleDescriptors))
            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
            .get();
        return "ApiKey "
            + Base64.getEncoder()
                .encodeToString((response.getId() + ":" + new String(response.getKey().getChars())).getBytes(StandardCharsets.UTF_8));
    }

    /** A small role descriptor, what a hand-made key typically carries. */
    static RoleDescriptor smallRoleDescriptor() {
        return new RoleDescriptor(
            "small",
            new String[] { "monitor" },
            new RoleDescriptor.IndicesPrivileges[] { RoleDescriptor.IndicesPrivileges.builder().indices("lesson-*").privileges("all").build() },
            null
        );
    }

    /**
     * A role descriptor shaped like a Fleet agent policy's: many per-integration data stream patterns, each with the same pair of
     * privileges. About 8 KB of JSON, like the 8,450 byte blob found in the heap dump.
     */
    static RoleDescriptor fleetLikeRoleDescriptor() {
        final List<RoleDescriptor.IndicesPrivileges> privileges = new ArrayList<>();
        privileges.add(RoleDescriptor.IndicesPrivileges.builder().indices("lesson-*").privileges("all").build());
        for (int i = 0; i < 70; i++) {
            privileges.add(
                RoleDescriptor.IndicesPrivileges.builder()
                    .indices("logs-integration" + i + ".dataset-*")
                    .privileges("auto_configure", "create_doc")
                    .build()
            );
        }
        return new RoleDescriptor(
            "fleet-like",
            new String[] { "monitor" },
            privileges.toArray(RoleDescriptor.IndicesPrivileges[]::new),
            null
        );
    }

    // ---- requests ---------------------------------------------------------------------------------------------------------

    static BulkRequest oneDocumentBulk() {
        final BulkRequest bulk = new BulkRequest();
        bulk.add(new IndexRequest(INDEX).source(Map.of("field", "value")));
        return bulk;
    }

    // ---- printing ---------------------------------------------------------------------------------------------------------

    /**
     * <b>The console vocabulary.</b> Every line a lesson prints starts with {@code LESSON | <TAG> |} so that an IDE console filter
     * of {@code .*LESSON.*} keeps only lesson lines and a highlighter per tag makes them scannable. The Javadoc tells the story; these
     * lines are the running commentary that lets you follow it while the test executes.
     * <pre>
     *   STEP n     a checkpoint, mirroring the "Step n" comment in the code
     *   SUBJECT    the thing about to be described, e.g. one identity's Authentication
     *   OBSERVE    an observed value, as key=value pairs
     *   CLAIM      what the assertion that follows is about to prove (printed before it, so a failure shows what was being claimed)
     *   TAKEAWAY   the conclusion to carry away
     * </pre>
     */
    private static void emit(String tag, String format, Object... args) {
        logger.info("LESSON | {} | {}", tag, String.format(java.util.Locale.ROOT, format, args));
    }

    static void step(int number, String format, Object... args) {
        emit("STEP " + number, format, args);
    }

    static void subject(String format, Object... args) {
        emit("SUBJECT", format, args);
    }

    /** Emits one observed value, e.g. {@code say("held=%s", bytes(n))}. */
    static void say(String format, Object... args) {
        emit("OBSERVE", format, args);
    }

    static void claim(String format, Object... args) {
        emit("CLAIM", format, args);
    }

    static void takeaway(String format, Object... args) {
        emit("TAKEAWAY", format, args);
    }

    static String bytes(long bytes) {
        return String.format(java.util.Locale.ROOT, "%,d B (%.1f KB)", bytes, bytes / 1024.0);
    }

    /** What Latin-1 string sizing means for a header value: object header plus one byte per character. */
    static long latin1StringBytes(String string) {
        return RamUsageEstimator.shallowSizeOfInstance(String.class) + RamUsageEstimator.alignObjectSize(
            RamUsageEstimator.NUM_BYTES_ARRAY_HEADER + string.length()
        );
    }

    /** Prints the parts of an Authentication that matter for memory: who, how, and what its subject metadata carries. */
    static void describe(String label, Authentication authentication) throws Exception {
        subject("%s", label);
        say("    authentication type ...... %s", authentication.getAuthenticationType());
        say("    effective user ........... %s", authentication.getEffectiveSubject().getUser().principal());
        say(
            "    authenticated by realm ... %s [%s]",
            authentication.getAuthenticatingSubject().getRealm().getName(),
            authentication.getAuthenticatingSubject().getRealm().getType()
        );
        final Map<String, Object> metadata = new TreeMap<>(authentication.getAuthenticatingSubject().getMetadata());
        say("    subject metadata ......... %d entries", metadata.size());
        for (Map.Entry<String, Object> entry : metadata.entrySet()) {
            final Object value = entry.getValue();
            final String shape = value instanceof BytesReference ref
                ? "BytesReference, " + bytes(ref.length()) + "  <-- identity " + Integer.toHexString(System.identityHashCode(ref))
                : value instanceof String s ? "String, " + s.length() + " chars" : String.valueOf(value);
            say("        %-45s %s", entry.getKey(), shape);
        }
        say("    encode() header length ... %s chars", String.format(java.util.Locale.ROOT, "%,d", authentication.encode().length()));
        say("    ramBytesUsed() ........... %s", bytes(authentication.ramBytesUsed()));
    }
}
