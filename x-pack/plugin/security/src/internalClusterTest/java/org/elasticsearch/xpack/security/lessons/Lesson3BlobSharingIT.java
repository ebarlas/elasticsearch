/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.lessons;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Capture;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Point;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.sameInstance;

/**
 * <h2>Lesson 3: the coordinator shares role descriptor bytes; the receiving node makes a copy per request</h2>
 *
 * <h3>The idea</h3>
 * This asymmetry is the heart of the incident. The two blobs from lesson 2 are {@code BytesReference} objects, and what matters
 * for memory is how many <em>distinct objects</em> exist, not how many requests point at them.
 *
 * <pre>
 *   coordinator (authenticates the request)          data node (receives the shard request)
 *   ───────────────────────────────────────          ──────────────────────────────────────
 *   ApiKeyService.roleDescriptorsBytesCache          AuthenticationContextSerializer.decode(header)
 *     key: hash of the blob's CONTENT                  runs once per request, allocates fresh byte[]s
 *     value: ONE shared BytesReference
 *
 *   N requests ──▶ 1 blob                            N requests ──▶ N blobs
 * </pre>
 *
 * In the staging heap dump, 29,578 exclusive copies of an 8,450 byte blob sat on one node. 13,381 different API keys had been used,
 * all with identical descriptors. Every copy was a decode of what is a single shared instance on the node that authenticated it.
 *
 * <h3>A subtlety about the cache</h3>
 * The coordinator's sharing is not automatic. A key's <em>first</em> request reads the key document from the security index, and
 * that request holds the document's own blob; the cache is filled from it. Later requests are cache hits and get the cached
 * blob. Because the cache is keyed by content, a different key with identical descriptors also hits it, but only from its second
 * request. The test sends four requests to show each case.
 *
 * <h3>What this means for the accounting change</h3>
 * On the data node the blob really is a per-request cost, so the change counts it in full there. On the coordinator the cost is
 * mostly shared, so counting it in full over-reserves (see lesson 4 for the size). That interim over-count is accepted, and a
 * follow-up that interns the blobs on decode would let the estimate skip shared bytes.
 *
 * <h3>Where to set breakpoints</h3>
 * {@code ApiKeyService.ApiKeyDocCache#get} and {@code #putIfNoInvalidationSince} on the coordinator;
 * {@code AuthenticationContextSerializer#decode} on the data node.
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 2, numClientNodes = 0, supportsDedicatedMasters = false)
@TestLogging(reason = "lesson output", value = "org.elasticsearch.xpack.security.lessons:INFO")
public class Lesson3BlobSharingIT extends LessonCase {

    public void testCoordinatorSharesBlobsButReceiverDecodesCopies() throws Exception {
        createIndexOnDataNode();
        step(1, "create two API keys with identical role descriptors");
        final String keyA = createApiKey("fleet-a", fleetLikeRoleDescriptor());
        final String keyB = createApiKey("fleet-b", fleetLikeRoleDescriptor());

        // Request 1: key A, first use. The key document is read from the security index and the cache is seeded from it.
        // Request 2: key A again. Cache hit: the blob comes from the content-keyed cache.
        // Request 3: key B, first use. Its document is read from the index, so this request holds that document's own blob.
        // Request 4: key B again. Cache hit, and B's descriptors hash the same as A's, so it receives A's blob.
        step(2, "send four bulks: A, A, B, B");
        as(coordinator(), keyA).bulk(oneDocumentBulk()).actionGet();
        as(coordinator(), keyA).bulk(oneDocumentBulk()).actionGet();
        as(coordinator(), keyB).bulk(oneDocumentBulk()).actionGet();
        as(coordinator(), keyB).bulk(oneDocumentBulk()).actionGet();

        step(3, "collect the blob each request held, on the coordinator and on the data node");
        final List<BytesReference> onCoordinator = blobs(LessonProbe.captures(Point.SENT, LessonProbe.BULK_SHARD));
        final List<BytesReference> onDataNode = blobs(LessonProbe.captures(Point.RECEIVED, LessonProbe.BULK_SHARD_PRIMARY));
        assertThat(onCoordinator.size(), equalTo(4));
        assertThat(onDataNode.size(), equalTo(4));

        // The identity hash codes are what to compare in a debugger: equal on the coordinator where the object is shared, all
        // different on the data node.
        say("coordinator blob identities: %s %s %s %s", id(onCoordinator.get(0)), id(onCoordinator.get(1)), id(onCoordinator.get(2)), id(onCoordinator.get(3)));
        say("data node blob identities:   %s %s %s %s", id(onDataNode.get(0)), id(onDataNode.get(1)), id(onDataNode.get(2)), id(onDataNode.get(3)));

        // Coordinator: 1 and 2 share A's blob. 3 holds B's own document blob. 4 shares A's blob again, across keys.
        claim("coordinator: A's second and B's second request share A's blob; B's first request does not");
        assertThat(onCoordinator.get(1), sameInstance(onCoordinator.get(0)));
        assertThat(onCoordinator.get(2), not(sameInstance(onCoordinator.get(0))));
        assertThat(onCoordinator.get(3), sameInstance(onCoordinator.get(0)));

        // Data node: the contents are equal to the coordinator's, but each request decoded its own byte[]. Four requests, four blobs.
        claim("data node: equal contents, but four distinct objects");
        for (int i = 0; i < 4; i++) {
            assertThat(onDataNode.get(i), equalTo(onCoordinator.get(0)));
            for (int j = 0; j < i; j++) {
                assertThat(onDataNode.get(i), not(sameInstance(onDataNode.get(j))));
            }
        }
        say("blob bytes per request on the data node=%d", onDataNode.get(0).length());
        takeaway("the coordinator shares blobs once its cache is warm; every request on the data node pays for its own copy");
    }

    /** The role descriptor blob of each API key request. Other writes (the security index itself) are not API key requests. */
    private static List<BytesReference> blobs(List<Capture> captures) {
        final List<BytesReference> blobs = new ArrayList<>();
        for (Capture capture : captures) {
            if (capture.authentication() != null && capture.authentication().isApiKey()) {
                blobs.add(Lesson2AuthenticationAnatomyIT.blob(capture.authentication()));
            }
        }
        return blobs;
    }

    private static String id(Object o) {
        return "@" + Integer.toHexString(System.identityHashCode(o));
    }
}
