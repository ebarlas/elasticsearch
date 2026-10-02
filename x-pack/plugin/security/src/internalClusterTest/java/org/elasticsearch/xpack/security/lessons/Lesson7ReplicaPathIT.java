/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.lessons;

import org.elasticsearch.index.stats.IndexingPressureStats;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Capture;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Point;

import static org.elasticsearch.test.hamcrest.ElasticsearchAssertions.assertAcked;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

/**
 * <h2>Lesson 7: the replica path</h2>
 *
 * <h3>The idea</h3>
 * With a replica, the node holding the primary forwards the write to the replica node over the transport, carrying the request
 * headers including the encoded authentication. So the replica node holds its own copy of the context for as long as the replica
 * write is in flight, exactly like a network-received primary:
 * <pre>
 *   coordinator ──bulk[s]──▶ primary node ──bulk[s][r]──▶ replica node
 *      counts context          counts context              counts context
 * </pre>
 * A replica request <em>always</em> arrives over the network, so unlike the primary there is no local-reroute case to exclude:
 * {@code TransportWriteAction#checkReplicaLimits} adds the context estimate unconditionally.
 *
 * <h3>History</h3>
 * The first version of the change covered the coordinating and primary reservations only, and this lesson asserted that the
 * replica node counted none of its context, to document the gap. Closing the gap took one line, and the same test then reported
 * the replica node's {@code totalReplicaBytes} growing from a few hundred bytes to the size of the context. It now asserts the
 * opposite. Serverless has no replicas, so this matters for stateful clusters.
 *
 * <h3>Where to set breakpoints</h3>
 * {@code TransportWriteAction#checkReplicaLimits} and {@code IndexingPressure#markReplicaOperationStarted}.
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 2, numClientNodes = 0, supportsDedicatedMasters = false)
@TestLogging(reason = "lesson output", value = "org.elasticsearch.xpack.security.lessons:INFO")
public class Lesson7ReplicaPathIT extends LessonCase {

    private static final String REPLICA_ACTION = LessonProbe.BULK_SHARD + "[r]";

    public void testReplicaRequestsCountTheirContext() throws Exception {
        step(1, "one shard with one replica: primary and replica on different nodes");
        // One shard, one replica: with two nodes the primary and the replica necessarily land on different nodes.
        assertAcked(asRoot(coordinator()).admin().indices().prepareCreate(INDEX).setSettings(indexSettings(1, 1)));
        ensureGreen(INDEX);
        final String fleetKey = createApiKey("fleet-like", fleetLikeRoleDescriptor());
        as(coordinator(), fleetKey).bulk(oneDocumentBulk()).actionGet();
        LessonProbe.reset();
        LessonProbe.watch(REPLICA_ACTION);

        step(2, "send one Fleet-like bulk and watch the replica node");
        final IndexingPressureStats[] before = { pressure(coordinator()).stats(), pressure(dataNode()).stats() };
        as(coordinator(), fleetKey).bulk(oneDocumentBulk()).actionGet();
        final IndexingPressureStats[] after = { pressure(coordinator()).stats(), pressure(dataNode()).stats() };

        // The probe records the replica request arriving, on whichever node holds the replica. The capture is taken before security
        // has decoded the Authentication, so its estimate is the headers alone (the encoded authentication string): a lower bound
        // on the context that node really holds, and so on what it should be charged.
        final Capture replicaArrival = LessonProbe.captures(Point.RECEIVED, REPLICA_ACTION).getFirst();
        final int replicaNode = replicaArrival.node().equals(coordinator()) ? 0 : 1;
        final long replicaDelta = after[replicaNode].getTotalReplicaBytes() - before[replicaNode].getTotalReplicaBytes();
        say("replica node=%s headersOnlyContext=%d", replicaArrival.node(), replicaArrival.contextBytes());
        say("replica totalReplicaBytes delta=%d", replicaDelta);
        claim("the replica node is charged at least the headers it holds, plus the decoded Authentication and the request itself");
        assertThat(replicaDelta, greaterThanOrEqualTo(replicaArrival.contextBytes()));
        takeaway("a replica request always arrives over the network, so it always counts its own context copy");
    }
}
