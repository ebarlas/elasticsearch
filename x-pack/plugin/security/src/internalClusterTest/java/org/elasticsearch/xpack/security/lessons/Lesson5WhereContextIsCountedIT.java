/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.lessons;

import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.index.stats.IndexingPressureStats;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Capture;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Point;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThan;

/**
 * <h2>Lesson 5: indexing pressure, and where the request context is counted</h2>
 *
 * <h3>The idea</h3>
 * Every node has an {@code IndexingPressure} that tracks the bytes of write work currently in flight, in three buckets, and
 * rejects new work (HTTP 429) when a limit would be exceeded:
 * <table>
 *   <caption>IndexingPressure buckets</caption>
 *   <tr><th>bucket</th><th>charged on</th><th>held for</th></tr>
 *   <tr><td>coordinating</td><td>the node that received the bulk from the client</td><td>the whole request, until the response</td></tr>
 *   <tr><td>primary</td><td>the node executing the write on the primary shard</td><td>until the primary phase answers</td></tr>
 *   <tr><td>replica</td><td>nodes applying the write to a replica</td><td>until the replica write finishes</td></tr>
 * </table>
 * Each bucket has a monotonically increasing {@code total*Bytes} counter and a {@code current*Bytes} gauge. Before the change all
 * three counted the request <em>payload</em> only.
 *
 * <h3>What the change adds</h3>
 * <pre>
 *   coordinating  += payload + estimatedRequestContextBytes()      (TransportAbstractBulkAction)
 *   primary       += shard request + estimatedRequestContextBytes()  ONLY when the request arrived over the network
 *                                                                    (TransportWriteAction#checkOperationLimits)
 * </pre>
 * The rule is "count a context once per copy that actually exists on the heap".
 * <ul>
 *   <li>Coordinator and primary on <b>different nodes</b>: two copies exist (lesson 1), each node counts its own. Test A.</li>
 *   <li>Coordinator and primary on <b>the same node</b>: the primary phase loops back through a local reroute using the
 *       coordinating request's own context, so there is one copy. {@code checkPrimaryLimits} deliberately returns nothing for
 *       that case, and counting again would double-charge. Test B.</li>
 * </ul>
 *
 * <p>Both tests read the {@code total*Bytes} counters before and after a single bulk, so no request needs to be held in flight
 * (lesson 6 does that).
 *
 * <h3>Where to set breakpoints</h3>
 * {@code TransportAbstractBulkAction#doRun} (coordinating), {@code TransportWriteAction#checkOperationLimits} (network-received
 * primary), {@code TransportWriteAction#checkPrimaryLimits} (the local-reroute branches that add nothing) and
 * {@code IndexingPressure#markCoordinatingOperationStarted}.
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 2, numClientNodes = 0, supportsDedicatedMasters = false)
@TestLogging(reason = "lesson output", value = "org.elasticsearch.xpack.security.lessons:INFO")
public class Lesson5WhereContextIsCountedIT extends LessonCase {

    /**
     * <b>Test A: coordinator and primary on different nodes</b>
     * Expected arithmetic. These figures are from one run; the exact bytes vary a little with the cluster, but the relationships hold:
     * <pre>
     *   coordinator.totalCoordinatingBytes += payload (266) + context (23,208)       = 23,474
     *   dataNode.totalPrimaryBytes         += shard request (426) + context (23,208) = 23,634
     * </pre>
     * The same request is charged about 23 KB on <em>each</em> node because each node really holds its own ~23 KB copy.
     */
    public void testCoordinatorAndRemotePrimaryEachCountTheirOwnContext() throws Exception {
        step(1, "coordinator is node 0, the primary shard lives on node 1");
        createIndexOnDataNode();
        final String fleetKey = createApiKey("fleet-like", fleetLikeRoleDescriptor());
        // Warm the key so the measured request is a steady-state one (key document cached on the coordinator), then forget what
        // the probe recorded and take the "before" readings.
        as(coordinator(), fleetKey).bulk(oneDocumentBulk()).actionGet();
        LessonProbe.reset();

        step(2, "read the counters on both nodes before the measured request");
        final IndexingPressureStats coordinatorBefore = pressure(coordinator()).stats();
        final IndexingPressureStats dataNodeBefore = pressure(dataNode()).stats();

        step(3, "send one Fleet-like bulk");
        final BulkRequest bulk = oneDocumentBulk();
        final long payload = bulk.ramBytesUsed();
        as(coordinator(), fleetKey).bulk(bulk).actionGet();

        final IndexingPressureStats coordinatorAfter = pressure(coordinator()).stats();
        final IndexingPressureStats dataNodeAfter = pressure(dataNode()).stats();
        final long coordinatingDelta = coordinatorAfter.getTotalCoordinatingBytes() - coordinatorBefore.getTotalCoordinatingBytes();
        final long primaryDelta = dataNodeAfter.getTotalPrimaryBytes() - dataNodeBefore.getTotalPrimaryBytes();

        // The probe's estimates are taken from the same thread contexts the reservations were taken from. SENT is the coordinator's
        // context; the primary-phase RECEIVED capture is the data node's, with the decoded Authentication already in place.
        final Capture sent = LessonProbe.captures(Point.SENT, LessonProbe.BULK_SHARD).getFirst();
        final Capture primaryPhase = LessonProbe.captures(Point.RECEIVED, LessonProbe.BULK_SHARD_PRIMARY).getFirst();
        say("payload=%d", payload);
        say("context estimate: coordinator=%d dataNode=%d", sent.contextBytes(), primaryPhase.contextBytes());
        say("coordinator totalCoordinatingBytes delta=%d", coordinatingDelta);
        say("dataNode totalPrimaryBytes delta=%d", primaryDelta);
        say("dataNode totalCoordinatingBytes delta=%d", dataNodeAfter.getTotalCoordinatingBytes() - dataNodeBefore.getTotalCoordinatingBytes());

        claim("coordinator is charged payload + its context; the remote primary is charged shard request + its own context");
        assertThat(coordinatingDelta, greaterThanOrEqualTo(payload + sent.contextBytes()));
        assertThat(primaryDelta, greaterThan(primaryPhase.contextBytes()));
        takeaway("each node counts the copy of the context that it holds");
    }

    /**
     * <b>Test B: coordinator and primary on the same node</b>
     * No shard request crosses the network (the probe sees no {@code SENT}), so there is exactly one context in the JVM. It is
     * counted once, as part of the coordinating reservation. {@code totalPrimaryBytes} still grows, but only by the small shard
     * request (426 bytes), not by another ~23 KB.
     */
    public void testLocalPrimaryDoesNotCountTheSameContextTwice() throws Exception {
        step(1, "the primary shard lives on the coordinator: no network hop");
        createIndexOnCoordinator();
        final String fleetKey = createApiKey("fleet-like", fleetLikeRoleDescriptor());
        as(coordinator(), fleetKey).bulk(oneDocumentBulk()).actionGet();
        LessonProbe.reset();

        step(2, "read the counters, then send one Fleet-like bulk");
        final IndexingPressureStats before = pressure(coordinator()).stats();
        final BulkRequest bulk = oneDocumentBulk();
        final long payload = bulk.ramBytesUsed();
        as(coordinator(), fleetKey).bulk(bulk).actionGet();
        final IndexingPressureStats after = pressure(coordinator()).stats();

        final long coordinatingDelta = after.getTotalCoordinatingBytes() - before.getTotalCoordinatingBytes();
        final long primaryDelta = after.getTotalPrimaryBytes() - before.getTotalPrimaryBytes();
        final Capture primaryPhase = LessonProbe.captures(Point.RECEIVED, LessonProbe.BULK_SHARD_PRIMARY).getFirst();
        say("payload=%d context=%d", payload, primaryPhase.contextBytes());
        say("totalCoordinatingBytes delta=%d totalPrimaryBytes delta=%d", coordinatingDelta, primaryDelta);

        claim("the context is charged once on the coordinating side; the local primary adds only the shard request");
        assertThat(coordinatingDelta, greaterThanOrEqualTo(payload + primaryPhase.contextBytes() / 2));
        assertThat(primaryDelta, lessThan(primaryPhase.contextBytes() / 2));
        assertThat(LessonProbe.captures(Point.SENT, LessonProbe.BULK_SHARD).size(), equalTo(0));
        takeaway("one copy of the context in the JVM, counted once");
    }
}
