/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.lessons;

import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.unit.ByteSizeValue;
import org.elasticsearch.index.IndexingPressure;
import org.elasticsearch.index.stats.IndexingPressureStats;
import org.elasticsearch.rest.RestStatus;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Capture;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Point;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;

/**
 * <h2>Lesson 6: the incident in miniature</h2>
 *
 * <h3>What happened in staging</h3>
 * The OOM was not caused by a big request. About 30,000 <em>tiny</em> requests were in flight at once, one per Fleet agent. Each
 * agent had its own API key (so 13,381 distinct keys) but all with identical role descriptors. Every request sat in a write queue
 * waiting for a thread, pinning a ~29 KB context on the receiving node. Counted payload was 372 MB; uncounted context was 874 MB.
 * The heap filled while back-pressure, which only saw the 372 MB, never fired.
 *
 * <pre>
 *   30,000 requests × ( payload ~12 KB  +  context ~29 KB )
 *                       └─ counted ─┘      └─ NOT counted, until this change
 * </pre>
 *
 * <h3>The reproduction</h3>
 * 30 distinct Fleet-like keys each send one tiny bulk. {@link LessonProbe} <em>parks</em> every primary-phase operation: it
 * keeps the operation and its thread context in a queue instead of running it, exactly what a saturated write thread pool does.
 * The data node has a primary limit of 200 KB, about 25 times the 7.8 KB of payload all 30 requests add up to.
 * <ul>
 *   <li><b>Before the change</b>: nothing would be rejected. All 30 contexts (~700 KB of heap) would pile up under a 200 KB limit
 *       that only looks at ~8 KB.</li>
 *   <li><b>With the change</b>: each admitted request is charged ~23.6 KB, the limit is reached after 8, and the other 22 are
 *       rejected with 429 instead of piling up. That is the safety net.</li>
 * </ul>
 *
 * <p>This is also why the primary reservation is the right place to count the context on the receiving node: the primary check
 * happens before the operation is queued, so a rejected request never gets as far as pinning its context in the queue.
 *
 * <h3>A note on how the parking works</h3>
 * The primary reservation is released <em>before</em> the response is sent ({@code ActionListener.runBefore(..., releasable::close)}
 * in {@code TransportReplicationAction#handleOperationRequest}), so holding the response would not hold the reservation. The probe
 * therefore parks the later {@code [p]} step, after the reservation has been taken.
 *
 * <h3>Where to set breakpoints</h3>
 * The parking branch in {@code LessonProbe} (see the queued runnable hold its context), then
 * {@code IndexingPressure#validateAndMarkPrimaryOperationStarted} when the limit is hit.
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 2, numClientNodes = 0, supportsDedicatedMasters = false)
@TestLogging(reason = "lesson output", value = "org.elasticsearch.xpack.security.lessons:INFO")
public class Lesson6AmplificationIT extends LessonCase {

    private static final ByteSizeValue PRIMARY_LIMIT = ByteSizeValue.ofKb(200);
    private static final int AGENTS = 30;

    @Override
    protected Settings nodeSettings(int nodeOrdinal, Settings otherSettings) {
        return Settings.builder()
            .put(super.nodeSettings(nodeOrdinal, otherSettings))
            .put(IndexingPressure.MAX_PRIMARY_BYTES.getKey(), PRIMARY_LIMIT)
            .build();
    }

    public void testParkedRequestsFillThePrimaryLimit() throws Exception {
        step(1, "create 30 API keys with identical descriptors; the primary limit is 200 KB");
        createIndexOnDataNode();
        final List<String> agentKeys = new ArrayList<>();
        for (int i = 0; i < AGENTS; i++) {
            agentKeys.add(createApiKey("agent-" + i, fleetLikeRoleDescriptor()));
        }
        // Authenticate each key once so every key document is cached, then forget what the probe recorded.
        for (String key : agentKeys) {
            as(coordinator(), key).bulk(oneDocumentBulk()).actionGet();
        }
        LessonProbe.reset();
        final IndexingPressureStats before = pressure(dataNode()).stats();

        // From here on, every primary-phase operation is parked instead of executed.
        step(2, "park primary-phase operations as a saturated write queue would, then fire 30 tiny bulks");
        LessonProbe.parkPrimaryOperations(true);
        final long payloadPerRequest = oneDocumentBulk().ramBytesUsed();
        final List<PlainActionFuture<BulkResponse>> responses = new ArrayList<>();
        for (String key : agentKeys) {
            final PlainActionFuture<BulkResponse> future = new PlainActionFuture<>();
            as(coordinator(), key).bulk(oneDocumentBulk(), future);
            responses.add(future);
        }

        step(3, "wait until every request is either parked or rejected");
        // Each request ends up in exactly one of two places: parked (the primary check admitted it) or rejected by that check.
        // Wait until all 30 are accounted for.
        assertBusy(() -> {
            final long rejected = pressure(dataNode()).stats().getPrimaryRejections() - before.getPrimaryRejections();
            assertThat(LessonProbe.parkedOperations() + rejected, equalTo((long) AGENTS));
        });

        final IndexingPressureStats held = pressure(dataNode()).stats();
        final int admitted = LessonProbe.parkedOperations();
        final long rejected = held.getPrimaryRejections() - before.getPrimaryRejections();
        final List<Capture> parked = LessonProbe.captures(Point.RECEIVED, LessonProbe.BULK_SHARD_PRIMARY);
        final long retainedContext = parked.stream().mapToLong(Capture::contextBytes).sum();
        say("primaryLimit=%d payloadOfAll=%d", PRIMARY_LIMIT.getBytes(), AGENTS * payloadPerRequest);
        say("admitted=%d rejected=%d", admitted, rejected);
        say("currentPrimaryBytes=%d retainedContextOfParked=%d perAdmitted=%d", held.getCurrentPrimaryBytes(), retainedContext, retainedContext / Math.max(admitted, 1));

        claim("the payload alone could never reach the limit, yet contexts did: some admitted, the rest rejected with 429");
        assertThat(AGENTS * payloadPerRequest, lessThan(PRIMARY_LIMIT.getBytes() / 10));
        assertThat(rejected, greaterThan(0L));
        assertThat(admitted, greaterThan(0));
        assertThat(held.getCurrentPrimaryBytes(), lessThan(PRIMARY_LIMIT.getBytes() + 40_000L));

        // Release the parked operations. The admitted ones complete normally, the rejected ones had already failed with 429 at the
        // coordinator, and every reservation is returned.
        step(4, "release the parked operations and collect the outcomes");
        LessonProbe.parkPrimaryOperations(false);
        LessonProbe.releaseParked();
        int succeeded = 0;
        int rejectedItems = 0;
        for (PlainActionFuture<BulkResponse> future : responses) {
            final BulkResponse response = future.actionGet();
            for (BulkItemResponse item : response.getItems()) {
                if (item.isFailed()) {
                    assertThat(item.getFailure().getStatus(), equalTo(RestStatus.TOO_MANY_REQUESTS));
                    rejectedItems++;
                } else {
                    succeeded++;
                }
            }
        }
        say("succeeded=%d failedWith429=%d", succeeded, rejectedItems);
        assertThat(succeeded, equalTo(admitted));
        assertThat((long) rejectedItems, equalTo(rejected));
        assertBusy(() -> assertThat(pressure(dataNode()).stats().getCurrentPrimaryBytes(), equalTo(0L)));
        takeaway("with the context counted, the node sheds load at the primary check instead of queueing 30 pinned contexts");
    }
}
