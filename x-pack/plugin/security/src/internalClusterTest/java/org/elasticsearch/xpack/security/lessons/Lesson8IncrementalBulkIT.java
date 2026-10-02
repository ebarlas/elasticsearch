/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.lessons;

import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.bulk.IncrementalBulkService;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.index.IndexingPressure;
import org.elasticsearch.index.stats.IndexingPressureStats;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Point;

import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.lessThan;

/**
 * <h2>Lesson 8: the streaming REST bulk handler, and a reservation that outlives its sub-requests</h2>
 *
 * <h3>The idea</h3>
 * Over REST, a large {@code _bulk} body is streamed in chunks rather than buffered. {@code IncrementalBulkService.Handler}
 * accumulates the items of each chunk and, when back-pressure says the pending work is large enough, <em>splits</em> off a
 * sub-bulk, sends it, and carries on with the next chunk:
 * <pre>
 *   HTTP request (one thread context, alive for the whole stream)
 *     │
 *     ├─ Handler created ........ takes the CONTEXT reservation   ◀── lives until Handler.close()
 *     │
 *     ├─ chunk 1 ─▶ addItems ─▶ maybeSplit ─▶ sub-bulk 1 (own coordinating bytes, released when it completes)
 *     ├─ chunk 2 ─▶ addItems ─▶ maybeSplit ─▶ sub-bulk 2 (same)
 *     └─ last chunk ─▶ lastItems ─▶ final sub-bulk
 *                                   └─ the REST layer then calls Handler.close()
 * </pre>
 * Each sub-bulk's bytes belong to that sub-bulk and are returned when it finishes. But the context belongs to the whole HTTP
 * request. If it were folded into the first sub-bulk's reservation it would be released after the first split while the request,
 * and its context, were still alive. So the handler takes a separate {@code requestContextReservation} at construction and
 * releases it only in {@code close()}. Sub-bulks are marked "already accounted" so {@code TransportAbstractBulkAction} does not
 * reserve the context a second time.
 *
 * <h3>How the lesson imitates REST</h3>
 * No HTTP is involved. A real {@code Authentication} is written into a fresh thread context (as security does when it authenticates
 * a REST request), the handler is created in it, and the context is captured with {@code newRestorableContext} so each later chunk
 * runs in it, as the REST layer does.
 *
 * <h3>A side effect worth knowing</h3>
 * {@code Incremental#maybeSplit} compares <em>node-wide</em> in-flight bytes with watermarks to decide when to split. The context
 * now counts in those bytes, so heavy contexts make bulks split earlier. Test A uses a Fleet-like key whose ~22 KB context is
 * already above a deliberately tiny 10 KB low watermark, so the very first item splits. Test B uses the root user, whose small
 * context stays under the watermark, so the identical bulk does not split. Whether sooner splitting is desirable is a judgment call
 * for the review: more pressure producing smaller sub-bulks is the intent of the watermarks, but it is a behavior change.
 *
 * <h3>Where to set breakpoints</h3>
 * {@code IncrementalBulkService.Handler#<init>} (the two reservations), {@code Handler#addItems},
 * {@code IndexingPressure.Incremental#maybeSplit} and {@code Handler#close}.
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 2, numClientNodes = 0, supportsDedicatedMasters = false)
@TestLogging(reason = "lesson output", value = "org.elasticsearch.xpack.security.lessons:INFO")
public class Lesson8IncrementalBulkIT extends LessonCase {

    @Override
    protected Settings nodeSettings(int nodeOrdinal, Settings otherSettings) {
        return Settings.builder()
            .put(super.nodeSettings(nodeOrdinal, otherSettings))
            // Split as soon as node-wide coordinating bytes reach 10 KB and the handler holds at least one byte of its own.
            .put(IndexingPressure.SPLIT_BULK_LOW_WATERMARK.getKey(), "10KB")
            .put(IndexingPressure.SPLIT_BULK_LOW_WATERMARK_SIZE.getKey(), "1B")
            .build();
    }

    /**
     * <b>Test A: the context reservation survives the split it causes</b>
     * Watch {@code currentCoordinatingBytes} through the handler's life. It is the context estimate right after construction,
     * still exactly that after the split-off sub-bulk has completed (its own bytes returned, the context's not), still that after
     * the final bulk, and zero only after {@code close()}.
     */
    public void testContextReservationOutlivesTheSplitOffSubBulk() throws Exception {
        final Authentication authentication = authenticationOf(createApiKey("fleet-like", fleetLikeRoleDescriptor()));
        final IndexingPressure pressure = pressure(coordinator());
        final long splitsBefore = pressure.stats().getLowWaterMarkSplits();
        final long coordinatingBefore = pressure.stats().getCurrentCoordinatingBytes();

        step(1, "REST layer creates the handler on accept; the context reservation is taken");
        // Step 1: the REST layer creates the handler as soon as the request is accepted, before any body chunk has arrived.
        final ThreadContext threadContext = threadContext(coordinator());
        final IncrementalBulkService.Handler handler;
        final Supplier<ThreadContext.StoredContext> requestContext;
        final long contextEstimate;
        try (var ignored = threadContext.stashContext()) {
            authentication.writeToContext(threadContext);
            contextEstimate = threadContext.estimatedRequestContextBytes();
            requestContext = threadContext.newRestorableContext(false);
            handler = internalCluster().getInstance(IncrementalBulkService.class, coordinator()).newBulkRequest();
        }
        final long reservedAtStart = pressure.stats().getCurrentCoordinatingBytes() - coordinatingBefore;
        say("contextEstimate=%d reservedAtStart=%d", contextEstimate, reservedAtStart);
        // Nothing but the context has been received, and the whole context is already reserved.
        claim("before any body arrives, exactly the context is reserved");
        assertThat(reservedAtStart, equalTo(contextEstimate));

        step(2, "first chunk: the context alone is over the low watermark, so it splits");
        // Step 2: the first chunk, one document. The context alone already puts node-wide usage above the 10 KB low watermark,
        // so maybeSplit() splits and a sub-bulk is sent.
        try (var ignored = requestContext.get()) {
            handler.addItems(List.of(newIndexRequest()), () -> {}, () -> {});
        }
        assertBusy(() -> assertThat(pressure.stats().getLowWaterMarkSplits(), equalTo(splitsBefore + 1)));

        step(3, "the sub-bulk completes and returns its bytes; the context reservation stays");
        // Step 3: when the sub-bulk completes it returns its own bytes. The context reservation must NOT go with them.
        assertBusy(() -> assertThat(pressure.stats().getCurrentCoordinatingBytes() - coordinatingBefore, equalTo(contextEstimate)));
        say("held after split completed=%d", pressure.stats().getCurrentCoordinatingBytes() - coordinatingBefore);

        step(4, "last chunk completes; the handler is still open so the context is still reserved");
        // Step 4: the last chunk. The final bulk completes, yet the handler is still open, so the context is still reserved.
        final PlainActionFuture<BulkResponse> future = new PlainActionFuture<>();
        try (var ignored = requestContext.get()) {
            handler.lastItems(List.of(newIndexRequest()), () -> {}, future);
        }
        assertFalse(future.actionGet().hasFailures());
        assertBusy(() -> assertThat(pressure.stats().getCurrentCoordinatingBytes() - coordinatingBefore, equalTo(contextEstimate)));
        say("held after final bulk=%d", pressure.stats().getCurrentCoordinatingBytes() - coordinatingBefore);

        step(5, "REST layer closes the handler; the context is released");
        // Step 5: the REST layer closes the handler when the HTTP request's stream ends (RestBulkAction.ChunkHandler#streamClose).
        // Only now is the context released.
        handler.close();
        say("held after close=%d", pressure.stats().getCurrentCoordinatingBytes() - coordinatingBefore);
        assertThat(pressure.stats().getCurrentCoordinatingBytes() - coordinatingBefore, equalTo(0L));
        takeaway("the context reservation belongs to the HTTP request, not to any sub-bulk");
    }

    /**
     * <b>Test B: the same bulk under a small context does not split</b>
     * The only difference from test A is the identity, hence the size of the context. A ~0.7 KB context leaves node-wide usage far
     * below the 10 KB watermark, so the first item does not split.
     */
    public void testSmallContextDoesNotReachTheWatermark() throws Exception {
        step(1, "same flow, but the root user's small context");
        final Authentication authentication = authenticationOf(rootAuthorization());
        final IndexingPressure pressure = pressure(coordinator());
        final IndexingPressureStats before = pressure.stats();

        final ThreadContext threadContext = threadContext(coordinator());
        final IncrementalBulkService.Handler handler;
        final Supplier<ThreadContext.StoredContext> requestContext;
        try (var ignored = threadContext.stashContext()) {
            authentication.writeToContext(threadContext);
            requestContext = threadContext.newRestorableContext(false);
            handler = internalCluster().getInstance(IncrementalBulkService.class, coordinator()).newBulkRequest();
        }
        final long held = pressure.stats().getCurrentCoordinatingBytes() - before.getCurrentCoordinatingBytes();
        say("context reservation=%d", held);
        assertThat(held, greaterThan(0L));
        assertThat(held, lessThan(10_000L));

        try (var ignored = requestContext.get()) {
            handler.addItems(List.of(newIndexRequest()), () -> {}, () -> {});
        }
        final long splits = pressure.stats().getLowWaterMarkSplits() - before.getLowWaterMarkSplits();
        say("low watermark splits=%d", splits);
        claim("a small context stays under the watermark, so there is no split");
        assertThat(splits, equalTo(0L));

        final PlainActionFuture<BulkResponse> future = new PlainActionFuture<>();
        try (var ignored = requestContext.get()) {
            handler.lastItems(List.of(newIndexRequest()), () -> {}, future);
        }
        assertFalse(future.actionGet().hasFailures());
        handler.close();
        assertThat(pressure.stats().getCurrentCoordinatingBytes() - before.getCurrentCoordinatingBytes(), equalTo(0L));
        takeaway("context size now influences when bulks split");
    }

    /** Runs one bulk as the given identity, so the coordinator holds a real Authentication for it, and returns that Authentication. */
    private Authentication authenticationOf(String authorization) {
        createIndexOnDataNode();
        as(coordinator(), authorization).bulk(oneDocumentBulk()).actionGet();
        return LessonProbe.captures(Point.SENT, LessonProbe.BULK_SHARD).getLast().authentication();
    }

    private static DocWriteRequest<?> newIndexRequest() {
        return new IndexRequest(INDEX).source(Map.of("field", "value"));
    }
}
