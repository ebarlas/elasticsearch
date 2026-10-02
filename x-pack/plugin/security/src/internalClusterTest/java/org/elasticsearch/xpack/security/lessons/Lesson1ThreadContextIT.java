/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.lessons;

import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Capture;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Point;

import java.util.Map;
import java.util.function.Supplier;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;

/**
 * <h2>Lesson 1: the ThreadContext, and why a request's context lives as long as the request</h2>
 *
 * <h3>The idea</h3>
 * Every request on a node runs with a {@link ThreadContext} attached to its thread. It has two halves:
 * <table>
 *   <caption>The two halves of a ThreadContext</caption>
 *   <tr><th>half</th><th>type</th><th>crosses to other nodes?</th></tr>
 *   <tr><td>request headers</td><td>{@code Map<String,String>}</td><td>yes, serialized with the request</td></tr>
 *   <tr><td>transient headers</td><td>{@code Map<String,Object>}</td><td>no, it never leaves this JVM</td></tr>
 * </table>
 *
 * Security stores the caller's identity under one key, {@code _xpack_security_authentication}, <em>in both halves</em>:
 * <ul>
 *   <li>as a <b>request header</b>: the encoded base64 string, so it can travel to other nodes;</li>
 *   <li>as a <b>transient</b>: the decoded {@code Authentication} object, so this node can use it cheaply.</li>
 * </ul>
 *
 * <h3>Why it matters for the accounting change</h3>
 * Anything that holds on to a context holds on to <em>both</em> halves. {@code TransportService} captures the context of every
 * request it sends, to restore it when the response arrives; the write thread pool's queue holds the context of every write
 * waiting to run. So a request that is merely waiting keeps its headers and its decoded {@code Authentication} on the heap.
 * Indexing back-pressure used to count none of that.
 *
 * <h3>What the two tests show</h3>
 * <ol>
 *   <li>{@link #testHeadersTransientsAndRestorableContext}: the two halves, stashing, and a captured context being restored later.</li>
 *   <li>{@link #testWhatCrossesTheWire}: a real bulk crossing from the coordinator to the data node. The receiver ends up with
 *       <em>its own copies</em> of the headers and builds a fresh {@code Authentication}.</li>
 * </ol>
 *
 * <h3>Where to set breakpoints</h3>
 * {@code ThreadContext#newRestorableContext}, {@code TransportService#sendRequestInternal} (each outgoing request captures its
 * context into a response handler here) and {@code ThreadContext#estimatedRequestContextBytes} (the new method).
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 2, numClientNodes = 0, supportsDedicatedMasters = false)
@TestLogging(reason = "lesson output", value = "org.elasticsearch.xpack.security.lessons:INFO")
public class Lesson1ThreadContextIT extends LessonCase {

    /**
     * <b>Part A: headers, transients, and capturing a context</b>
     * Works directly on a node's {@link ThreadContext}, no transport involved.
     */
    public void testHeadersTransientsAndRestorableContext() throws Exception {
        final ThreadContext threadContext = threadContext(coordinator());

        final Supplier<ThreadContext.StoredContext> restorable;
        final long bytesInsideStash;
        try (var ignored = threadContext.stashContext()) {
            step(1, "stash: start from an empty context");
            // Step 1: stashContext() swaps in an empty context, so what follows is not mixed with the test framework's own headers.
            assertThat(threadContext.getHeaders().size(), equalTo(0));

            step(2, "put one request header and one transient header");
            // Step 2: put one of each kind. The header is a String and would travel to other nodes. The transient is any object
            // and stays in this JVM.
            threadContext.putHeader("x-lesson", "a request header: this string would travel to other nodes");
            threadContext.putTransient("lesson.transient", new Object());
            say("request headers=%s", threadContext.getHeaders());
            say("transient headers=%s", threadContext.getTransientHeaders().keySet());

            step(3, "estimatedRequestContextBytes counts header strings, not plain-Object transients");
            // Step 3: the new method. Every header key and value is counted, sized as a Latin-1 String (see lesson 4). A transient
            // is counted only if it implements Lucene's Accountable, and a plain Object does not, so it adds nothing here.
            bytesInsideStash = threadContext.estimatedRequestContextBytes();
            say("estimatedRequestContextBytes=%s", bytes(bytesInsideStash));
            assertThat(
                bytesInsideStash,
                equalTo(
                    latin1StringBytes("x-lesson") + latin1StringBytes("a request header: this string would travel to other nodes")
                )
            );

            step(4, "capture the context, as TransportService does for every request it sends");
            // Step 4: capture the context. TransportService does exactly this for every request it sends, so it can handle the
            // response (possibly much later) with the sender's context. Whoever keeps this Supplier keeps the context alive.
            restorable = threadContext.newRestorableContext(true);
        }

        step(5, "leave the stash: the live thread no longer has the header");
        // Step 5: leaving the try block restored the thread's original context. Our header is gone from the live thread...
        assertThat(threadContext.getHeader("x-lesson"), nullValue());

        step(6, "restore the captured context: the header is back, so a pending request pins it");
        // Step 6: ...but the captured copy still has it, and can be reinstated at any later time, on any thread. That retention
        // is the whole point: a pending request pins its context in memory until the response handler or queued task is dropped.
        try (var ignored = restorable.get()) {
            assertThat(threadContext.getHeader("x-lesson"), notNullValue());
            assertThat(threadContext.estimatedRequestContextBytes(), equalTo(bytesInsideStash));
            say("header after restore=%s", threadContext.getHeader("x-lesson") != null);
            takeaway("a captured context keeps every header and transient alive while it is referenced; response handlers and queued tasks are such references");
        }
    }

    /**
     * <b>Part B: what crosses the transport, and what the receiver rebuilds</b>
     * A bulk request is sent through the coordinator for a shard that lives on the data node. {@link LessonProbe} looks at the
     * thread context at three moments:
     * <pre>
     *   coordinator                         data node
     *   ───────────                         ─────────
     *   SENT  bulk[s]  ───── network ─────▶ RECEIVED bulk[s]   (before security has looked at it)
     *                                       RECEIVED bulk[s][p] (the primary phase, after security decoded the header)
     * </pre>
     *
     * <b>How the decoded Authentication gets from {@code bulk[s]} to {@code bulk[s][p]}</b>
     * The two steps on the data node are not two network messages. {@code bulk[s]} is the request that arrived over the wire;
     * {@code bulk[s][p]} is a message the data node sends <em>to itself</em> once it has found the primary is local
     * ({@code TransportReplicationAction.ReroutePhase#performLocalAction}). Nothing is serialized, so nothing is dropped:
     * <pre>
     *   1. bulk[s] arrives. The thread context holds only the request headers, among them the encoded authentication string.
     *   2. Security's handler wrapper authenticates it. AuthenticatorChain asks for an existing authentication in the
     *      context: AuthenticationContextSerializer.readFromContext finds the header but no transient, so it DECODES the
     *      header and calls putTransient. This is the one decode per request on this node.
     *   3. The handler runs checkOperationLimits (the primary reservation), then ReroutePhase sends bulk[s][p] to the local
     *      node. TransportService.sendLocalRequest skips the network. Both handlers are registered with
     *      DIRECT_EXECUTOR_SERVICE, so it calls the bulk[s][p] handler synchronously, on the SAME thread, inside the same
     *      thread context (plus a fresh trace context). There is no hop and no copy.
     *   4. On that same thread, security's wrapper for bulk[s][p] authenticates again. readFromContext finds the transient,
     *      returns it, and decodes nothing.
     *   5. Only after the primary-limits check does handlePrimaryRequest hand the work to the write thread pool:
     *          handlerExecutor(indexShard).execute(new AsyncPrimaryAction(...))
     *      EsThreadPoolExecutor wraps every submitted task with threadContext.preserveContext, which captures the CURRENT
     *      context, headers and transients alike, and reinstates it on the write thread.
     * </pre>
     * So the {@code Authentication} that {@link LessonProbe} sees in the primary phase is the very object decoded in step 2.
     * The probe's wrapper is outermost, so it runs synchronously inside step 3's call, before security's wrapper in step 4.
     * The transient survives the {@code bulk[s]} to {@code bulk[s][p]} step because it is a plain method call on one thread;
     * it survives the later hop to the write thread because a pool task carries its submitter's context. Nothing copies it.
     *
     * <p>It would not survive a hop over the real network. If the primary lived on a third node, {@code bulk[s]} would be
     * forwarded as a new transport message, only the header would travel, and that node would decode again. That is why
     * {@code TransportWriteAction#checkPrimaryLimits} counts nothing on the local-reroute branch (same context object, already
     * counted by {@code checkOperationLimits}) but does count on a request received from the network.
     */
    public void testWhatCrossesTheWire() throws Exception {
        createIndexOnDataNode();

        step(1, "send one bulk via the coordinator as the root user, with an extra header");
        // Step 1: send one bulk through the coordinator, authenticated as the root user, with one extra request header of our own.
        final var client = internalCluster().client(coordinator())
            .filterWithHeader(Map.of("Authorization", rootAuthorization(), "x-lesson", "hello"));
        client.bulk(oneDocumentBulk()).actionGet();

        final Capture sent = LessonProbe.captures(Point.SENT, LessonProbe.BULK_SHARD).getFirst();
        final Capture received = LessonProbe.captures(Point.RECEIVED, LessonProbe.BULK_SHARD).getFirst();
        final Capture primary = LessonProbe.captures(Point.RECEIVED, LessonProbe.BULK_SHARD_PRIMARY).getFirst();
        say("sent by=%s received by=%s primary phase on=%s", sent.node(), received.node(), primary.node());
        assertThat(sent.node(), equalTo(coordinator()));
        assertThat(received.node(), equalTo(dataNode()));

        step(2, "request headers cross the wire; the receiver gets new String objects");
        // Step 2: request headers cross the wire. The value is equal, but the receiver's String is a different object, because
        // the receiver parsed it out of the bytes it was sent. Remember this: every node, and every request, gets its own copy.
        assertThat(received.headers().get("x-lesson"), equalTo("hello"));
        assertThat(received.headers().get("x-lesson"), not(sameInstance(sent.headers().get("x-lesson"))));

        step(3, "the encoded authentication header crosses too, again as a new String");
        // Step 3: the same is true of the encoded authentication header. It is ~84 chars for a plain user, but for an API key
        // it embeds the role descriptors and runs to many KB (lesson 2). Every request carries its own copy of that string.
        final String sentAuthHeader = sent.authenticationHeader();
        final String receivedAuthHeader = received.authenticationHeader();
        say("auth header chars: sender=%d receiver=%d", sentAuthHeader.length(), receivedAuthHeader.length());
        assertThat(receivedAuthHeader, equalTo(sentAuthHeader));
        assertThat(receivedAuthHeader, not(sameInstance(sentAuthHeader)));

        step(4, "the decoded Authentication is transient: absent on arrival");
        // Step 4: the decoded Authentication is a transient, so it did NOT cross. The sender had one; the receiver has none on
        // arrival, until something decodes the header.
        say("decoded Authentication: sender=%s receiver-on-arrival=%s", sent.authentication() != null, received.authentication() != null);
        assertThat(sent.authentication(), notNullValue());
        assertThat(received.authentication(), nullValue());

        step(5, "security decodes a fresh Authentication on the receiving node");
        // Step 5: security's handler wrapper then decodes the header into a brand new Authentication and stores it as a transient.
        // By the primary phase it is in the context, and it is a different object from the sender's. Two copies of the identity
        // now exist, one per node, each pinned for as long as its node's request is in flight.
        say("decoded Authentication in primary phase=%s", primary.authentication() != null);
        assertThat(primary.authentication(), notNullValue());
        assertThat(primary.authentication(), not(sameInstance(sent.authentication())));
        takeaway("each node holds its own copy of the headers and of the Authentication, made per request");
    }
}
