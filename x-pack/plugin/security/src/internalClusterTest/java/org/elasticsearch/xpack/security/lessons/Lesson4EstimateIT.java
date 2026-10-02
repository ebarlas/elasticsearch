/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.lessons;

import org.apache.lucene.util.Accountable;
import org.apache.lucene.util.RamUsageEstimator;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.support.AuthenticationContextSerializer;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Capture;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Point;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

/**
 * <h2>Lesson 4: how the estimate is built, and how close it is</h2>
 *
 * <h3>The idea</h3>
 * Indexing pressure needs a number for "how much heap does this request's context pin". The change provides it as
 * {@code ThreadContext#estimatedRequestContextBytes()}, which is the sum of:
 * <pre>
 *   header strings          every request header key and value, each sized as a Latin-1 String
 *   + Accountable transients  for each transient value that implements Lucene's Accountable, its ramBytesUsed()
 * </pre>
 * {@code ThreadContext} lives in the server module and knows nothing about security. {@code Authentication} implements
 * {@link Accountable} (as does {@code CrossClusterAccessSubjectInfo.RoleDescriptorsBytes}), so security's types plug into a generic
 * hook. Any other module can opt in the same way.
 *
 * <h3>The three tests</h3>
 * <ol>
 *   <li>{@link #testAccountableBasics}: what {@code Accountable} is, and why strings are sized as Latin-1.</li>
 *   <li>{@link #testPiecesOfTheEstimate}: for one request, how the total splits into the encoded header, the decoded
 *       Authentication and everything else, set against the payload size that indexing pressure counted before.</li>
 *   <li>{@link #testEstimateAgainstRealHeap}: is the number right? Decode one header 2,000 times, keep every copy alive, and
 *       measure the heap. A shared JVM makes this approximate, so it prints and asserts loosely.</li>
 * </ol>
 *
 * <h3>Where to set breakpoints</h3>
 * {@code ThreadContext#estimatedRequestContextBytes}, then step into {@code Authentication#ramBytesUsed} and its
 * {@code valueRamBytesUsed} helper to watch the metadata map being walked.
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 2, numClientNodes = 0, supportsDedicatedMasters = false)
@TestLogging(reason = "lesson output", value = "org.elasticsearch.xpack.security.lessons:INFO")
public class Lesson4EstimateIT extends LessonCase {

    /**
     * {@code Accountable} is a one-method Lucene interface: {@code long ramBytesUsed()}. Objects report their own footprint, and
     * this is already used by dozens of server classes. A {@code BytesArray} reports its array length plus its own header.
     *
     * <p>Strings are the trickier case. Lucene's {@code sizeOf(String)} assumes two bytes per character, but since Java 9 the JVM
     * stores an ASCII-only String at one byte per character ("compact strings"). Transport headers are ASCII, so the change sizes
     * them as Latin-1: object header plus array header plus one byte per char. The staging heap dump measured 15,904 bytes retained
     * for a 15,864 char header, which is exactly the Latin-1 figure, so Lucene's version would have double-counted the largest
     * single item.
     */
    public void testAccountableBasics() {
        step(1, "Accountable: a BytesArray reports its own size");
        final BytesArray blob = new BytesArray(new byte[8_450]);
        say("BytesArray(8450).ramBytesUsed=%s", bytes(blob.ramBytesUsed()));

        final String header = "x".repeat(15_864);
        say("Lucene sizeOf(String)=%s latin1StringBytes=%s", bytes(RamUsageEstimator.sizeOf(header)), bytes(latin1StringBytes(header)));
        claim("Lucene sizes the ASCII header at about twice its real heap cost");
        assertThat(RamUsageEstimator.sizeOf(header), greaterThan(latin1StringBytes(header)));
        takeaway("strings are sized as Latin-1; Lucene's two bytes per char would double-count the largest single item");
    }

    /**
     * Split the estimate for three identities into its parts. For each: <b>auth header</b> is the encoded
     * {@code _xpack_security_authentication} string, <b>decoded Authentication</b> is the transient's {@code ramBytesUsed()}, and
     * <b>other headers</b> is everything else (small). The <b>payload</b> is all that indexing pressure used to count.
     *
     * <p>The ratio is the point: a one-document bulk is a few hundred bytes, a plain user's context is a few times that, and a
     * Fleet-like API key's context is tens of times the payload. Back-pressure was blind to the part that dominates.
     */
    public void testPiecesOfTheEstimate() throws Exception {
        createIndexOnDataNode();
        step(1, "measure the payload that indexing pressure used to count");
        final long payloadBytes = oneDocumentBulk().ramBytesUsed();
        say("payload bytes=%d", payloadBytes);

        step(2, "send one bulk per identity and split each estimate into its parts");
        final String[] labels = { "root user", "small API key", "Fleet-like API key" };
        final String[] authorizations = {
            rootAuthorization(),
            createApiKey("small", smallRoleDescriptor()),
            createApiKey("fleet-like", fleetLikeRoleDescriptor()) };
        final long[] totals = new long[3];
        for (int i = 0; i < 3; i++) {
            as(coordinator(), authorizations[i]).bulk(oneDocumentBulk()).actionGet();
            final Capture sent = LessonProbe.captures(Point.SENT, LessonProbe.BULK_SHARD).getLast();
            final long total = sent.contextBytes();
            final long authHeader = latin1StringBytes(sent.authenticationHeader());
            final long decoded = sent.authentication().ramBytesUsed();
            totals[i] = total;
            say("%s: total=%d authHeader=%d decodedAuthentication=%d otherHeaders=%d", labels[i], total, authHeader, decoded, total - authHeader - decoded);
            assertThat(total, greaterThanOrEqualTo(authHeader + decoded));
        }
        say("context/payload ratio: root=%.1f fleet-like=%.0f", totals[0] / (double) payloadBytes, totals[2] / (double) payloadBytes);
        claim("a Fleet-like context is over 10x a user's and over 20x the payload");
        assertThat(totals[2], greaterThan(10 * totals[0]));
        assertThat(totals[2], greaterThan(20 * payloadBytes));
        takeaway("back-pressure was blind to the part of a request that dominates its memory");
    }

    /**
     * A receiving node builds one Authentication per request by decoding the header. Here we do the same 2,000 times and keep
     * every result reachable, so the heap growth divided by 2,000 is what one decoded copy really costs. Compare it with
     * {@code ramBytesUsed()}.
     *
     * <p>The estimate comes out somewhat above the measurement (it is deliberately simple and slightly conservative: it charges
     * a map-entry overhead and a constant per unknown value). The staging dump measured 12,816 bytes retained for the metadata of a
     * real Fleet agent Authentication, whose limited-by blob is a further ~2.5 KB bigger than this test's, which is consistent.
     */
    public void testEstimateAgainstRealHeap() throws Exception {
        createIndexOnDataNode();
        as(coordinator(), createApiKey("fleet-like", fleetLikeRoleDescriptor())).bulk(oneDocumentBulk()).actionGet();
        final Capture sent = LessonProbe.captures(Point.SENT, LessonProbe.BULK_SHARD).getLast();
        final String header = sent.authenticationHeader();
        final long estimate = sent.authentication().ramBytesUsed();

        step(1, "decode the same header 2,000 times, keeping every copy alive, and measure the heap");
        final int copies = 2_000;
        final long before = usedHeapAfterGc();
        final List<Authentication> keepAlive = new ArrayList<>(copies);
        for (int i = 0; i < copies; i++) {
            keepAlive.add(AuthenticationContextSerializer.decode(header));
        }
        final long after = usedHeapAfterGc();
        final double measuredPerCopy = (after - before) / (double) copies;
        say("estimate=%d measuredPerCopy=%d", estimate, (long) measuredPerCopy);
        claim("the estimate is the right order of magnitude for the measured heap");
        assertThat(keepAlive.size(), equalTo(copies));
        assertThat(measuredPerCopy, greaterThan(estimate / 3.0));
        takeaway("the estimate is simple and slightly conservative relative to the measured heap");
    }

    private static long usedHeapAfterGc() throws InterruptedException {
        for (int i = 0; i < 3; i++) {
            System.gc();
            Thread.sleep(50);
        }
        final Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }
}
