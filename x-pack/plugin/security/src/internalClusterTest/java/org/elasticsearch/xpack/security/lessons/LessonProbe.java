/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.lessons;

import org.elasticsearch.action.bulk.TransportShardBulkAction;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.node.Node;
import org.elasticsearch.plugins.NetworkPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Transport;
import org.elasticsearch.transport.TransportInterceptor;
import org.elasticsearch.transport.TransportRequest;
import org.elasticsearch.transport.TransportRequestHandler;
import org.elasticsearch.transport.TransportRequestOptions;
import org.elasticsearch.transport.TransportResponse;
import org.elasticsearch.transport.TransportResponseHandler;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationField;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;

/**
 * Lesson scaffolding (temporary). A node plugin that wraps every transport handler and sender so a lesson can look at the
 * {@link ThreadContext} at the moment a watched request leaves one node and arrives at another, and can optionally <em>park</em>
 * primary-shard write operations the way a saturated write thread pool queue would.
 *
 * <p>It is a transport interceptor rather than a {@code MockTransportService} rule because security integration tests run on the
 * real transport (security installs its own interceptor), and we want the real security code in the picture.
 *
 * <p>Interceptors are chained so that the plugin listed last is outermost. This plugin is listed after security, so on the receiving
 * side it runs <em>before</em> security has authenticated the request, and on the sending side before security's sender.
 */
public class LessonProbe extends Plugin implements NetworkPlugin {

    /** The shard-level bulk request a coordinator sends to the node holding the primary. */
    public static final String BULK_SHARD = TransportShardBulkAction.ACTION_NAME;
    /** The primary-phase action the receiving node loops back to itself after its network-received checks. */
    public static final String BULK_SHARD_PRIMARY = BULK_SHARD + "[p]";

    public enum Point {
        /** On the sending node, just before the request is handed to the transport. */
        SENT,
        /** On the receiving node, as the handler is invoked (before security's own handler wrapper). */
        RECEIVED
    }

    /**
     * What the thread context looked like at one observation point.
     *
     * @param authentication the decoded transient {@link Authentication}, or null if nothing has decoded it yet
     * @param contextBytes   what {@link ThreadContext#estimatedRequestContextBytes()} reported at that moment
     */
    public record Capture(
        String node,
        Point point,
        String action,
        Map<String, String> headers,
        Authentication authentication,
        long contextBytes
    ) {
        public String authenticationHeader() {
            return headers.get(AuthenticationField.AUTHENTICATION_KEY);
        }
    }

    private static final Set<String> DEFAULT_WATCHED = Set.of(BULK_SHARD, BULK_SHARD_PRIMARY);

    private static final List<Capture> CAPTURES = new CopyOnWriteArrayList<>();
    private static final Set<String> WATCHED = ConcurrentHashMap.newKeySet();
    private static final Queue<Runnable> PARKED = new ConcurrentLinkedQueue<>();
    private static volatile boolean parkPrimaryOperations;

    private final String nodeName;
    private volatile ThreadPool threadPool;

    public LessonProbe(Settings settings) {
        this.nodeName = Node.NODE_NAME_SETTING.get(settings);
    }

    public static void reset() {
        CAPTURES.clear();
        WATCHED.clear();
        WATCHED.addAll(DEFAULT_WATCHED);
        parkPrimaryOperations = false;
        PARKED.clear();
    }

    public static void watch(String action) {
        WATCHED.add(action);
    }

    public static List<Capture> captures(Point point, String action) {
        return CAPTURES.stream().filter(c -> c.point() == point && c.action().equals(action)).toList();
    }

    /** While true, primary-phase bulk operations are queued by this probe instead of being executed, holding their context alive. */
    public static void parkPrimaryOperations(boolean park) {
        parkPrimaryOperations = park;
    }

    public static int parkedOperations() {
        return PARKED.size();
    }

    /** Resumes every parked operation on the write thread pool of the node that parked it. */
    public static void releaseParked() {
        Runnable resume;
        while ((resume = PARKED.poll()) != null) {
            resume.run();
        }
    }

    @Override
    public Collection<?> createComponents(PluginServices services) {
        this.threadPool = services.threadPool();
        return List.of();
    }

    @Override
    public List<TransportInterceptor> getTransportInterceptors(NamedWriteableRegistry registry, ThreadContext threadContext) {
        return List.of(new TransportInterceptor() {
            @Override
            public <T extends TransportRequest> TransportRequestHandler<T> interceptHandler(
                String action,
                Executor executor,
                boolean forceExecution,
                TransportRequestHandler<T> actualHandler
            ) {
                return (request, channel, task) -> {
                    if (WATCHED.contains(action) == false) {
                        actualHandler.messageReceived(request, channel, task);
                        return;
                    }
                    capture(threadContext, Point.RECEIVED, action);
                    if (parkPrimaryOperations && BULK_SHARD_PRIMARY.equals(action)) {
                        // Park the request together with its thread context. A real write queue does exactly this: the queued
                        // runnable keeps the context, and therefore the decoded Authentication, alive until a write thread is free.
                        final Runnable resume = threadContext.preserveContext(() -> {
                            try {
                                actualHandler.messageReceived(request, channel, task);
                            } catch (Exception e) {
                                channel.sendResponse(e);
                            }
                        });
                        final ThreadPool pool = threadPool;
                        PARKED.add(() -> pool.executor(ThreadPool.Names.WRITE).execute(resume));
                    } else {
                        actualHandler.messageReceived(request, channel, task);
                    }
                };
            }

            @Override
            public AsyncSender interceptSender(AsyncSender sender) {
                return new AsyncSender() {
                    @Override
                    public <T extends TransportResponse> void sendRequest(
                        Transport.Connection connection,
                        String action,
                        TransportRequest request,
                        TransportRequestOptions options,
                        TransportResponseHandler<T> handler
                    ) {
                        if (WATCHED.contains(action)) {
                            capture(threadContext, Point.SENT, action);
                        }
                        sender.sendRequest(connection, action, request, options, handler);
                    }
                };
            }
        });
    }

    private void capture(ThreadContext threadContext, Point point, String action) {
        final Authentication authentication = threadContext.getTransient(AuthenticationField.AUTHENTICATION_KEY);
        CAPTURES.add(
            new Capture(nodeName, point, action, threadContext.getHeaders(), authentication, threadContext.estimatedRequestContextBytes())
        );
    }
}
