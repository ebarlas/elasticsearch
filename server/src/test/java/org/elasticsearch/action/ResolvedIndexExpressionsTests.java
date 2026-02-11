/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.action;

import org.elasticsearch.action.ResolvedIndexExpression.LocalExpressions;
import org.elasticsearch.action.ResolvedIndexExpression.LocalIndexResolutionResult;
import org.elasticsearch.test.ESTestCase;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ResolvedIndexExpressionsTests extends ESTestCase {

    public void testBuildProducesImmutableLocalExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr-1", new HashSet<>(Set.of("index-a", "index-b")), LocalIndexResolutionResult.SUCCESS, Set.of());
        ResolvedIndexExpressions result = builder.build();

        Set<String> localIndices = result.expressions().get(0).localExpressions().indices();
        expectThrows(UnsupportedOperationException.class, () -> localIndices.add("index-c"));
        expectThrows(UnsupportedOperationException.class, () -> localIndices.remove("index-a"));
        expectThrows(UnsupportedOperationException.class, localIndices::clear);
    }

    public void testBuildProducesImmutableRemoteExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions(
            "expr-1",
            Set.of(),
            LocalIndexResolutionResult.NONE,
            new HashSet<>(Set.of("remote1:index-a", "remote2:index-b"))
        );
        ResolvedIndexExpressions result = builder.build();

        Set<String> remoteExpressions = result.expressions().get(0).remoteExpressions();
        expectThrows(UnsupportedOperationException.class, () -> remoteExpressions.add("remote3:index-c"));
        expectThrows(UnsupportedOperationException.class, () -> remoteExpressions.remove("remote1:index-a"));
        expectThrows(UnsupportedOperationException.class, remoteExpressions::clear);
    }

    public void testBuildProducesImmutableExpressionsList() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr-1", new HashSet<>(Set.of("index-a")), LocalIndexResolutionResult.SUCCESS, Set.of());
        ResolvedIndexExpressions result = builder.build();

        List<ResolvedIndexExpression> expressions = result.expressions();
        expectThrows(UnsupportedOperationException.class, () -> expressions.add(
            new ResolvedIndexExpression("expr-2", LocalExpressions.NONE, Set.of())
        ));
        expectThrows(UnsupportedOperationException.class, () -> expressions.remove(0));
        expectThrows(UnsupportedOperationException.class, expressions::clear);
    }

    public void testBuilderAccumulatesMultipleExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr-1", new HashSet<>(Set.of("index-a", "index-b")), LocalIndexResolutionResult.SUCCESS, Set.of());
        builder.addExpressions(
            "expr-2",
            new HashSet<>(Set.of("index-c")),
            LocalIndexResolutionResult.SUCCESS,
            Set.of("remote1:index-d")
        );
        builder.addRemoteExpressions("expr-3", Set.of("remote2:index-e"));

        ResolvedIndexExpressions result = builder.build();

        assertEquals(3, result.expressions().size());

        ResolvedIndexExpression first = result.expressions().get(0);
        assertEquals("expr-1", first.original());
        assertEquals(Set.of("index-a", "index-b"), first.localExpressions().indices());
        assertEquals(Set.of(), first.remoteExpressions());

        ResolvedIndexExpression second = result.expressions().get(1);
        assertEquals("expr-2", second.original());
        assertEquals(Set.of("index-c"), second.localExpressions().indices());
        assertEquals(Set.of("remote1:index-d"), second.remoteExpressions());

        ResolvedIndexExpression third = result.expressions().get(2);
        assertEquals("expr-3", third.original());
        assertEquals(LocalExpressions.NONE, third.localExpressions());
        assertEquals(Set.of("remote2:index-e"), third.remoteExpressions());
    }

    public void testExcludeFromLocalExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions(
            "expr-1",
            new HashSet<>(Set.of("index-a", "index-b", "index-c")),
            LocalIndexResolutionResult.SUCCESS,
            Set.of()
        );
        builder.addExpressions(
            "expr-2",
            new HashSet<>(Set.of("index-b", "index-d")),
            LocalIndexResolutionResult.SUCCESS,
            Set.of()
        );

        builder.excludeFromLocalExpressions(Set.of("index-b", "index-c"));

        ResolvedIndexExpressions result = builder.build();

        assertEquals(Set.of("index-a"), result.expressions().get(0).localExpressions().indices());
        assertEquals(Set.of("index-d"), result.expressions().get(1).localExpressions().indices());
    }

    public void testExcludeFromLocalExpressionsSkipsEmptySets() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr-1", new HashSet<>(), LocalIndexResolutionResult.SUCCESS, Set.of());
        builder.addExpressions(
            "expr-2",
            new HashSet<>(Set.of("index-a")),
            LocalIndexResolutionResult.SUCCESS,
            Set.of()
        );

        // Should not throw even though expr-1 has an empty set
        builder.excludeFromLocalExpressions(Set.of("index-a"));

        ResolvedIndexExpressions result = builder.build();
        assertEquals(Set.of(), result.expressions().get(0).localExpressions().indices());
        assertEquals(Set.of(), result.expressions().get(1).localExpressions().indices());
    }

    public void testAddExpression() {
        var builder = ResolvedIndexExpressions.builder();
        var expression = new ResolvedIndexExpression(
            "expr-1",
            new LocalExpressions(new HashSet<>(Set.of("index-a")), LocalIndexResolutionResult.SUCCESS, null),
            new HashSet<>(Set.of("remote1:index-b"))
        );
        builder.addExpression(expression);

        ResolvedIndexExpressions result = builder.build();

        assertEquals(1, result.expressions().size());
        assertEquals("expr-1", result.expressions().get(0).original());
        assertEquals(Set.of("index-a"), result.expressions().get(0).localExpressions().indices());
        assertEquals(Set.of("remote1:index-b"), result.expressions().get(0).remoteExpressions());

        // Verify immutability of the built result
        expectThrows(UnsupportedOperationException.class, () -> result.expressions().get(0).localExpressions().indices().add("index-c"));
        expectThrows(
            UnsupportedOperationException.class,
            () -> result.expressions().get(0).remoteExpressions().add("remote2:index-d")
        );
    }

    public void testGetLocalIndicesList() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions(
            "expr-1",
            new HashSet<>(Set.of("index-a", "index-b")),
            LocalIndexResolutionResult.SUCCESS,
            Set.of()
        );
        builder.addExpressions("expr-2", new HashSet<>(Set.of("index-c")), LocalIndexResolutionResult.SUCCESS, Set.of());

        ResolvedIndexExpressions result = builder.build();

        List<String> localIndices = result.getLocalIndicesList();
        assertEquals(3, localIndices.size());
        assertTrue(localIndices.containsAll(List.of("index-a", "index-b", "index-c")));
    }

    public void testGetRemoteIndicesList() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions(
            "expr-1",
            Set.of(),
            LocalIndexResolutionResult.NONE,
            Set.of("remote1:index-a")
        );
        builder.addRemoteExpressions("expr-2", Set.of("remote2:index-b", "remote3:index-c"));

        ResolvedIndexExpressions result = builder.build();

        List<String> remoteIndices = result.getRemoteIndicesList();
        assertEquals(3, remoteIndices.size());
        assertTrue(remoteIndices.containsAll(List.of("remote1:index-a", "remote2:index-b", "remote3:index-c")));
    }

    public void testEmptyBuilder() {
        var builder = ResolvedIndexExpressions.builder();
        ResolvedIndexExpressions result = builder.build();

        assertEquals(0, result.expressions().size());
        assertTrue(result.getLocalIndicesList().isEmpty());
        assertTrue(result.getRemoteIndicesList().isEmpty());
    }

    public void testBuilderRejectsNullArguments() {
        var builder = ResolvedIndexExpressions.builder();
        expectThrows(
            NullPointerException.class,
            () -> builder.addExpressions(null, Set.of(), LocalIndexResolutionResult.SUCCESS, Set.of())
        );
        expectThrows(
            NullPointerException.class,
            () -> builder.addExpressions("expr", null, LocalIndexResolutionResult.SUCCESS, Set.of())
        );
        expectThrows(
            NullPointerException.class,
            () -> builder.addExpressions("expr", Set.of(), null, Set.of())
        );
        expectThrows(
            NullPointerException.class,
            () -> builder.addExpressions("expr", Set.of(), LocalIndexResolutionResult.SUCCESS, null)
        );
        expectThrows(NullPointerException.class, () -> builder.addRemoteExpressions(null, Set.of()));
        expectThrows(NullPointerException.class, () -> builder.addRemoteExpressions("expr", null));
        expectThrows(NullPointerException.class, () -> builder.excludeFromLocalExpressions(null));
    }
}
