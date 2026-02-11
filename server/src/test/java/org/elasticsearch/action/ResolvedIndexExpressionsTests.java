/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.action;

import org.elasticsearch.test.ESTestCase;

import java.util.List;
import java.util.Set;

import static org.elasticsearch.action.ResolvedIndexExpression.LocalIndexResolutionResult.SUCCESS;
import static org.hamcrest.Matchers.containsInAnyOrder;

public class ResolvedIndexExpressionsTests extends ESTestCase {

    public void testAddExpressionsAcceptsImmutableSet() {
        var builder = ResolvedIndexExpressions.builder();
        // Set.of() returns an immutable set; this should not throw
        builder.addExpressions("expr", Set.of("index-1", "index-2"), SUCCESS, Set.of());
        ResolvedIndexExpressions result = builder.build();
        assertEquals(1, result.expressions().size());
        assertEquals(Set.of("index-1", "index-2"), result.expressions().get(0).localExpressions().indices());
    }

    public void testExcludeFromLocalExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr1", Set.of("a", "b", "c"), SUCCESS, Set.of());
        builder.addExpressions("expr2", Set.of("b", "c", "d"), SUCCESS, Set.of());
        builder.excludeFromLocalExpressions(Set.of("b", "c"));
        ResolvedIndexExpressions result = builder.build();
        assertEquals(Set.of("a"), result.expressions().get(0).localExpressions().indices());
        assertEquals(Set.of("d"), result.expressions().get(1).localExpressions().indices());
    }

    public void testExcludeDoesNotAffectImmutableEntries() {
        var builder = ResolvedIndexExpressions.builder();
        // addExpression (singular) adds an immutable entry
        builder.addExpression(
            new ResolvedIndexExpression("expr1", new ResolvedIndexExpression.LocalExpressions(Set.of("a", "b"), SUCCESS, null), Set.of())
        );
        // addExpressions (plural) adds a mutable entry
        builder.addExpressions("expr2", Set.of("a", "b"), SUCCESS, Set.of());
        // exclude should only affect mutable entries
        builder.excludeFromLocalExpressions(Set.of("a"));
        ResolvedIndexExpressions result = builder.build();
        // immutable entry unchanged
        assertEquals(Set.of("a", "b"), result.expressions().get(1).localExpressions().indices());
        // mutable entry had "a" removed
        assertEquals(Set.of("b"), result.expressions().get(0).localExpressions().indices());
    }

    public void testBuildProducesImmutableExpressionsList() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr", Set.of("index-1"), SUCCESS, Set.of());
        ResolvedIndexExpressions result = builder.build();
        expectThrows(UnsupportedOperationException.class, () -> result.expressions().add(null));
    }

    public void testBuildProducesImmutableLocalIndices() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr", Set.of("index-1", "index-2"), SUCCESS, Set.of());
        ResolvedIndexExpressions result = builder.build();
        Set<String> indices = result.expressions().get(0).localExpressions().indices();
        expectThrows(UnsupportedOperationException.class, () -> indices.add("index-3"));
        expectThrows(UnsupportedOperationException.class, () -> indices.remove("index-1"));
    }

    public void testBuildProducesImmutableRemoteExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr", Set.of(), SUCCESS, Set.of("remote:index-1"));
        ResolvedIndexExpressions result = builder.build();
        Set<String> remote = result.expressions().get(0).remoteExpressions();
        expectThrows(UnsupportedOperationException.class, () -> remote.add("remote:index-2"));
    }

    public void testAddRemoteExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addRemoteExpressions("expr", Set.of("remote:a", "remote:b"));
        ResolvedIndexExpressions result = builder.build();
        assertEquals(1, result.expressions().size());
        assertEquals(ResolvedIndexExpression.LocalExpressions.NONE, result.expressions().get(0).localExpressions());
        assertEquals(Set.of("remote:a", "remote:b"), result.expressions().get(0).remoteExpressions());
    }

    public void testEmptyBuilder() {
        var builder = ResolvedIndexExpressions.builder();
        ResolvedIndexExpressions result = builder.build();
        assertEquals(List.of(), result.expressions());
    }

    public void testExcludeFromEmptyLocalExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr", Set.of(), SUCCESS, Set.of());
        // excluding from empty local expressions should not throw
        builder.excludeFromLocalExpressions(Set.of("a"));
        ResolvedIndexExpressions result = builder.build();
        assertEquals(Set.of(), result.expressions().get(0).localExpressions().indices());
    }

    public void testGetLocalIndicesList() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr1", Set.of("a"), SUCCESS, Set.of());
        builder.addExpressions("expr2", Set.of("b"), SUCCESS, Set.of());
        ResolvedIndexExpressions result = builder.build();
        assertThat(result.getLocalIndicesList(), containsInAnyOrder("a", "b"));
    }

    public void testGetRemoteIndicesList() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr1", Set.of(), SUCCESS, Set.of("remote:a"));
        builder.addExpressions("expr2", Set.of(), SUCCESS, Set.of("remote:b"));
        ResolvedIndexExpressions result = builder.build();
        assertThat(result.getRemoteIndicesList(), containsInAnyOrder("remote:a", "remote:b"));
    }
}
