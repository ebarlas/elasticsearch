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

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.elasticsearch.action.ResolvedIndexExpression.LocalIndexResolutionResult.CONCRETE_RESOURCE_NOT_VISIBLE;
import static org.elasticsearch.action.ResolvedIndexExpression.LocalIndexResolutionResult.CONCRETE_RESOURCE_UNAUTHORIZED;
import static org.elasticsearch.action.ResolvedIndexExpression.LocalIndexResolutionResult.SUCCESS;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;

public class ResolvedIndexExpressionsTests extends ESTestCase {

    private static final Set<String> NO_REMOTE = Set.of();

    public void testAddExpressionsAcceptsSetInterface() {
        var builder = ResolvedIndexExpressions.builder();
        // Pass a Set (not necessarily a HashSet) to addExpressions
        Set<String> localExpressions = Set.of("index-1", "index-2");
        builder.addExpressions("my-pattern-*", localExpressions, SUCCESS, NO_REMOTE);

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().size(), equalTo(1));
        assertThat(result.expressions().get(0).original(), equalTo("my-pattern-*"));
        assertThat(result.expressions().get(0).localExpressions().indices(), containsInAnyOrder("index-1", "index-2"));
    }

    public void testAddExpressionsWithHashSet() {
        var builder = ResolvedIndexExpressions.builder();
        // HashSet is still accepted since HashSet implements Set
        HashSet<String> localExpressions = new HashSet<>();
        localExpressions.add("index-a");
        localExpressions.add("index-b");
        builder.addExpressions("expr", localExpressions, SUCCESS, NO_REMOTE);

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().size(), equalTo(1));
        assertThat(result.getLocalIndicesList(), containsInAnyOrder("index-a", "index-b"));
    }

    public void testBuildProducesImmutableLocalExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        HashSet<String> mutableSet = new HashSet<>();
        mutableSet.add("index-1");
        builder.addExpressions("expr", mutableSet, SUCCESS, NO_REMOTE);

        ResolvedIndexExpressions result = builder.build();
        Set<String> indices = result.expressions().get(0).localExpressions().indices();
        expectThrows(UnsupportedOperationException.class, () -> indices.add("index-2"));
    }

    public void testBuildProducesImmutableRemoteExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        HashSet<String> mutableRemote = new HashSet<>();
        mutableRemote.add("remote:index-1");
        builder.addExpressions("expr", Set.of(), SUCCESS, mutableRemote);

        ResolvedIndexExpressions result = builder.build();
        Set<String> remote = result.expressions().get(0).remoteExpressions();
        expectThrows(UnsupportedOperationException.class, () -> remote.add("remote:index-2"));
    }

    public void testBuildProducesImmutableExpressionsList() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr", Set.of("index-1"), SUCCESS, NO_REMOTE);

        ResolvedIndexExpressions result = builder.build();
        List<ResolvedIndexExpression> expressions = result.expressions();
        expectThrows(
            UnsupportedOperationException.class,
            () -> expressions.add(new ResolvedIndexExpression("new", ResolvedIndexExpression.LocalExpressions.NONE, Set.of()))
        );
    }

    public void testExcludeFromLocalExpressionsRemovesMatchingOriginals() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr-a", Set.of("index-1"), SUCCESS, NO_REMOTE);
        builder.addExpressions("expr-b", Set.of("index-2"), SUCCESS, NO_REMOTE);
        builder.addExpressions("expr-c", Set.of("index-3"), SUCCESS, NO_REMOTE);

        builder.excludeFromLocalExpressions(Set.of("expr-b"));

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().size(), equalTo(2));
        assertThat(result.expressions().get(0).original(), equalTo("expr-a"));
        assertThat(result.expressions().get(1).original(), equalTo("expr-c"));
    }

    public void testExcludeFromLocalExpressionsFiltersIndices() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr", Set.of("index-1", "index-2", "index-3"), SUCCESS, NO_REMOTE);

        builder.excludeFromLocalExpressions(Set.of("index-2"));

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().size(), equalTo(1));
        assertThat(result.expressions().get(0).localExpressions().indices(), containsInAnyOrder("index-1", "index-3"));
    }

    public void testExcludeFromLocalExpressionsDoesNotMutateOriginalSets() {
        var builder = ResolvedIndexExpressions.builder();
        Set<String> originalSet = new HashSet<>(Set.of("index-1", "index-2", "index-3"));
        builder.addExpressions("expr", originalSet, SUCCESS, NO_REMOTE);

        builder.excludeFromLocalExpressions(Set.of("index-2"));

        // The original set passed to the builder should not be mutated
        assertThat(originalSet, containsInAnyOrder("index-1", "index-2", "index-3"));
    }

    public void testExcludeFromLocalExpressionsSkipsEmptyLocalExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr-a", Set.of(), SUCCESS, NO_REMOTE);
        builder.addExpressions("expr-b", Set.of("index-1"), SUCCESS, NO_REMOTE);

        builder.excludeFromLocalExpressions(Set.of("index-1"));

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().size(), equalTo(2));
        assertThat(result.expressions().get(0).localExpressions().indices(), empty());
        assertThat(result.expressions().get(1).localExpressions().indices(), empty());
    }

    public void testExcludeFromLocalExpressionsWithEmptyExcludeSet() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr", Set.of("index-1", "index-2"), SUCCESS, NO_REMOTE);

        builder.excludeFromLocalExpressions(Set.of());

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().size(), equalTo(1));
        assertThat(result.expressions().get(0).localExpressions().indices(), containsInAnyOrder("index-1", "index-2"));
    }

    public void testExcludeFromLocalExpressionsPreservesResolutionResult() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr", Set.of("index-1", "index-2"), CONCRETE_RESOURCE_NOT_VISIBLE, NO_REMOTE);

        builder.excludeFromLocalExpressions(Set.of("index-1"));

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().get(0).localExpressions().localIndexResolutionResult(), equalTo(CONCRETE_RESOURCE_NOT_VISIBLE));
        assertThat(result.expressions().get(0).localExpressions().indices(), containsInAnyOrder("index-2"));
    }

    public void testExcludeFromLocalExpressionsPreservesRemoteExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        Set<String> remote = Set.of("remote:index-1");
        builder.addExpressions("expr", Set.of("index-1", "index-2"), SUCCESS, remote);

        builder.excludeFromLocalExpressions(Set.of("index-1"));

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().get(0).remoteExpressions(), containsInAnyOrder("remote:index-1"));
        assertThat(result.expressions().get(0).localExpressions().indices(), containsInAnyOrder("index-2"));
    }

    public void testAddRemoteExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addRemoteExpressions("remote-expr", Set.of("remote:index-1", "remote:index-2"));

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().size(), equalTo(1));
        assertThat(result.expressions().get(0).localExpressions().indices(), empty());
        assertThat(result.getRemoteIndicesList(), containsInAnyOrder("remote:index-1", "remote:index-2"));
    }

    public void testAddExpression() {
        var builder = ResolvedIndexExpressions.builder();
        var expr = new ResolvedIndexExpression(
            "original",
            new ResolvedIndexExpression.LocalExpressions(Set.of("index-1"), SUCCESS, null),
            Set.of("remote:index-1")
        );
        builder.addExpression(expr);

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().size(), equalTo(1));
        assertThat(result.getLocalIndicesList(), containsInAnyOrder("index-1"));
        assertThat(result.getRemoteIndicesList(), containsInAnyOrder("remote:index-1"));
    }

    public void testMultipleExpressionsAndResolutionResults() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr-a", Set.of("index-1"), SUCCESS, NO_REMOTE);
        builder.addExpressions("expr-b", Set.of("index-2"), CONCRETE_RESOURCE_UNAUTHORIZED, NO_REMOTE);
        builder.addRemoteExpressions("expr-c", Set.of("remote:index-1"));

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions().size(), equalTo(3));
        assertThat(result.getLocalIndicesList(), containsInAnyOrder("index-1", "index-2"));
        assertThat(result.getRemoteIndicesList(), containsInAnyOrder("remote:index-1"));
    }

    public void testGetLocalIndicesListAggregatesAcrossExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr-a", Set.of("index-1", "index-2"), SUCCESS, NO_REMOTE);
        builder.addExpressions("expr-b", Set.of("index-3"), SUCCESS, NO_REMOTE);

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.getLocalIndicesList(), containsInAnyOrder("index-1", "index-2", "index-3"));
    }

    public void testGetRemoteIndicesListAggregatesAcrossExpressions() {
        var builder = ResolvedIndexExpressions.builder();
        builder.addExpressions("expr-a", Set.of(), SUCCESS, Set.of("remote:a"));
        builder.addExpressions("expr-b", Set.of(), SUCCESS, Set.of("remote:b"));

        ResolvedIndexExpressions result = builder.build();
        assertThat(result.getRemoteIndicesList(), containsInAnyOrder("remote:a", "remote:b"));
    }

    public void testEmptyBuild() {
        var builder = ResolvedIndexExpressions.builder();
        ResolvedIndexExpressions result = builder.build();
        assertThat(result.expressions(), empty());
        assertThat(result.getLocalIndicesList(), empty());
        assertThat(result.getRemoteIndicesList(), empty());
    }
}
