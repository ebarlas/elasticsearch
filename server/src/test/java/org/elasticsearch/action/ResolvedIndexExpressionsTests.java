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

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;

public class ResolvedIndexExpressionsTests extends ESTestCase {

    public void testBuilderProducesImmutableCollections() {
        final var builder = ResolvedIndexExpressions.builder();

        builder.addExpressions(
            "local",
            Set.of("index-a", "index-b"),
            ResolvedIndexExpression.LocalIndexResolutionResult.SUCCESS,
            Set.of("remote1:index-*", "remote2:index-*")
        );
        builder.addRemoteExpressions("remote-only", Set.of("remote3:other-*"));

        final ResolvedIndexExpressions resolved = builder.build();
        assertThat(resolved.expressions().size(), equalTo(2));

        expectThrows(UnsupportedOperationException.class, () -> resolved.expressions().add(resolved.expressions().get(0)));

        for (ResolvedIndexExpression expression : resolved.expressions()) {
            expectThrows(UnsupportedOperationException.class, () -> expression.localExpressions().indices().add("new-local-index"));
            expectThrows(UnsupportedOperationException.class, () -> expression.remoteExpressions().add("new-remote:index-*"));
        }
    }

    public void testBuilderAccumulatesAndExcludesFromLocalExpressions() {
        final var builder = ResolvedIndexExpressions.builder();

        builder.addExpressions(
            "expr",
            Set.of("index-1", "index-2", "index-3"),
            ResolvedIndexExpression.LocalIndexResolutionResult.SUCCESS,
            Set.of()
        );

        // This mutates the builder's prior local expression sets (but must not require caller mutability).
        builder.excludeFromLocalExpressions(Set.of("index-2"));

        final ResolvedIndexExpressions resolved = builder.build();
        assertThat(resolved.expressions().size(), equalTo(1));

        final ResolvedIndexExpression expression = resolved.expressions().get(0);
        assertThat(expression.original(), equalTo("expr"));
        assertThat(expression.localExpressions().indices(), containsInAnyOrder("index-1", "index-3"));

        assertThat(resolved.getLocalIndicesList(), containsInAnyOrder("index-1", "index-3"));
        assertThat(resolved.getRemoteIndicesList(), equalTo(List.of()));
    }
}

