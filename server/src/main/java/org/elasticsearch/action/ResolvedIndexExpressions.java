/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

package org.elasticsearch.action;

import org.elasticsearch.TransportVersion;
import org.elasticsearch.action.ResolvedIndexExpression.LocalExpressions;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.io.stream.Writeable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A collection of {@link ResolvedIndexExpression}.
 */
public record ResolvedIndexExpressions(List<ResolvedIndexExpression> expressions) implements Writeable {
    public static final TransportVersion RESOLVED_INDEX_EXPRESSIONS = TransportVersion.fromName("resolved_index_expressions");

    public ResolvedIndexExpressions(StreamInput in) throws IOException {
        this(in.readCollectionAsImmutableList(ResolvedIndexExpression::new));
    }

    public List<String> getLocalIndicesList() {
        return expressions.stream().flatMap(e -> e.localExpressions().indices().stream()).toList();
    }

    public List<String> getRemoteIndicesList() {
        return expressions.stream().flatMap(e -> e.remoteExpressions().stream()).toList();
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeCollection(expressions);
    }

    public static final class Builder {
        private final List<ResolvedIndexExpression> expressions = new ArrayList<>();

        /**
         * Add a new resolved expression.
         * @param original         the original expression that was resolved -- may be blank for "access all" cases
         * @param localExpressions the set of local expressions. May be empty.
         */
        public void addExpressions(
            String original,
            Set<String> localExpressions,
            ResolvedIndexExpression.LocalIndexResolutionResult resolutionResult,
            Set<String> remoteExpressions
        ) {
            Objects.requireNonNull(original);
            Objects.requireNonNull(localExpressions);
            Objects.requireNonNull(resolutionResult);
            Objects.requireNonNull(remoteExpressions);
            expressions.add(
                new ResolvedIndexExpression(original, new LocalExpressions(localExpressions, resolutionResult, null), remoteExpressions)
            );
        }

        /**
         * Add a new resolved expression.
         * @param expression       the expression you want to add.
         */
        public void addExpression(ResolvedIndexExpression expression) {
            expressions.add(expression);
        }

        public void addRemoteExpressions(String original, Set<String> remoteExpressions) {
            Objects.requireNonNull(original);
            Objects.requireNonNull(remoteExpressions);
            expressions.add(new ResolvedIndexExpression(original, LocalExpressions.NONE, remoteExpressions));
        }

        /**
         * Exclude the given expressions from the local expressions of all prior added {@link ResolvedIndexExpression}.
         */
        public void excludeFromLocalExpressions(Set<String> expressionsToExclude) {
            Objects.requireNonNull(expressionsToExclude);
            if (expressionsToExclude.isEmpty() == false) {
                final List<ResolvedIndexExpression> rebuilt = new ArrayList<>(expressions.size());
                for (ResolvedIndexExpression current : expressions) {
                    if (expressionsToExclude.contains(current.original())) {
                        continue;
                    }
                    final Set<String> localExpressions = current.localExpressions().indices();
                    if (localExpressions.isEmpty()) {
                        rebuilt.add(current);
                        continue;
                    }
                    final Set<String> filtered = new LinkedHashSet<>(localExpressions);
                    filtered.removeAll(expressionsToExclude);
                    rebuilt.add(
                        new ResolvedIndexExpression(
                            current.original(),
                            new LocalExpressions(
                                filtered,
                                current.localExpressions().localIndexResolutionResult(),
                                current.localExpressions().exception()
                            ),
                            current.remoteExpressions()
                        )
                    );
                }
                expressions.clear();
                expressions.addAll(rebuilt);
            }
        }

        public ResolvedIndexExpressions build() {
            final List<ResolvedIndexExpression> immutableExpressions = expressions.stream().map(expr -> {
                final Set<String> immutableLocal = Set.copyOf(expr.localExpressions().indices());
                final Set<String> immutableRemote = Set.copyOf(expr.remoteExpressions());
                return new ResolvedIndexExpression(
                    expr.original(),
                    new LocalExpressions(
                        immutableLocal,
                        expr.localExpressions().localIndexResolutionResult(),
                        expr.localExpressions().exception()
                    ),
                    immutableRemote
                );
            }).toList();
            return new ResolvedIndexExpressions(immutableExpressions);
        }
    }
}
