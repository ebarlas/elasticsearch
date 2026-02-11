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
import java.util.HashSet;
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
         * @param localExpressions the resolved local expressions. May be empty.
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
            final HashSet<String> localExpressionsMutable = new HashSet<>(localExpressions);
            final Set<String> remoteExpressionsCopy = new HashSet<>(remoteExpressions);
            expressions.add(
                new ResolvedIndexExpression(
                    original,
                    new LocalExpressions(localExpressionsMutable, resolutionResult, null),
                    remoteExpressionsCopy
                )
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
            expressions.add(new ResolvedIndexExpression(original, LocalExpressions.NONE, new HashSet<>(remoteExpressions)));
        }

        /**
         * Exclude the given expressions from the local expressions of all prior added {@link ResolvedIndexExpression}.
         */
        public void excludeFromLocalExpressions(Set<String> expressionsToExclude) {
            Objects.requireNonNull(expressionsToExclude);
            if (expressionsToExclude.isEmpty() == false) {
                for (ResolvedIndexExpression prior : expressions) {
                    final Set<String> localExpressions = prior.localExpressions().indices();
                    if (localExpressions.isEmpty()) {
                        continue;
                    }
                    localExpressions.removeAll(expressionsToExclude);
                }
            }
        }

        public ResolvedIndexExpressions build() {
            if (expressions.isEmpty()) {
                return new ResolvedIndexExpressions(List.of());
            }

            final ArrayList<ResolvedIndexExpression> expressionsCopy = new ArrayList<>(expressions.size());
            for (ResolvedIndexExpression expression : expressions) {
                final LocalExpressions local = expression.localExpressions();
                final Set<String> localIndices = local.indices();
                final Set<String> localIndicesImmutable = localIndices.isEmpty() ? Set.of() : Set.copyOf(localIndices);

                final LocalExpressions localImmutable;
                if (local == LocalExpressions.NONE) {
                    localImmutable = LocalExpressions.NONE;
                } else {
                    localImmutable = new LocalExpressions(
                        localIndicesImmutable,
                        local.localIndexResolutionResult(),
                        local.exception()
                    );
                }

                final Set<String> remote = expression.remoteExpressions();
                final Set<String> remoteImmutable = remote.isEmpty() ? Set.of() : Set.copyOf(remote);

                expressionsCopy.add(new ResolvedIndexExpression(expression.original(), localImmutable, remoteImmutable));
            }

            return new ResolvedIndexExpressions(List.copyOf(expressionsCopy));
        }
    }
}
