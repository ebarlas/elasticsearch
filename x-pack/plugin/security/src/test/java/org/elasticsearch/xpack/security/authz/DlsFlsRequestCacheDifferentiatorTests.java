/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.security.authz;

import org.apache.lucene.util.SetOnce;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.core.CheckedConsumer;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.license.MockLicenseState;
import org.elasticsearch.script.Script;
import org.elasticsearch.script.ScriptService;
import org.elasticsearch.script.TemplateScript;
import org.elasticsearch.script.mustache.MustacheScriptEngine;
import org.elasticsearch.search.internal.ShardSearchRequest;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.core.security.SecurityContext;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationTestHelper;
import org.elasticsearch.xpack.core.security.authz.AuthorizationServiceField;
import org.elasticsearch.xpack.core.security.authz.accesscontrol.IndicesAccessControl;
import org.elasticsearch.xpack.core.security.authz.permission.DocumentPermissions;
import org.elasticsearch.xpack.core.security.authz.permission.FieldPermissions;
import org.elasticsearch.xpack.core.security.authz.permission.FieldPermissionsDefinition;
import org.elasticsearch.xpack.core.security.user.User;
import org.junit.Before;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.elasticsearch.xpack.core.security.SecurityField.DOCUMENT_LEVEL_SECURITY_FEATURE;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DlsFlsRequestCacheDifferentiatorTests extends ESTestCase {

    private MockLicenseState licenseState;
    private ThreadContext threadContext;
    private StreamOutput out;
    private DlsFlsRequestCacheDifferentiator differentiator;
    private ShardSearchRequest shardSearchRequest;
    private String indexName;
    private String dlsIndexName;
    private String flsIndexName;
    private String dlsFlsIndexName;

    @Before
    public void init() throws IOException {
        licenseState = mock(MockLicenseState.class);
        when(licenseState.isAllowed(DOCUMENT_LEVEL_SECURITY_FEATURE)).thenReturn(true);
        threadContext = new ThreadContext(Settings.EMPTY);
        out = new BytesStreamOutput();
        final SecurityContext securityContext = new SecurityContext(Settings.EMPTY, threadContext);
        differentiator = new DlsFlsRequestCacheDifferentiator(
            licenseState,
            new SetOnce<>(securityContext),
            new SetOnce<>(mock(ScriptService.class))
        );
        shardSearchRequest = mock(ShardSearchRequest.class);
        indexName = randomAlphaOfLengthBetween(3, 8);
        dlsIndexName = "dls-" + randomAlphaOfLengthBetween(3, 8);
        flsIndexName = "fls-" + randomAlphaOfLengthBetween(3, 8);
        dlsFlsIndexName = "dls-fls-" + randomAlphaOfLengthBetween(3, 8);

        final DocumentPermissions documentPermissions1 = DocumentPermissions.filteredBy(Set.of(new BytesArray("""
            {"term":{"number":1}}""")));

        securityContext.putIndicesAccessControl(
            new IndicesAccessControl(
                true,
                Map.of(
                    flsIndexName,
                    new IndicesAccessControl.IndexAccessControl(
                        new FieldPermissions(new FieldPermissionsDefinition(new String[] { "*" }, new String[] { "private" })),
                        DocumentPermissions.allowAll()
                    ),
                    dlsIndexName,
                    new IndicesAccessControl.IndexAccessControl(FieldPermissions.DEFAULT, documentPermissions1),
                    dlsFlsIndexName,
                    new IndicesAccessControl.IndexAccessControl(
                        new FieldPermissions(new FieldPermissionsDefinition(new String[] { "*" }, new String[] { "private" })),
                        documentPermissions1
                    )
                )
            )
        );
    }

    public void testWillWriteCacheKeyForAnyDlsOrFls() throws IOException {
        when(shardSearchRequest.shardId()).thenReturn(
            new ShardId(randomFrom(dlsIndexName, flsIndexName, dlsFlsIndexName), randomAlphaOfLength(10), randomIntBetween(0, 3))
        );
        differentiator.accept(shardSearchRequest, out);
        assertThat(out.position(), greaterThan(0L));
    }

    public void testWillDoNothingIfNoDlsFls() throws IOException {
        when(shardSearchRequest.shardId()).thenReturn(new ShardId(indexName, randomAlphaOfLength(10), randomIntBetween(0, 3)));
        differentiator.accept(shardSearchRequest, out);
        assertThat(out.position(), equalTo(0L));
    }

    public void testWillWriteCacheKeyForImplicitDlsWithoutPlatinumLicense() throws IOException {
        when(licenseState.isAllowed(DOCUMENT_LEVEL_SECURITY_FEATURE)).thenReturn(false);

        String implicitDlsIndex = "implicit-dls-" + randomAlphaOfLengthBetween(3, 8);
        ThreadContext implicitThreadContext = new ThreadContext(Settings.EMPTY);
        SecurityContext implicitSecurityContext = new SecurityContext(Settings.EMPTY, implicitThreadContext);
        DlsFlsRequestCacheDifferentiator implicitDifferentiator = new DlsFlsRequestCacheDifferentiator(
            licenseState,
            new SetOnce<>(implicitSecurityContext),
            new SetOnce<>(mock(ScriptService.class))
        );
        implicitSecurityContext.putIndicesAccessControl(
            new IndicesAccessControl(
                true,
                Map.of(
                    implicitDlsIndex,
                    new IndicesAccessControl.IndexAccessControl(
                        FieldPermissions.DEFAULT,
                        DocumentPermissions.filteredBy(Set.of(new BytesArray("""
                            {"term":{"kibana.space_ids":"default"}}"""))),
                        true
                    )
                )
            )
        );

        when(shardSearchRequest.shardId()).thenReturn(
            new ShardId(implicitDlsIndex, randomAlphaOfLength(10), randomIntBetween(0, 3))
        );
        implicitDifferentiator.accept(shardSearchRequest, out);
        assertThat(out.position(), greaterThan(0L));
    }

    public void testWillDoNothingForExplicitDlsWithoutPlatinumLicense() throws IOException {
        when(licenseState.isAllowed(DOCUMENT_LEVEL_SECURITY_FEATURE)).thenReturn(false);

        when(shardSearchRequest.shardId()).thenReturn(
            new ShardId(dlsIndexName, randomAlphaOfLength(10), randomIntBetween(0, 3))
        );
        differentiator.accept(shardSearchRequest, out);
        assertThat(out.position(), equalTo(0L));
    }

    /**
     * Regression test pinning the ordering invariant that the request cache key produced by
     * {@link DlsFlsRequestCacheDifferentiator} must reflect the metadata that
     * {@link SecurityContext#executeWithEnrichedUserMetadata} merged into the effective user.
     * <p>
     * The differentiator is what writes the per-shard suffix on the request cache key. When a DLS
     * template references {@code {{_user.metadata._foo}}}, the rendered query string is what feeds
     * the cache key. If the differentiator runs <em>before</em> enrichment (or in a thread context
     * that doesn't carry the enriched {@code Authentication}), two requests by the same principal
     * with different externally-looked-up data will collide on the same cache key, returning stale
     * results from one tenant's view to another. This test pins both halves: the differentiator
     * <em>does</em> produce different cache key bytes when the user's metadata changes, and the
     * Authentication swap in {@code executeWithEnrichedUserMetadata} actually flows enriched
     * metadata into the rendered query.
     */
    public void testCacheKeyReflectsEnrichedUserMetadata() throws IOException {
        // Use a real Mustache engine wired into the mocked ScriptService so the template
        // substitution actually runs. Otherwise the differentiator would see the un-rendered
        // template literal and the test couldn't distinguish "no enrichment" from "enrichment
        // happened but didn't reach the differentiator's rendering call".
        final MustacheScriptEngine mustache = new MustacheScriptEngine(Settings.EMPTY);
        final ScriptService realRenderingScriptService = mock(ScriptService.class);
        when(realRenderingScriptService.compile(any(Script.class), eq(TemplateScript.CONTEXT))).thenAnswer(inv -> {
            final Script script = (Script) inv.getArguments()[0];
            return mustache.compile(script.getIdOrCode(), script.getIdOrCode(), TemplateScript.CONTEXT, script.getOptions());
        });

        final ThreadContext localThreadContext = new ThreadContext(Settings.EMPTY);
        final SecurityContext localSecurityContext = new SecurityContext(Settings.EMPTY, localThreadContext);
        final DlsFlsRequestCacheDifferentiator localDifferentiator = new DlsFlsRequestCacheDifferentiator(
            licenseState,
            new SetOnce<>(localSecurityContext),
            new SetOnce<>(realRenderingScriptService)
        );

        // A templated DLS query that resolves {{_user.metadata._foo}} into the term value.
        // The {"template":{"source":"..."}} envelope is the form SecurityQueryTemplateEvaluator
        // dispatches into MustacheTemplateEvaluator on; a non-templated query would short-circuit
        // through the pass-through branch and never reach the user-metadata substitution path.
        final String templatedQuery = """
            {"template":{"source":"{\\"term\\":{\\"x\\":\\"{{_user.metadata._foo}}\\"}}"}}""";
        final String templatedDlsIndex = "templated-dls-" + randomAlphaOfLengthBetween(3, 8);
        // Build a fresh IndicesAccessControl per invocation. DocumentPermissions memoizes its
        // listOfEvaluatedQueries on the first buildCacheKey call (a real performance win in
        // production where each request gets a fresh IAC anyway), so reusing one instance across
        // both the baseline and enriched runs would cause the second run to silently see the
        // first run's rendered query rather than the one rendered against the current user.
        final java.util.function.Supplier<IndicesAccessControl> makeIac = () -> new IndicesAccessControl(
            true,
            Map.of(
                templatedDlsIndex,
                new IndicesAccessControl.IndexAccessControl(
                    FieldPermissions.DEFAULT,
                    DocumentPermissions.filteredBy(Set.of(new BytesArray(templatedQuery)))
                )
            )
        );

        // Baseline user has no enrichment-provided metadata. Authentication must be on the
        // thread context because securityContext.getUser() reads it via the context serializer;
        // SecurityContext.executeWithEnrichedUserMetadata will then read this Authentication,
        // build a copy via Authentication.withEffectiveUser(enrichedUser), and swap it in
        // via a newStoredContext scope that clears only the Authentication key.
        final User baselineUser = new User("u", new String[] { "r" }, "Full Name", "u@example", Map.of(), true);
        final Authentication baselineAuth = AuthenticationTestHelper.builder().user(baselineUser).realm().build(false);
        try {
            baselineAuth.writeToContext(localThreadContext);
        } catch (IOException e) {
            throw new AssertionError("failed to write authentication to context", e);
        }

        when(shardSearchRequest.shardId()).thenReturn(
            new ShardId(templatedDlsIndex, randomAlphaOfLength(10), randomIntBetween(0, 3))
        );

        // Each phase wraps its differentiator call in a newStoredContext scope that clears the
        // IAC transient on entry, so each phase can install a fresh IAC via putIndicesAccessControl
        // (which refuses to overwrite an existing transient) and render its own DLS template
        // against the Authentication visible in that phase. DocumentPermissions memoizes its
        // listOfEvaluatedQueries on the first buildCacheKey call, so sharing an IAC across phases
        // would serve the first render's output to every subsequent one.
        final BytesStreamOutput baselineOut = runWithFreshIac(
            localThreadContext,
            localSecurityContext,
            makeIac,
            out -> localDifferentiator.accept(shardSearchRequest, out)
        );

        // Run the differentiator inside the enriched scope. executeWithEnrichedUserMetadata
        // swaps only the Authentication on the thread context -- the IAC placed above is still
        // visible inside the enrichment.
        final BytesStreamOutput enrichedOut = runWithFreshIac(
            localThreadContext,
            localSecurityContext,
            makeIac,
            out -> localSecurityContext.executeWithEnrichedUserMetadata(Map.of("_foo", "ENRICHED_VALUE"), () -> {
                try {
                    localDifferentiator.accept(shardSearchRequest, out);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            })
        );

        assertThat("baseline differentiator must write a cache key for any DLS index", baselineOut.position(), greaterThan(0L));
        assertThat("enriched differentiator must write a cache key for any DLS index", enrichedOut.position(), greaterThan(0L));

        // The enriched cache key MUST differ from the baseline. If this assertion fails, the
        // differentiator is not observing the rewritten Authentication -- meaning either
        // executeWithEnrichedUserMetadata is broken or someone has changed AuthorizationService
        // to invoke the dispatch outside the enriched scope.
        assertThat(
            "cache key bytes must change when enrichment shifts the rendered DLS query",
            enrichedOut.bytes(),
            not(equalTo(baselineOut.bytes()))
        );

        // And it must contain the literal substituted value -- proving the cache key was built
        // from the *rendered* template, not the raw template string.
        assertThat(
            "enriched cache key must contain the rendered substitution value",
            enrichedOut.bytes().utf8ToString(),
            containsString("ENRICHED_VALUE")
        );

        // After the enriched scope exits, the original Authentication must be back on the thread
        // context (the newStoredContext try-with-resources restores it). A subsequent render --
        // with a fresh IAC so we're not reading a memoized result -- must match the baseline.
        // A leaked enriched Authentication would silently corrupt subsequent requests on the
        // same thread, and this assertion would catch that.
        final BytesStreamOutput postScopeOut = runWithFreshIac(
            localThreadContext,
            localSecurityContext,
            makeIac,
            out -> localDifferentiator.accept(shardSearchRequest, out)
        );
        assertThat(
            "post-scope cache key must match baseline (enriched Authentication must not leak past scope exit)",
            postScopeOut.bytes(),
            equalTo(baselineOut.bytes())
        );
    }

    /**
     * Runs {@code body} with a fresh {@link IndicesAccessControl} transient installed on the
     * thread context. Any IAC previously on the context is stashed-and-restored automatically so
     * {@code SecurityContext#putIndicesAccessControl} (which refuses to overwrite an existing
     * transient) works regardless of prior state. Returns the {@link BytesStreamOutput} the body
     * wrote to, ready for the caller to assert against.
     */
    private static BytesStreamOutput runWithFreshIac(
        ThreadContext threadContext,
        SecurityContext securityContext,
        java.util.function.Supplier<IndicesAccessControl> iacSupplier,
        CheckedConsumer<BytesStreamOutput, IOException> body
    ) throws IOException {
        try (
            ThreadContext.StoredContext ignore = threadContext.newStoredContext(
                List.of(AuthorizationServiceField.INDICES_PERMISSIONS_VALUE.getKey()),
                List.of()
            )
        ) {
            securityContext.putIndicesAccessControl(iacSupplier.get());
            final BytesStreamOutput out = new BytesStreamOutput();
            body.accept(out);
            return out;
        }
    }

}
