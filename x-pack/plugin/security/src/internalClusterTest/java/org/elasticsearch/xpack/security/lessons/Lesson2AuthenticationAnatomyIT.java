/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.security.lessons;

import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.elasticsearch.xpack.core.security.authc.Authentication;
import org.elasticsearch.xpack.core.security.authc.AuthenticationField;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Capture;
import org.elasticsearch.xpack.security.lessons.LessonProbe.Point;

import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.not;

/**
 * <h2>Lesson 2: what an Authentication is, and why an API key's is so much bigger than a user's</h2>
 *
 * <h3>The idea</h3>
 * An {@code Authentication} answers "who is calling?". It holds a <em>subject</em>: a user, the realm that vouched for them, and a
 * free-form {@code metadata} map. When a request is run-as another user it holds two subjects, but that is not our concern.
 *
 * <pre>
 *   Authentication
 *     └─ authenticatingSubject
 *          ├─ user       principal, roles, ...
 *          ├─ realm      name, type, node
 *          └─ metadata   Map&lt;String,Object&gt;
 *               ├─ user in a realm:  empty (nothing extra to remember)
 *               └─ API key:          the key's id and name, plus two BLOBS
 *                    ├─ _security_api_key_role_descriptors             what the key was created with
 *                    └─ _security_api_key_limited_by_role_descriptors  the owner's permissions at creation time
 * </pre>
 *
 * <h3>Why API keys carry their role descriptors</h3>
 * A node that receives a request has to authorize it, and for an API key the permissions are defined by those descriptors. Rather
 * than look them up again, they travel inside the Authentication. A Fleet agent's key has one index pattern per integration it is
 * allowed to write to, so the blob is kilobytes, and it rides in <em>every</em> request the agent sends.
 *
 * <h3>What the test shows</h3>
 * The same one-document bulk is sent under three identities. Compare the metadata, the encoded header length (the string that
 * travels, see lesson 1) and {@code ramBytesUsed()} (the estimate the change adds, see lesson 4).
 *
 * <h3>Where to set breakpoints</h3>
 * {@code ApiKeyService#authenticateWithApiKeyIfPresent} (where the metadata is filled in), {@code Authentication#encode} (what
 * becomes the header) and {@code Authentication#ramBytesUsed}.
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 2, numClientNodes = 0, supportsDedicatedMasters = false)
@TestLogging(reason = "lesson output", value = "org.elasticsearch.xpack.security.lessons:INFO")
public class Lesson2AuthenticationAnatomyIT extends LessonCase {

    public void testThreeIdentitiesCompared() throws Exception {
        createIndexOnDataNode();

        step(1, "create a small and a Fleet-like API key");
        final String smallKey = createApiKey("small", smallRoleDescriptor());
        final String fleetKey = createApiKey("fleet-like", fleetLikeRoleDescriptor());

        // Run one bulk per identity and keep the Authentication the coordinator was holding for it (captured when the shard request
        // was sent). Each is a real Authentication produced by the real security code.
        step(2, "run one bulk per identity and keep the coordinator's Authentication for each");
        final Authentication user = authenticationFor(rootAuthorization());
        final Authentication small = authenticationFor(smallKey);
        final Authentication fleet = authenticationFor(fleetKey);

        // (a) A user authenticated by a realm: no metadata at all, a tiny header.
        step(3, "describe each Authentication: metadata, encoded header length, estimate");
        describe("(a) root user", user);
        // (b) An API key with one small descriptor: the two blobs are there, but small.
        describe("(b) API key, small descriptor", small);
        // (c) An API key shaped like a Fleet agent's: the same two blobs, one of them ~8 KB, 70 index patterns.
        describe("(c) API key, Fleet-like descriptor", fleet);

        // The user's metadata is empty; both keys carry the two blobs as BytesReferences.
        claim("a user has no API key blobs; both keys carry two BytesReference blobs");
        assertThat(user.getAuthenticatingSubject().getMetadata(), not(hasKey(AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY)));
        for (Authentication key : new Authentication[] { small, fleet }) {
            final Map<String, Object> metadata = key.getAuthenticatingSubject().getMetadata();
            assertThat(metadata.get(AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY), instanceOf(BytesReference.class));
            assertThat(metadata.get(AuthenticationField.API_KEY_LIMITED_ROLE_DESCRIPTORS_KEY), instanceOf(BytesReference.class));
        }

        // The Fleet-like key's descriptor blob is what makes it big. (The limited-by blob here is the root user's small superuser
        // descriptor; for a real Fleet agent it was a further ~2.8 KB.) Because the encoded header embeds both blobs, the header is
        // an order of magnitude longer than for a plain user, and that is the string sent on every hop.
        final int smallBlob = blob(small).length();
        final int fleetBlob = blob(fleet).length();
        say("descriptor blob bytes: small=%d fleet-like=%d", smallBlob, fleetBlob);
        say("encoded header chars: user=%d fleet-like=%d", user.encode().length(), fleet.encode().length());
        claim("the Fleet-like blob and header dwarf the small key's and the user's");
        assertThat(fleetBlob, greaterThan(5_000));
        assertThat(fleetBlob, greaterThan(10 * smallBlob));
        assertThat(fleet.encode().length(), greaterThan(10 * user.encode().length()));
        assertThat(fleet.isApiKey(), equalTo(true));
        takeaway("an API key's Authentication embeds its role descriptors, so its header and heap cost scale with the descriptors, not the payload");
    }

    private Authentication authenticationFor(String authorization) {
        as(coordinator(), authorization).bulk(oneDocumentBulk()).actionGet();
        final Capture sent = LessonProbe.captures(Point.SENT, LessonProbe.BULK_SHARD).getLast();
        return sent.authentication();
    }

    static BytesReference blob(Authentication authentication) {
        return (BytesReference) authentication.getAuthenticatingSubject().getMetadata().get(AuthenticationField.API_KEY_ROLE_DESCRIPTORS_KEY);
    }
}
