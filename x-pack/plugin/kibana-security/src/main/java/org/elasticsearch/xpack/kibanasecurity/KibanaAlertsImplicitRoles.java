/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.kibanasecurity;

import org.elasticsearch.common.Strings;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.json.JsonXContent;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.store.ImplicitPrivilegesProvider;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Implicitly grants read access to {@code .alerts-*} for users whose roles include Kibana
 * application privileges with the {@code alerts:read} action.
 * <p>
 * When the user has access to specific spaces, a DLS query restricts visibility to documents
 * matching those spaces via the {@code kibana.space_ids} field. When the user has the wildcard
 * resource ({@code *}), full document access is granted with no DLS restriction.
 */
public class KibanaAlertsImplicitRoles implements ImplicitPrivilegesProvider {

    static final String KIBANA_APPLICATION = "kibana-.kibana";
    static final String ALERTS_ACTION = "alerts:read";
    static final String ALERTS_INDEX_PATTERN = ".alerts-*";
    static final String RESOURCE_PREFIX = "space:";
    static final String ALL_RESOURCES = "*";
    static final String INDEX_READ_PRIVILEGE = "read";

    @Override
    public Collection<RoleDescriptor.IndicesPrivileges> getImplicitIndicesPrivileges(
        RoleDescriptor roleDescriptor,
        Collection<ApplicationPrivilegeDescriptor> storedApplicationPrivileges
    ) {
        Set<String> matchingPrivilegeNames = storedApplicationPrivileges.stream()
            .filter(d -> KIBANA_APPLICATION.equals(d.getApplication()))
            .filter(d -> d.getActions().contains(ALERTS_ACTION))
            .map(ApplicationPrivilegeDescriptor::getName)
            .collect(Collectors.toSet());
        if (matchingPrivilegeNames.isEmpty()) {
            return List.of();
        }

        Set<String> resources = Stream.of(roleDescriptor.getApplicationPrivileges())
            .filter(p -> KIBANA_APPLICATION.equals(p.getApplication()))
            .filter(p -> Stream.of(p.getPrivileges()).anyMatch(matchingPrivilegeNames::contains))
            .flatMap(p -> Stream.of(p.getResources()))
            .collect(Collectors.toSet());
        if (resources.isEmpty()) {
            return List.of();
        }
        if (resources.contains(ALL_RESOURCES)) {
            return List.of(RoleDescriptor.IndicesPrivileges.builder().indices(ALERTS_INDEX_PATTERN).privileges(INDEX_READ_PRIVILEGE).build());
        }

        Set<String> spaceIds = resources.stream()
            .filter(r -> r.startsWith(RESOURCE_PREFIX))
            .map(r -> r.substring(RESOURCE_PREFIX.length()))
            .collect(Collectors.toSet());
        if (spaceIds.isEmpty()) {
            return List.of();
        }

        return List.of(
            RoleDescriptor.IndicesPrivileges.builder()
                .indices(ALERTS_INDEX_PATTERN)
                .privileges(INDEX_READ_PRIVILEGE)
                .query(buildSpaceIdsDlsQuery(spaceIds))
                .build()
        );
    }

    static String buildSpaceIdsDlsQuery(Set<String> spaceIds) {
        try (XContentBuilder builder = JsonXContent.contentBuilder()) {
            builder.startObject();
            builder.startObject("terms");
            builder.array("kibana.space_ids", spaceIds.toArray(new String[0]));
            builder.endObject();
            builder.endObject();
            return Strings.toString(builder);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
