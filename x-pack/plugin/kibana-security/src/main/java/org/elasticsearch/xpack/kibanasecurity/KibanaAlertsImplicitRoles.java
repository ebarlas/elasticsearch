/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.kibanasecurity;

import org.elasticsearch.common.Strings;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.json.JsonXContent;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;
import org.elasticsearch.xpack.core.security.authz.store.ImplicitPrivilegesProvider;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Implicitly grants index privileges to users whose roles include Kibana application privileges
 * with specific actions (e.g. {@code alerts:read}).
 * <p>
 * Each {@link ImplicitResourceConfig} maps a Kibana application privilege action to an index
 * pattern. When the user has access to specific
 * spaces, a DLS query restricts visibility to documents matching those spaces via the
 * {@code kibana.space_ids} field. When the user has the wildcard resource ({@code *}), full
 * document access is granted with no DLS restriction.
 */
public class KibanaAlertsImplicitRoles implements ImplicitPrivilegesProvider {

    static final String KIBANA_APPLICATION = "kibana-.kibana";
    static final String RESOURCE_PREFIX = "space:";
    static final String ALL_RESOURCES = "*";

    /**
     * Maps a Kibana application privilege action to the implicit index privilege it should produce.
     *
     * @param action       the application privilege action to match (e.g. {@code "alerts:read"})
     * @param indexPattern the index pattern to grant read access to (e.g. {@code ".alerts-*"})
     */
    record ImplicitResourceConfig(String action, String indexPattern) {}

    static final List<ImplicitResourceConfig> RESOURCE_CONFIGS = List.of(new ImplicitResourceConfig("alerts:read", ".alerts-*"));

    @Override
    public Collection<RoleDescriptor.IndicesPrivileges> getImplicitIndicesPrivileges(
        Collection<RoleDescriptor> roleDescriptors,
        Collection<ApplicationPrivilegeDescriptor> storedApplicationPrivileges
    ) {
        List<RoleDescriptor.IndicesPrivileges> result = new ArrayList<>();
        for (ImplicitResourceConfig config : RESOURCE_CONFIGS) {
            RoleDescriptor.IndicesPrivileges privilege = buildPrivilegeForConfig(config, roleDescriptors, storedApplicationPrivileges);
            if (privilege != null) {
                result.add(privilege);
            }
        }
        return result;
    }

    @Nullable
    static RoleDescriptor.IndicesPrivileges buildPrivilegeForConfig(
        ImplicitResourceConfig config,
        Collection<RoleDescriptor> roleDescriptors,
        Collection<ApplicationPrivilegeDescriptor> storedApplicationPrivileges
    ) {
        Set<String> matchingPrivilegeNames = storedApplicationPrivileges.stream()
            .filter(d -> KIBANA_APPLICATION.equals(d.getApplication()))
            .filter(d -> d.getActions().contains(config.action()))
            .map(ApplicationPrivilegeDescriptor::getName)
            .collect(Collectors.toSet());

        if (matchingPrivilegeNames.isEmpty()) {
            return null;
        }

        Set<String> spaceIds = new HashSet<>();
        boolean allSpaces = false;

        for (RoleDescriptor descriptor : roleDescriptors) {
            for (RoleDescriptor.ApplicationResourcePrivileges appPriv : descriptor.getApplicationPrivileges()) {
                if (!KIBANA_APPLICATION.equals(appPriv.getApplication())) {
                    continue;
                }

                boolean hasMatchingPrivilege = false;
                for (String privName : appPriv.getPrivileges()) {
                    if (matchingPrivilegeNames.contains(privName)) {
                        hasMatchingPrivilege = true;
                        break;
                    }
                }

                if (hasMatchingPrivilege) {
                    for (String resource : appPriv.getResources()) {
                        if (ALL_RESOURCES.equals(resource)) {
                            allSpaces = true;
                        } else if (resource.startsWith(RESOURCE_PREFIX)) {
                            spaceIds.add(resource.substring(RESOURCE_PREFIX.length()));
                        }
                    }
                }
            }
        }

        if (!allSpaces && spaceIds.isEmpty()) {
            return null;
        }

        RoleDescriptor.IndicesPrivileges.Builder builder = RoleDescriptor.IndicesPrivileges.builder()
            .indices(config.indexPattern())
            .privileges("read");

        if (!allSpaces) {
            builder.query(buildSpaceIdsDlsQuery(spaceIds));
        }

        return builder.build();
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
