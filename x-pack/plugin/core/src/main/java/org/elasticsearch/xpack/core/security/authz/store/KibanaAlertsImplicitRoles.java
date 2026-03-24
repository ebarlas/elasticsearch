/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz.store;

import org.elasticsearch.common.Strings;
import org.elasticsearch.xcontent.XContentBuilder;
import org.elasticsearch.xcontent.json.JsonXContent;
import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Implicitly grants {@code read} access to {@code .alerts-*} indices for users whose roles
 * include Kibana application privileges with the {@code alerts:read} action.
 * <p>
 * When the user has access to specific spaces, a DLS query restricts visibility to documents
 * matching those spaces via the {@code kibana.space_ids} field. When the user has the wildcard
 * resource ({@code *}), full access is granted with no DLS restriction.
 */
public class KibanaAlertsImplicitRoles implements ImplicitRoleDescriptorContributor {

    static final String KIBANA_APPLICATION = "kibana-.kibana";
    static final String ALERTS_READ_ACTION = "alerts:read";
    static final String RESOURCE_PREFIX = "space:";
    static final String ALL_RESOURCES = "*";
    static final String ALERTS_INDEX_PATTERN = ".alerts-*";

    @Override
    public Collection<RoleDescriptor.IndicesPrivileges> getImplicitIndicesPrivileges(
        Collection<RoleDescriptor> roleDescriptors,
        Collection<ApplicationPrivilegeDescriptor> storedApplicationPrivileges
    ) {
        Set<String> alertsReadPrivilegeNames = storedApplicationPrivileges.stream()
            .filter(d -> KIBANA_APPLICATION.equals(d.getApplication()))
            .filter(d -> d.getActions().contains(ALERTS_READ_ACTION))
            .map(ApplicationPrivilegeDescriptor::getName)
            .collect(Collectors.toSet());

        if (alertsReadPrivilegeNames.isEmpty()) {
            return List.of();
        }

        Set<String> spaceIds = new HashSet<>();
        boolean allSpaces = false;

        for (RoleDescriptor descriptor : roleDescriptors) {
            for (RoleDescriptor.ApplicationResourcePrivileges appPriv : descriptor.getApplicationPrivileges()) {
                if (KIBANA_APPLICATION.equals(appPriv.getApplication()) == false) {
                    continue;
                }

                boolean hasAlertsRead = false;
                for (String privName : appPriv.getPrivileges()) {
                    if (alertsReadPrivilegeNames.contains(privName)) {
                        hasAlertsRead = true;
                        break;
                    }
                }

                if (hasAlertsRead) {
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

        if (allSpaces == false && spaceIds.isEmpty()) {
            return List.of();
        }

        RoleDescriptor.IndicesPrivileges.Builder builder = RoleDescriptor.IndicesPrivileges.builder()
            .indices(ALERTS_INDEX_PATTERN)
            .privileges("read");

        if (allSpaces == false) {
            builder.query(buildSpaceIdsDlsQuery(spaceIds));
        }

        return List.of(builder.build());
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
