/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.core.security.authz.store;

import org.elasticsearch.xpack.core.security.authz.RoleDescriptor;
import org.elasticsearch.xpack.core.security.authz.privilege.ApplicationPrivilegeDescriptor;

import java.util.Collection;

/**
 * Provides additional {@link RoleDescriptor.IndicesPrivileges} that should be implicitly
 * granted based on a user's application privileges.
 * <p>
 * During role building, after application privileges are resolved from the privilege store,
 * each registered contributor is invoked with the user's role descriptors and the stored
 * application privilege definitions. Any returned {@link RoleDescriptor.IndicesPrivileges}
 * entries are merged into the built role as if they had been declared explicitly.
 */
public interface ImplicitRoleDescriptorContributor {

    /**
     * Returns additional index privileges that should be implicitly added to the role
     * based on the user's role descriptors and stored application privilege definitions.
     *
     * @param roleDescriptors the user's resolved role descriptors
     * @param storedApplicationPrivileges the stored application privilege definitions
     *        loaded from the privilege store (may be empty if the user has no application privileges)
     * @return additional index privileges to merge into the role, or an empty collection if none
     */
    Collection<RoleDescriptor.IndicesPrivileges> getImplicitIndicesPrivileges(
        Collection<RoleDescriptor> roleDescriptors,
        Collection<ApplicationPrivilegeDescriptor> storedApplicationPrivileges
    );
}
