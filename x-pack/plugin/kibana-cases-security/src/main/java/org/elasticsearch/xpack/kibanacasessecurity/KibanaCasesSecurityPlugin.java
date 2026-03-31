/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.kibanacasessecurity;

import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.xpack.core.security.SecurityExtension;
import org.elasticsearch.xpack.core.security.authz.store.ImplicitPrivilegesProvider;

import java.util.List;

/**
 * Provides implicit security privileges for Kibana Cases analytics indices.
 *
 * <p>This plugin extends the security plugin to inject index-level privileges
 * derived from Kibana application privileges, enabling users to search Cases
 * analytics data directly in Elasticsearch while respecting Kibana's
 * space-based access control.
 */
public class KibanaCasesSecurityPlugin extends Plugin implements SecurityExtension {

    @Override
    public List<ImplicitPrivilegesProvider> getImplicitPrivilegesProviders(SecurityComponents components) {
        return List.of(new KibanaCasesImplicitRoles());
    }
}
