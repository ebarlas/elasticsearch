/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import org.elasticsearch.xpack.core.security.authz.store.ImplicitPrivilegesProvider;
import org.elasticsearch.xpack.kibanacasessecurity.KibanaCasesImplicitRoles;

module org.elasticsearch.kibanacasessecurity {
    requires org.elasticsearch.base;
    requires org.elasticsearch.server;
    requires org.elasticsearch.xcore;

    exports org.elasticsearch.xpack.kibanacasessecurity;

    provides ImplicitPrivilegesProvider with KibanaCasesImplicitRoles;
}
