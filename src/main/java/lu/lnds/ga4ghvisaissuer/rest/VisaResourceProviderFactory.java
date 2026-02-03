// SPDX-FileCopyrightText: 2026 PNED G.I.E.
//
// SPDX-License-Identifier: Apache-2.0

package lu.lnds.ga4ghvisaissuer.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class VisaResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "ga4gh-visa-issuer";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new VisaResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration needed for now
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no post-initialization needed
    }

    @Override
    public void close() {
        // no resource cleanup needed
    }

    @Override
    public String getId() {
        return ID;
    }
}
