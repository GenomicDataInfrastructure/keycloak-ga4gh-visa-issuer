// SPDX-FileCopyrightText: 2026 PNED G.I.E.
//
// SPDX-License-Identifier: Apache-2.0

package lu.lnds.ga4ghvisaissuer.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class VisaResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public VisaResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new VisaResource(session);
    }

    @Override
    public void close() {
        // no cleanup needed
    }
}
