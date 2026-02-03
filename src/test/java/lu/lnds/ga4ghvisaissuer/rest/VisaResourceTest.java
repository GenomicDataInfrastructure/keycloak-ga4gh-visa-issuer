// SPDX-FileCopyrightText: 2026 PNED G.I.E.
//
// SPDX-License-Identifier: Apache-2.0

package lu.lnds.ga4ghvisaissuer.rest;

import lu.lnds.ga4ghvisaissuer.dto.GetPermissionsResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.KeyManager;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VisaResourceTest {

    @Mock
    private KeycloakSession session;
    @Mock
    private KeycloakContext context;
    @Mock
    private RealmModel realm;
    @Mock
    private KeycloakUriInfo uriInfo;
    @Mock
    private UserProvider userProvider;
    @Mock
    private UserModel user;
    @Mock
    private KeyManager keyManager;

    private VisaResource visaResource;

    @BeforeEach
    void setUp() throws Exception {
        visaResource = new VisaResource(session);

        // Common mocks
        lenient().when(session.getContext()).thenReturn(context);
        lenient().when(context.getRealm()).thenReturn(realm);
        lenient().when(context.getUri()).thenReturn(uriInfo);
        lenient().when(uriInfo.getBaseUri()).thenReturn(new URI("http://localhost:8080/"));
        lenient().when(realm.getName()).thenReturn("master");

        lenient().when(session.users()).thenReturn(userProvider);
        lenient().when(session.keys()).thenReturn(keyManager);
    }

    @Test
    void testGetJwk() {
        when(keyManager.getKeysStream(realm)).thenReturn(Stream.empty());

        Response response = visaResource.getJwk();
        assertEquals(200, response.getStatus());
        assertTrue(response.getEntity() instanceof java.util.Map);
    }

    @Test
    void testGetUserPermissions_UserFound_WithAttributes() throws Exception {
        String elixirId = "elixir-user";
        when(userProvider.searchForUserByUserAttributeStream(realm, "elixir_id", elixirId))
                .thenReturn(Stream.of(user));
        when(user.getUsername()).thenReturn("researcher");

        // Mock Key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setPrivateKey(kp.getPrivate());
        keyWrapper.setPublicKey(kp.getPublic());
        keyWrapper.setAlgorithm(Algorithm.RS256);
        keyWrapper.setKid("key-id");

        when(keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256)).thenReturn(keyWrapper);

        Response response = visaResource.getUserPermissions(elixirId);

        assertEquals(200, response.getStatus());
        GetPermissionsResponse permissions = (GetPermissionsResponse) response.getEntity();
        assertNotNull(permissions);
        assertNotNull(permissions.getGa4ghPassportV1());
        assertEquals(2, permissions.getGa4ghPassportV1().size());

        // Basic JWT verification (checking if it's a string looking like a JWT)
        String visa = permissions.getGa4ghPassportV1().get(0);
        assertTrue(visa.split("\\.").length == 3);
    }

    @Test
    void testGetUserPermissions_UserNotFound() {
        String elixirId = "unknown";
        when(userProvider.searchForUserByUserAttributeStream(realm, "elixir_id", elixirId))
                .thenReturn(Stream.empty());

        Response response = visaResource.getUserPermissions(elixirId);
        assertEquals(404, response.getStatus());
    }
}
