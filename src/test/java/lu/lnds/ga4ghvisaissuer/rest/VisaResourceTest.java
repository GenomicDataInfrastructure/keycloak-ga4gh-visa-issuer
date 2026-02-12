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
import org.keycloak.jose.jwk.JWK;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.KeyManager;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RoleModel;
import java.util.Base64;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.stream.Stream;
import java.util.List;
import java.util.Map;

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
    @Mock
    private ClientModel client;
    @Mock
    private UserModel serviceAccountUser;
    @Mock
    private RoleModel role;

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
    @SuppressWarnings("unchecked")
    void testGetJwk_KeyStatusNull() {
        // Mock a key with null status
        KeyWrapper keyWithError = new KeyWrapper();
        keyWithError.setAlgorithm(Algorithm.RS256);
        // implicit null status

        when(keyManager.getKeysStream(realm)).thenReturn(Stream.of(keyWithError));

        Response response = visaResource.getJwk();
        assertEquals(200, response.getStatus());
        Map<String, Object> entity = (Map<String, Object>) response.getEntity();
        List<JWK> keys = (List<JWK>) entity.get("keys");
        assertTrue(keys.isEmpty()); // Should be filtered out safely, not throw NPE
    }

    @Test
    void testGetUserPermissions_UserFound_WithAttributes() throws Exception {
        String elixirId = "elixir-user";
        when(userProvider.searchForUserByUserAttributeStream(realm, "elixir_id", elixirId))
                .thenReturn(Stream.of(user));
        when(user.getUsername()).thenReturn("researcher");

        // Mock Auth
        String clientId = "gdi";
        String secret = "secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret)
                .getBytes());

        when(realm.getClientByClientId(clientId)).thenReturn(client);
        when(client.getSecret()).thenReturn(secret);
        when(session.users().getServiceAccount(client)).thenReturn(serviceAccountUser);
        when(realm.getRole("ga4gh-visa-issuer")).thenReturn(role);
        when(serviceAccountUser.hasRole(role)).thenReturn(true);

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

        Response response = visaResource.getUserPermissions(authHeader, elixirId);

        assertEquals(200, response.getStatus());
        GetPermissionsResponse permissions = (GetPermissionsResponse) response.getEntity();
        assertNotNull(permissions);
        assertNotNull(permissions.getGa4ghPassportV1());
        assertEquals(2, permissions.getGa4ghPassportV1().size());

        // Basic JWT verification (checking if it's a string looking like a JWT)
        String visaString = permissions.getGa4ghPassportV1().get(0);
        assertTrue(visaString.split("\\.").length == 3);

        // Verify jku header
        DecodedJWT visa = JWT.decode(visaString);
        String jku = visa.getHeaderClaim("jku").asString();
        assertNotNull(jku, "jku header should be present");
        assertTrue(jku.endsWith("/realms/master/protocol/openid-connect/certs"));
    }

    @Test
    void testGetUserPermissions_UserNotFound() {
        String elixirId = "unknown";
        when(userProvider.searchForUserByUserAttributeStream(realm, "elixir_id", elixirId))
                .thenReturn(Stream.empty());

        // Mock Auth
        String clientId = "gdi";
        String secret = "secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret)
                .getBytes());

        when(realm.getClientByClientId(clientId)).thenReturn(client);
        when(client.getSecret()).thenReturn(secret);
        when(session.users().getServiceAccount(client)).thenReturn(serviceAccountUser);
        when(realm.getRole("ga4gh-visa-issuer")).thenReturn(role);
        when(serviceAccountUser.hasRole(role)).thenReturn(true);

        Response response = visaResource.getUserPermissions(authHeader, elixirId);
        assertEquals(404, response.getStatus());
    }

    @Test
    void testGetUserPermissions_MultipleUsersFound() {
        String elixirId = "ambiguous-user";
        when(userProvider.searchForUserByUserAttributeStream(realm, "elixir_id", elixirId))
                .thenReturn(Stream.of(user, user));

        // Mock Auth
        String clientId = "gdi";
        String secret = "secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret)
                .getBytes());

        when(realm.getClientByClientId(clientId)).thenReturn(client);
        when(client.getSecret()).thenReturn(secret);
        when(session.users().getServiceAccount(client)).thenReturn(serviceAccountUser);
        when(realm.getRole("ga4gh-visa-issuer")).thenReturn(role);
        when(serviceAccountUser.hasRole(role)).thenReturn(true);

        Response response = visaResource.getUserPermissions(authHeader, elixirId);
        assertEquals(409, response.getStatus());
    }

    @Test
    void testGetUserPermissions_InternalServerError() {
        String elixirId = "error-user";
        when(userProvider.searchForUserByUserAttributeStream(realm, "elixir_id", elixirId))
                .thenReturn(Stream.of(user));
        when(keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256))
                .thenThrow(new RuntimeException("Signing failed"));

        // Mock Auth
        String clientId = "gdi";
        String secret = "secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret)
                .getBytes());

        when(realm.getClientByClientId(clientId)).thenReturn(client);
        when(client.getSecret()).thenReturn(secret);
        when(session.users().getServiceAccount(client)).thenReturn(serviceAccountUser);
        when(realm.getRole("ga4gh-visa-issuer")).thenReturn(role);
        when(serviceAccountUser.hasRole(role)).thenReturn(true);

        Response response = visaResource.getUserPermissions(authHeader, elixirId);
        assertEquals(500, response.getStatus());
    }

    @Test
    void testGetUserPermissions_ActiveKeyNull() {
        String elixirId = "elixir-user";
        when(userProvider.searchForUserByUserAttributeStream(realm, "elixir_id", elixirId))
                .thenReturn(Stream.of(user));
        when(user.getUsername()).thenReturn("researcher");

        // Mock active key returning null
        when(keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.RS256)).thenReturn(null);

        // Mock Auth
        String clientId = "gdi";
        String secret = "secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret)
                .getBytes());

        when(realm.getClientByClientId(clientId)).thenReturn(client);
        when(client.getSecret()).thenReturn(secret);
        when(session.users().getServiceAccount(client)).thenReturn(serviceAccountUser);
        when(realm.getRole("ga4gh-visa-issuer")).thenReturn(role);
        when(serviceAccountUser.hasRole(role)).thenReturn(true);

        Response response = visaResource.getUserPermissions(authHeader, elixirId);
        // Expect 500 because we throw RuntimeException which maps to 500 in the catch
        // block
        assertEquals(500, response.getStatus());
        assertEquals("Active key not found for realm", response.getEntity());
    }

    @Test
    void testValidateClient_MissingAuthHeader() {
        Response response = visaResource.getUserPermissions(null, "dummy");
        assertEquals(401, response.getStatus());
        assertEquals("Authorization header is missing", response.getEntity());
        assertEquals("Basic realm=\"master\"", response.getHeaderString("WWW-Authenticate"));
    }

    @Test
    void testValidateClient_InvalidAuthHeaderFormat() {
        Response response = visaResource.getUserPermissions("Bearer token", "dummy");
        assertEquals(401, response.getStatus());
        assertEquals("Invalid authorization header", response.getEntity());
        assertEquals("Basic realm=\"master\"", response.getHeaderString("WWW-Authenticate"));
    }

    @Test
    void testValidateClient_InvalidBase64Credentials() {
        // "invalidhash" is not valid base64 or decodes to something without ":"
        // Let's use valid base64 that doesn't have a colon
        String invalidCreds = Base64.getEncoder().encodeToString("nocolon".getBytes());
        Response response = visaResource.getUserPermissions("Basic " + invalidCreds, "dummy");
        assertEquals(401, response.getStatus());
        assertEquals("Invalid client credentials", response.getEntity());
        assertEquals("Basic realm=\"master\"", response.getHeaderString("WWW-Authenticate"));
    }

    @Test
    void testValidateClient_MalformedBase64() {
        Response response = visaResource.getUserPermissions("Basic invalidbase64!!!!", "dummy");
        assertEquals(401, response.getStatus());
        assertEquals("Failed to decode authorization header", response.getEntity());
        assertEquals("Basic realm=\"master\"", response.getHeaderString("WWW-Authenticate"));
    }

    @Test
    void testValidateClient_ClientNotFound() {
        String clientId = "unknown-client";
        String secret = "secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret)
                .getBytes());

        when(realm.getClientByClientId(clientId)).thenReturn(null);

        Response response = visaResource.getUserPermissions(authHeader, "dummy");
        assertEquals(401, response.getStatus());
        assertEquals("Client not found", response.getEntity());
        assertEquals("Basic realm=\"master\"", response.getHeaderString("WWW-Authenticate"));
    }

    @Test
    void testValidateClient_InvalidClientSecret() {
        String clientId = "gdi";
        String secret = "wrong-secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret)
                .getBytes());

        when(realm.getClientByClientId(clientId)).thenReturn(client);
        when(client.getSecret()).thenReturn("actual-secret");

        Response response = visaResource.getUserPermissions(authHeader, "dummy");
        assertEquals(401, response.getStatus());
        assertEquals("Invalid client secret", response.getEntity());
        assertEquals("Basic realm=\"master\"", response.getHeaderString("WWW-Authenticate"));
    }

    @Test
    void testValidateClient_ServiceAccountNotEnabled() {
        String clientId = "gdi";
        String secret = "secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret)
                .getBytes());

        when(realm.getClientByClientId(clientId)).thenReturn(client);
        when(client.getSecret()).thenReturn(secret);
        when(session.users().getServiceAccount(client)).thenReturn(null);

        Response response = visaResource.getUserPermissions(authHeader, "dummy");
        assertEquals(401, response.getStatus());
        assertEquals("Service Account not enabled for this client.", response.getEntity());
        assertEquals("Basic realm=\"master\"", response.getHeaderString("WWW-Authenticate"));
    }

    @Test
    void testValidateClient_ClientLacksRole() {
        String clientId = "gdi";
        String secret = "secret";
        String authHeader = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + secret)
                .getBytes());

        when(realm.getClientByClientId(clientId)).thenReturn(client);
        when(client.getSecret()).thenReturn(secret);
        when(session.users().getServiceAccount(client)).thenReturn(serviceAccountUser);
        when(realm.getRole("ga4gh-visa-issuer")).thenReturn(role);
        when(serviceAccountUser.hasRole(role)).thenReturn(false);

        Response response = visaResource.getUserPermissions(authHeader, "dummy");
        assertEquals(403, response.getStatus());
        assertEquals("Client lacks the 'ga4gh-visa-issuer' role.", response.getEntity());
    }
}
