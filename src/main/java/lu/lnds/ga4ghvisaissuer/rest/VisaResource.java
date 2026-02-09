// SPDX-FileCopyrightText: 2026 PNED G.I.E.
//
// SPDX-License-Identifier: Apache-2.0

package lu.lnds.ga4ghvisaissuer.rest;

import lu.lnds.ga4ghvisaissuer.dto.GetPermissionsResponse;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.ServerAsymmetricSignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;

import io.quarkus.security.ForbiddenException;
import io.quarkus.security.UnauthorizedException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

public class VisaResource {

    private static final String REQUIRED_ROLE = "ga4gh-visa-issuer";

    private final KeycloakSession session;

    public VisaResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Path("/api/jwk")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getJwk(@HeaderParam("Authorization") String authorizationHeader) {
        try {
            validateClient(authorizationHeader);
        } catch (UnauthorizedException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
        } catch (ForbiddenException e) {
            return Response.status(Response.Status.FORBIDDEN).entity(e.getMessage()).build();
        }

        List<JWK> jwks = session.keys().getKeysStream(session.getContext().getRealm())
                .filter(k -> k.getStatus().isEnabled() && k.getPublicKey() != null)
                .map(k -> {
                    return JWKBuilder.create().kid(k.getKid()).algorithm(k.getAlgorithmOrDefault())
                            .rsa(k.getPublicKey());
                })
                .collect(Collectors.toList());

        Map<String, Object> response = new HashMap<>();
        response.put("keys", jwks);

        return Response.ok(response).build();
    }

    @GET
    @Path("/api/permissions/{user}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserPermissions(
            @HeaderParam("Authorization") String authorizationHeader,
            @PathParam("user") String userIdentifier) {
        try {
            validateClient(authorizationHeader);
        } catch (UnauthorizedException e) {
            return Response.status(Response.Status.UNAUTHORIZED).entity(e.getMessage()).build();
        } catch (ForbiddenException e) {
            return Response.status(Response.Status.FORBIDDEN).entity(e.getMessage()).build();
        }

        List<UserModel> users = session.users()
                .searchForUserByUserAttributeStream(
                        session.getContext().getRealm(),
                        "elixir_id",
                        userIdentifier)
                .collect(Collectors.toList());

        if (users.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND).entity("User not found").build();
        }

        if (users.size() > 1) {
            return Response.status(Response.Status.CONFLICT).entity("Multiple users found").build();
        }

        UserModel user = users.get(0);

        List<String> passports = new ArrayList<>();

        try {
            // ResearcherStatus
            passports.add(signedVisaAsString(
                    user.getUsername(),
                    "ResearcherStatus",
                    "https://doi.org/10.1038/s41431-018-0219-y",
                    "so"));

            // AcceptedTermsAndPolicies
            passports.add(signedVisaAsString(
                    user.getUsername(),
                    "AcceptedTermsAndPolicies",
                    "https://doi.org/10.1038/s41431-018-0219-y",
                    "self"));
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(e.getMessage())
                    .build();
        }

        GetPermissionsResponse response = GetPermissionsResponse.builder()
                .ga4ghPassportV1(passports)
                .build();

        return Response.ok(response).build();
    }

    private String signedVisaAsString(String username, String type, String value, String by) {
        try {
            // Construct Claims
            long now = Instant.now().getEpochSecond();
            JsonWebToken visa = new JsonWebToken();
            visa.id(UUID.randomUUID().toString());

            // Construct Issuer URL manually as getRealmUrl() might be missing in
            // KeycloakUriInfo
            String issuer = session.getContext().getUri().getBaseUri().toString() + "/realms/"
                    + session.getContext().getRealm().getName();
            visa.issuer(issuer);

            visa.subject(username);
            visa.iat(now);
            visa.exp(now + 3600); // 1 hour expiration

            // GA4GH Visa Claims
            Map<String, Object> ga4ghClaims = new HashMap<>();
            ga4ghClaims.put("type", type);
            ga4ghClaims.put("value", value);
            ga4ghClaims.put("source", issuer);
            ga4ghClaims.put("asserted", now);
            ga4ghClaims.put("by", "system");

            visa.setOtherClaims("ga4gh_visa_v1", ga4ghClaims);

            // Sign using active realm key
            KeyWrapper key = session.keys().getActiveKey(session
                    .getContext().getRealm(),
                    KeyUse.SIG,
                    Algorithm.RS256);

            // Wrap KeyWrapper into SignatureSignerContext
            SignatureSignerContext signer = new ServerAsymmetricSignatureSignerContext(key);

            return new JWSBuilder()
                    .jsonContent(visa)
                    .sign(signer);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign visa", e);
        }
    }

    private void validateClient(String authorizationHeader) throws UnauthorizedException {
        RealmModel realm = session.getContext().getRealm();

        String[] parts = authorizationHeader.split(" ");
        if (parts.length != 2 || !parts[0].equalsIgnoreCase("Basic")) {
            throw new UnauthorizedException("Invalid authorization header");
        }

        String base64Credentials = parts[1];
        String decodedCredentials = new String(Base64.getDecoder().decode(base64Credentials));
        String[] credentials = decodedCredentials.split(":");
        if (credentials.length != 2) {
            throw new UnauthorizedException("Invalid authorization header");
        }

        String clientId = credentials[0];
        String providedSecret = credentials[1];

        // 1. Look up the client by its ID
        ClientModel client = realm.getClientByClientId(clientId);

        if (client == null) {
            throw new UnauthorizedException("Client not found");
        }

        // 2. Get the built-in secret from the client
        String actualSecret = client.getSecret();

        // 3. Validate
        if (actualSecret == null || !actualSecret.equals(providedSecret)) {
            throw new UnauthorizedException("Invalid client secret");
        }

        UserModel serviceAccountUser = session.users().getServiceAccount(client);

        if (serviceAccountUser == null) {
            throw new UnauthorizedException("Service Account not enabled for this client.");
        }

        RoleModel requiredRole = realm.getRole(REQUIRED_ROLE);

        // 4. Check if the client actually has this role
        if (requiredRole == null || !serviceAccountUser.hasRole(requiredRole)) {
            throw new ForbiddenException("Client lacks the '" + REQUIRED_ROLE + "' role.");
        }
    }
}
