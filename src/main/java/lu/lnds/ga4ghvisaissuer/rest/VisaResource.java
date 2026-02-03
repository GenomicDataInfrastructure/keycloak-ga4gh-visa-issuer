// SPDX-FileCopyrightText: 2026 PNED G.I.E.
//
// SPDX-License-Identifier: Apache-2.0

package lu.lnds.ga4ghvisaissuer.rest;

import lu.lnds.ga4ghvisaissuer.dto.GetPermissionsResponse;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.ServerAsymmetricSignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.stream.Collectors;

public class VisaResource {

    private final KeycloakSession session;

    public VisaResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Path("/api/jwk")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getJwk() {
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
    public Response getUserPermissions(@PathParam("user") String userIdentifier) {
        UserModel user = session.users()
                .searchForUserByUserAttributeStream(session.getContext().getRealm(), "elixir_id",
                        userIdentifier)
                .findFirst()
                .orElse(null);

        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("User not found").build();
        }

        List<String> passports = new ArrayList<>();

        // Helper to sign visas
        BiConsumer<String, String> addVisa = (type, value) -> {
            try {
                // Construct Claims
                long now = Instant.now().getEpochSecond();
                JsonWebToken visa = new JsonWebToken();
                visa.id(UUID.randomUUID().toString());

                // Construct Issuer URL manually as getRealmUrl() might be missing in
                // KeycloakUriInfo
                String issuer = session.getContext().getUri().getBaseUri().toString() + "realms/"
                        + session.getContext().getRealm().getName();
                visa.issuer(issuer);

                visa.subject(user.getUsername());
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
                org.keycloak.crypto.KeyWrapper key = session.keys().getActiveKey(session
                        .getContext().getRealm(),
                        KeyUse.SIG,
                        Algorithm.RS256);

                // Wrap KeyWrapper into SignatureSignerContext
                SignatureSignerContext signer = new ServerAsymmetricSignatureSignerContext(key);

                String token = new JWSBuilder()
                        .jsonContent(visa)
                        .sign(signer);
                passports.add(token);
            } catch (Exception e) {
                throw new RuntimeException("Failed to sign visa", e);
            }
        };

        // ResearcherStatus
        addVisa.accept("ResearcherStatus", "https://doi.org/10.1038/s41431-018-0219-y");

        // AcceptedTermsAndPolicies
        addVisa.accept("AcceptedTermsAndPolicies", "https://doi.org/10.1038/s41431-018-0219-y");

        GetPermissionsResponse response = GetPermissionsResponse.builder()
                .ga4ghPassportV1(passports)
                .build();

        return Response.ok(response).build();
    }
}
