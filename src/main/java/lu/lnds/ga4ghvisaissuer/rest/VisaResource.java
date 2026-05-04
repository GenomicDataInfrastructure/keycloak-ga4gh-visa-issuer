// SPDX-FileCopyrightText: 2026 PNED G.I.E.
//
// SPDX-License-Identifier: Apache-2.0

package lu.lnds.ga4ghvisaissuer.rest;

import lu.lnds.ga4ghvisaissuer.dto.GetPermissionsResponse;
import lu.lnds.ga4ghvisaissuer.dto.VisaType;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.ServerAsymmetricSignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.java.Log;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Log
public class VisaResource {

    private static final String REQUIRED_ROLE = "ga4gh-visa-issuer";
    private static final String DEFAULT_REALM_ROLE_PREFIX = "default-roles-";
    private static final String OFFLINE_ACCESS_ROLE = "offline_access";
    private static final String UMA_AUTHORIZATION_ROLE = "uma_authorization";

    private static final List<String> ROLE_ATTRIBUTE_KEYS = List.of(
            "role",
            "roles",
            "user_role",
            "user_roles",
            "researcher_status");

    private static final List<String> ROLE_ASSERTED_ATTRIBUTE_KEYS = List.of(
            "role_asserted",
            "roles_asserted",
            "role_assigned",
            "role_assigned_at",
            "researcher_status_asserted");

    private static final List<String> TERMS_ATTRIBUTE_KEYS = List.of(
            "accepted_terms_and_policies",
            "accepted_terms_and_conditions",
            "accepted_terms",
            "terms_and_conditions");

    private static final List<String> TERMS_ASSERTED_ATTRIBUTE_KEYS = List.of(
            "accepted_terms_and_policies_asserted",
            "accepted_terms_and_conditions_asserted",
            "accepted_terms_asserted",
            "terms_and_conditions_asserted",
            "terms_and_conditions_accepted_at");

    private final KeycloakSession session;

    public VisaResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Path("/api/permissions/{user}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getUserPermissions(
            @HeaderParam("Authorization") String authorizationHeader,
            @PathParam("user") String userIdentifier) {
        Response response = validateClient(authorizationHeader);
        if (response != null) {
            return response;
        }

        List<UserModel> users = session.users()
                .searchForUserByUserAttributeStream(
                        session.getContext().getRealm(),
                        "elixir_id",
                        userIdentifier)
                .toList();

        if (users.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND).entity("User not found").build();
        }

        if (users.size() > 1) {
            return Response.status(Response.Status.CONFLICT).entity("Multiple users found").build();
        }

        UserModel user = users.get(0);

        List<VisaClaim> visaClaims = collectVisaClaims(user);
        List<String> passports = new ArrayList<>();

        try {
            for (VisaClaim visaClaim : visaClaims) {
                passports.add(signedVisaAsString(
                        user.getUsername(),
                        visaClaim.type(),
                        visaClaim.value(),
                        visaClaim.by(),
                        visaClaim.asserted()));
            }
        } catch (Exception e) {
            log.log(Level.INFO, "Failed to sign visa: " + e.getMessage(), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(e.getMessage())
                    .build();
        }

        return Response.ok(GetPermissionsResponse.builder()
                .ga4ghPassportV1(passports)
                .build())
                .build();
    }

    private List<VisaClaim> collectVisaClaims(UserModel user) {
        long fallbackAsserted = getFallbackAsserted(user);
        List<VisaClaim> visaClaims = new ArrayList<>();
        visaClaims.addAll(buildResearcherStatusVisas(user, fallbackAsserted));
        visaClaims.addAll(buildAcceptedTermsAndPoliciesVisas(user, fallbackAsserted));
        return visaClaims;
    }

    private List<VisaClaim> buildResearcherStatusVisas(UserModel user, long fallbackAsserted) {
        List<String> roleValues = new ArrayList<>();

        for (String key : ROLE_ATTRIBUTE_KEYS) {
            roleValues.addAll(getNormalizedAttributeValues(user, key));
        }

        // Fallback to Keycloak role mappings when custom role attributes are not present.
        if (roleValues.isEmpty()) {
            String defaultRoleName = DEFAULT_REALM_ROLE_PREFIX + session.getContext().getRealm()
                    .getName();
            roleValues = user.getRoleMappingsStream()
                    .map(RoleModel::getName)
                    .filter(roleName -> !roleName.equals(defaultRoleName))
                    .filter(roleName -> !OFFLINE_ACCESS_ROLE.equals(roleName))
                    .filter(roleName -> !UMA_AUTHORIZATION_ROLE.equals(roleName))
                    .distinct()
                    .toList();
        }

        List<Long> assertedValues = getAssertedValues(user, ROLE_ASSERTED_ATTRIBUTE_KEYS);
        List<VisaClaim> claims = new ArrayList<>();
        Set<String> deduplicatedRoles = new LinkedHashSet<>(roleValues);
        int index = 0;
        for (String roleValue : deduplicatedRoles) {
            claims.add(new VisaClaim(
                    VisaType.ResearcherStatus.name(),
                    roleValue,
                    "so",
                    getAssertedAtIndex(assertedValues, index, fallbackAsserted)));
            index++;
        }
        return claims;
    }

    private List<VisaClaim> buildAcceptedTermsAndPoliciesVisas(UserModel user,
            long fallbackAsserted) {
        List<TermsEntry> entries = new ArrayList<>();

        for (String key : TERMS_ATTRIBUTE_KEYS) {
            entries.addAll(parseTermsEntriesFromAttributeValues(
                    getNormalizedAttributeValues(user, key),
                    fallbackAsserted));
        }

        if (entries.isEmpty()) {
            return Collections.emptyList();
        }

        List<Long> assertedValues = getAssertedValues(user, TERMS_ASSERTED_ATTRIBUTE_KEYS);
        List<VisaClaim> claims = new ArrayList<>();
        for (int i = 0; i < entries.size(); i++) {
            TermsEntry entry = entries.get(i);
            long asserted = entry.asserted() != null
                    ? entry.asserted()
                    : getAssertedAtIndex(assertedValues, i, fallbackAsserted);
            claims.add(new VisaClaim(
                    VisaType.AcceptedTermsAndPolicies.name(),
                    entry.value(),
                    "self",
                    asserted));
        }
        return claims;
    }

    private List<TermsEntry> parseTermsEntriesFromAttributeValues(List<String> attributeValues,
            long fallbackAsserted) {
        List<TermsEntry> entries = new ArrayList<>();

        for (String attributeValue : attributeValues) {
            String normalized = attributeValue.trim();
            if (normalized.isEmpty()) {
                continue;
            }

            TermsEntry parsed = parseStructuredTermsEntry(normalized);
            if (parsed != null) {
                entries.add(parsed);
                continue;
            }

            // JSON-like payloads should provide structured data; skip invalid ones.
            if (normalized.startsWith("{")) {
                continue;
            }

            entries.add(new TermsEntry(normalized, fallbackAsserted));
        }

        // Preserve insertion order while deduplicating exact duplicates.
        Set<TermsEntry> deduplicatedEntries = new LinkedHashSet<>(entries);
        return new ArrayList<>(deduplicatedEntries);
    }

    private TermsEntry parseStructuredTermsEntry(String attributeValue) {
        if (attributeValue.startsWith("{")) {
            try {
                @SuppressWarnings("unchecked") Map<String, Object> json = org.keycloak.util.JsonSerialization
                        .readValue(
                                attributeValue, Map.class);
                String value = firstNonBlank(
                        objectAsString(json.get("value")),
                        objectAsString(json.get("url")),
                        objectAsString(json.get("version")));
                if (value == null) {
                    return null;
                }
                Long asserted = Stream.of(
                        json.get("asserted"),
                        json.get("accepted"),
                        json.get("accepted_at"),
                        json.get("acceptedAt"))
                        .map(this::parseEpochSecond)
                        .filter(OptionalLong::isPresent)
                        .map(OptionalLong::getAsLong)
                        .findFirst()
                        .orElse(null);
                return new TermsEntry(value, asserted);
            } catch (Exception ignored) {
                // Fall through to delimiter parsing.
            }
        }

        if (attributeValue.contains("|")) {
            String[] parts = attributeValue.split("\\|");
            if (parts.length == 2) {
                String left = parts[0].trim();
                String right = parts[1].trim();
                OptionalLong leftAsEpoch = parseEpochSecond(left);
                OptionalLong rightAsEpoch = parseEpochSecond(right);

                if (leftAsEpoch.isPresent() && !rightAsEpoch.isPresent()) {
                    return new TermsEntry(right, leftAsEpoch.getAsLong());
                }
                if (rightAsEpoch.isPresent() && !leftAsEpoch.isPresent()) {
                    return new TermsEntry(left, rightAsEpoch.getAsLong());
                }
            }
        }

        return null;
    }

    private List<Long> getAssertedValues(UserModel user, List<String> attributeKeys) {
        return attributeKeys.stream()
                .flatMap(key -> getAttributeValues(user, key).stream())
                .map(this::parseEpochSecond)
                .filter(OptionalLong::isPresent)
                .map(OptionalLong::getAsLong)
                .collect(Collectors.toList());
    }

    private List<String> getNormalizedAttributeValues(UserModel user, String key) {
        return getAttributeValues(user, key).stream()
                .flatMap(value -> Stream.of(value.split(",")))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .collect(Collectors.toList());
    }

    private List<String> getAttributeValues(UserModel user, String key) {
        Map<String, List<String>> attributes = user.getAttributes();
        if (attributes == null) {
            return Collections.emptyList();
        }
        return attributes.getOrDefault(key, Collections.emptyList());
    }

    private long getFallbackAsserted(UserModel user) {
        Long createdTimestamp = user.getCreatedTimestamp();
        if (createdTimestamp != null && createdTimestamp > 0) {
            return createdTimestamp / 1000;
        }
        return Instant.now().getEpochSecond();
    }

    private long getAssertedAtIndex(List<Long> assertedValues, int index, long fallbackAsserted) {
        if (index >= 0 && index < assertedValues.size()) {
            return assertedValues.get(index);
        }
        return fallbackAsserted;
    }

    private OptionalLong parseEpochSecond(Object rawValue) {
        String value = objectAsString(rawValue);
        if (value == null || value.isBlank()) {
            return OptionalLong.empty();
        }
        try {
            long parsed = Long.parseLong(value.trim());
            // Support epoch milliseconds while storing in seconds.
            return OptionalLong.of(parsed > 9_999_999_999L ? parsed / 1000 : parsed);
        } catch (NumberFormatException e) {
            try {
                return OptionalLong.of(Instant.parse(value.trim()).getEpochSecond());
            } catch (Exception ignored) {
                return OptionalLong.empty();
            }
        }
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private String objectAsString(Object value) {
        if (value == null) {
            return null;
        }
        return String.valueOf(value);
    }

    @SuppressWarnings("deprecation")
    private String signedVisaAsString(String username, String type, String value, String by,
            long asserted) {
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
        ga4ghClaims.put("asserted", asserted);
        ga4ghClaims.put("by", by);

        visa.setOtherClaims("ga4gh_visa_v1", ga4ghClaims);

        // Sign using active realm key
        KeyWrapper key = session.keys().getActiveKey(session
                .getContext().getRealm(),
                KeyUse.SIG,
                Algorithm.RS256);

        if (key == null) {
            throw new IllegalArgumentException("Active key not found for realm");
        }

        // Wrap KeyWrapper into SignatureSignerContext
        SignatureSignerContext signer = new ServerAsymmetricSignatureSignerContext(key);

        JWSHeader header = new JWSHeader(Enum.valueOf(org.keycloak.jose.jws.Algorithm.class,
                signer.getAlgorithm()), "JWT", null);
        header.setKeyId(signer.getKid());
        header.setOtherClaims("jku", issuer + "/protocol/openid-connect/certs");

        try {
            String headerB64 = java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(org.keycloak.util.JsonSerialization.writeValueAsBytes(header));
            String contentB64 = java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(org.keycloak.util.JsonSerialization.writeValueAsBytes(visa));

            byte[] signatureData = (headerB64 + "." + contentB64).getBytes(
                    java.nio.charset.StandardCharsets.UTF_8);
            byte[] signature = signer.sign(signatureData);
            String signatureB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                    signature);

            return headerB64 + "." + contentB64 + "." + signatureB64;
        } catch (java.io.IOException e) {
            throw new RuntimeException("Failed to serialize JWT", e);
        }
    }

    private Response validateClient(String authorizationHeader) {
        if (authorizationHeader == null) {
            return buildUnauthorizedError("Authorization header is missing");
        }

        String[] parts = authorizationHeader.split(" ");
        if (parts.length != 2 || !parts[0].equalsIgnoreCase("Basic")) {
            return buildUnauthorizedError("Invalid authorization header");
        }

        String base64Credentials = parts[1];
        String decodedCredentials;
        try {
            decodedCredentials = new String(Base64.getDecoder().decode(base64Credentials));
        } catch (IllegalArgumentException e) {
            log.log(Level.INFO, "Failed to decode authorization header: " + e.getMessage(), e);
            return buildUnauthorizedError("Failed to decode authorization header");
        }
        String[] credentials = decodedCredentials.split(":");
        if (credentials.length != 2) {
            return buildUnauthorizedError("Invalid client credentials");
        }

        String clientId = credentials[0];
        String providedSecret = credentials[1];

        RealmModel realm = session.getContext().getRealm();

        // 1. Look up the client by its ID
        ClientModel client = realm.getClientByClientId(clientId);

        if (client == null) {
            return buildUnauthorizedError("Client not found");
        }

        // 2. Get the built-in secret from the client
        String actualSecret = client.getSecret();

        // 3. Validate
        if (actualSecret == null || !actualSecret.equals(providedSecret)) {
            return buildUnauthorizedError("Invalid client secret");
        }

        UserModel serviceAccountUser = session.users().getServiceAccount(client);

        if (serviceAccountUser == null) {
            return buildUnauthorizedError("Service Account not enabled for this client.");
        }

        RoleModel requiredRole = realm.getRole(REQUIRED_ROLE);

        // 4. Check if the client actually has this role
        if (requiredRole == null || !serviceAccountUser.hasRole(requiredRole)) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity("Client lacks the '" + REQUIRED_ROLE + "' role.")
                    .build();
        }

        return null;
    }

    private Response buildUnauthorizedError(String message) {
        return Response.status(Response.Status.UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"" + session.getContext().getRealm()
                        .getName() + "\"")
                .entity(message)
                .build();
    }

    private record VisaClaim(String type, String value, String by, long asserted) {
    }

    private record TermsEntry(String value, Long asserted) {
    }
}
