package lu.lnds.ga4ghvisaissuer;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.restassured.RestAssured;
import io.restassured.path.json.JsonPath;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;

import java.io.File;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.math.BigInteger;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Testcontainers
public class VisaIssuerIT {

    @Container
    @SuppressWarnings("resource")
    static GenericContainer<?> keycloak = new GenericContainer<>(
            new ImageFromDockerfile()
                    .withFileFromFile("Dockerfile", new File("src/test/resources/Dockerfile.test"))
                    .withFileFromFile(".", new File(".")))
            .withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            // Map the realm file to the import directory
            .withCopyFileToContainer(
                    MountableFile.forHostPath("realms/gdi-realm.json"),
                    "/opt/keycloak/data/import/gdi-realm.json")
            // Override command to match compose.yaml (start-dev with import)
            .withCommand("start-dev", "--import-realm")
            .waitingFor(Wait.forLogMessage(".*Listening on:.*", 1));

    @BeforeAll
    static void setup() {
        RestAssured.baseURI = "http://" + keycloak.getHost();
        RestAssured.port = keycloak.getMappedPort(8080);
    }

    @Test
    void testVisaIssuance() throws Exception {
        // 1. Fetch JWK
        // The JWK endpoint provided by the plugin:
        // /realms/{realm}/ga4gh-visa-issuer/api/jwk
        // Or standard Keycloak certs: /realms/{realm}/protocol/openid-connect/certs
        // The user asked to fetch from /api/jwk
        Map<String, Object> jwkSet = given()
                .get("/realms/gdi/ga4gh-visa-issuer/api/jwk")
                .then()
                .statusCode(200)
                .body("keys", hasSize(greaterThan(0)))
                .extract().as(new io.restassured.common.mapper.TypeRef<Map<String, Object>>() {
                });

        // 2. Get Visas for dummy user
        String permissionsResponse = given()
                .get("/realms/gdi/ga4gh-visa-issuer/api/permissions/dummy")
                .then()
                .statusCode(200)
                .body("ga4gh_passport_v1", not(empty()))
                .extract().asString();

        // 3. Validate Signature
        // The response contains "ga4gh_passport_v1": [ "jwt_string", ... ]
        List<String> visas = JsonPath.from(permissionsResponse).getList(
                "ga4gh_passport_v1",
                String.class);
        String visaJwt = visas.get(0);

        // Use standard Keycloak keys for validation or the keys returned by JWK
        // endpoint?
        // The plugin uses the realm's keys.
        // We can fetch the public key from the JWK endpoint response.

        // Simplified validation using auth0-jwt and the JWK
        // For strict validation, we need to parse the JWK.
        // Here we just decode to check structure for this example, or use a proper JWK
        // provider.
        // Since we have the JWK set from step 2, we can implement an RSAKeyProvider.

        DecodedJWT decoded = JWT.decode(visaJwt);
        String kid = decoded.getKeyId();

        // 4. Find matching JWK
        @SuppressWarnings("unchecked") List<Map<String, Object>> keys = (List<Map<String, Object>>) jwkSet
                .get("keys");
        Map<String, Object> jwk = keys.stream()
                .filter(k -> kid.equals(k.get("kid")))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("JWK not found for kid: " + kid));

        // 5. Construct Public Key
        String n = (String) jwk.get("n");
        String e = (String) jwk.get("e");

        byte[] modulusBytes = Base64.getUrlDecoder().decode(n);
        byte[] exponentBytes = Base64.getUrlDecoder().decode(e);
        BigInteger modulus = new BigInteger(1, modulusBytes);
        BigInteger publicExponent = new BigInteger(1, exponentBytes);

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) kf.generatePublic(spec);

        // 6. Verify Signature
        Algorithm algorithm = Algorithm.RSA256(publicKey, null);
        algorithm.verify(decoded);
        assertNotNull(decoded.getIssuer());
    }
}
