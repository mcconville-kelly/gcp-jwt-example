package com.example.friendlydemo;

import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.GenericData;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;

class JwtTest {

    private static final long EXPIRATION_TIME_IN_SECONDS = 3600L;
    private static final String JWT_BEARER_TOKEN_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    private static final String OAUTH_TOKEN_URI = "https://www.googleapis.com/oauth2/v4/token";
    private static final HttpTransport httpTransport = new NetHttpTransport();

    private static Clock clock = Clock.systemUTC();

    @Test
    void getJwt() throws Exception {
        ServiceAccountCredentials credentials = getCredentials(Paths.get("C://secret//gcp//claims-core-pilot-friendly.json"));
        String iapClientId = "722498773171-3l59qia0gso019brmc1sctrcg70jfomg.apps.googleusercontent.com";
        String jwt = getSignedJwt(credentials, iapClientId);
        System.out.println("jwt: " + jwt);
        if (jwt == null) {
            throw new Exception(
                    "Unable to create a signed jwt token for : "
                            + iapClientId
                            + "with issuer : "
                            + credentials.getClientEmail());
        }

        String idToken = getGoogleIdToken(jwt);
        if (idToken == null) {
            throw new Exception("Unable to retrieve open id token");
        }
        System.out.println("google id token: " + idToken);
    }

    private static ServiceAccountCredentials getCredentials(Path credentialsPath) throws Exception {
        FileInputStream stream = new FileInputStream(credentialsPath.toFile());
        GoogleCredentials credentials =
                GoogleCredentials.fromStream(stream);
        if (!(credentials instanceof ServiceAccountCredentials)) {
            throw new Exception("Google credentials : service accounts credentials expected");
        }
        return (ServiceAccountCredentials) credentials;
    }

    private static String getGoogleIdToken(String jwt) throws Exception {
        final GenericData tokenRequest = new GenericData().set("grant_type", JWT_BEARER_TOKEN_GRANT_TYPE).set("assertion", jwt);

        final HttpRequestFactory requestFactory = httpTransport.createRequestFactory();

        final UrlEncodedContent content = new UrlEncodedContent(tokenRequest);
        final HttpRequest request =
                requestFactory
                        .buildPostRequest(new GenericUrl(OAUTH_TOKEN_URI), content)
                        .setParser(new JsonObjectParser(JacksonFactory.getDefaultInstance()));

        HttpResponse response = request.execute();
        GenericData responseData = response.parseAs(GenericData.class);
        return (String) responseData.get("id_token");
    }

    private static String getSignedJwt(ServiceAccountCredentials credentials, String iapClientId)
            throws Exception {
        Instant now = Instant.now(clock);
        long expirationTime = now.getEpochSecond() + EXPIRATION_TIME_IN_SECONDS;

        JWSHeader jwsHeader =
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(credentials.getPrivateKeyId()).build();

        JWTClaimsSet claims =
                new JWTClaimsSet.Builder()
                        .audience(OAUTH_TOKEN_URI)
                        .issuer(credentials.getClientEmail())
                        .subject(credentials.getClientEmail())
                        .issueTime(Date.from(now))
                        .expirationTime(Date.from(Instant.ofEpochSecond(expirationTime)))
                        .claim("target_audience", iapClientId)
                        .build();

        JWSSigner signer = new RSASSASigner(credentials.getPrivateKey());
        SignedJWT signedJwt = new SignedJWT(jwsHeader, claims);
        signedJwt.sign(signer);

        return signedJwt.serialize();
    }


}
