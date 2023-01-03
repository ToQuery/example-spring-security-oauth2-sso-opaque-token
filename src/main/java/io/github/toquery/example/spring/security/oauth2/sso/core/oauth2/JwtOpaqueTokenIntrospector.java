package io.github.toquery.example.spring.security.oauth2.sso.core.oauth2;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.text.ParseException;
import java.time.Instant;

import static com.nimbusds.jwt.JWTClaimNames.ISSUED_AT;
import static org.springframework.security.core.authority.AuthorityUtils.NO_AUTHORITIES;
import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;

/**
 *
 */
public class JwtOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private final OAuth2ResourceServerProperties auth2ResourceServerProperties;


    private OpaqueTokenIntrospector delegate;

    private final OAuth2UserService oauth2UserService = new AppOAuth2UserService();

    private final ClientRegistrationRepository clientRegistrationRepository;

    private JwtDecoder jwtDecoder = new NimbusJwtDecoder(new ParseOnlyJWTProcessor());

    public JwtOpaqueTokenIntrospector(OAuth2ResourceServerProperties auth2ResourceServerProperties, ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.auth2ResourceServerProperties = auth2ResourceServerProperties;
        OAuth2ResourceServerProperties.Opaquetoken opaquetoken = auth2ResourceServerProperties.getOpaquetoken();
        this.delegate = new NimbusOpaqueTokenIntrospector(opaquetoken.getIntrospectionUri(), opaquetoken.getClientId(), opaquetoken.getClientSecret());
    }

    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal authorized = this.delegate.introspect(token);

//        Instant issuedAt = authorized.getAttribute(JWTClaimNames.ISSUED_AT);
//        Instant expiresAt = authorized.getAttribute(JWTClaimNames.EXPIRATION_TIME);
//        ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(auth2ResourceServerProperties.getOpaquetoken().getClientId());
//        OAuth2AccessToken auth2AccessToken = new OAuth2AccessToken(BEARER, token, issuedAt, expiresAt);
//        OAuth2UserRequest oauth2UserRequest = new OAuth2UserRequest(clientRegistration, auth2AccessToken);
//        return this.oauth2UserService.loadUser(oauth2UserRequest);

        try {
            Jwt jwt = this.jwtDecoder.decode(token);
            return new DefaultOAuth2AuthenticatedPrincipal(jwt.getClaims(), NO_AUTHORITIES);
        } catch (JwtException ex) {
            throw ex;
        }
    }

    private static class ParseOnlyJWTProcessor extends DefaultJWTProcessor<SecurityContext> {
        @Override
        public JWTClaimsSet process(SignedJWT jwt, SecurityContext context) throws BadJOSEException, JOSEException {
            try {
                return jwt.getJWTClaimsSet();
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
