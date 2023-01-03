package io.github.toquery.example.spring.security.oauth2.sso.core.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.toquery.example.spring.security.oauth2.sso.core.oauth2.AppOAuth2UserService;
import io.github.toquery.example.spring.security.oauth2.sso.core.oauth2.AppOidcUserService;
import io.github.toquery.example.spring.security.oauth2.sso.core.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import io.github.toquery.example.spring.security.oauth2.sso.core.properties.AppProperties;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppLogoutSuccessHandler;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppOAuth2AuthenticationFailureHandler;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppOAuth2AuthenticationSuccessHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 *
 */
@Slf4j
@RequiredArgsConstructor
@Configuration
public class OAuthLoginSecurityConfig {

    @Bean
    public SecurityFilterChain loginSecurityFilterChain(HttpSecurity http,
                                           OAuth2UserService<OidcUserRequest, OidcUser> appOidcUserService,
                                           OAuth2UserService<OAuth2UserRequest, OAuth2User> appOAuth2UserService,
                                           AuthenticationSuccessHandler appOAuth2AuthenticationSuccessHandler,
                                           AuthenticationFailureHandler appOAuth2AuthenticationFailureHandler,
                                           AuthorizationRequestRepository<OAuth2AuthorizationRequest> httpCookieOAuth2AuthorizationRequestRepository) throws Exception {


        http.oauth2Login(oauth2LoginConfigurer -> {
            oauth2LoginConfigurer.loginPage("/oauth2/authorization/github");


            oauth2LoginConfigurer.authorizationEndpoint(authorizationEndpointConfig -> {
                authorizationEndpointConfig.authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository);
            });

            oauth2LoginConfigurer.userInfoEndpoint(userInfoEndpointConfig -> {
                userInfoEndpointConfig.userService(appOAuth2UserService);
                userInfoEndpointConfig.oidcUserService(appOidcUserService);
            });

            oauth2LoginConfigurer.successHandler(appOAuth2AuthenticationSuccessHandler);
            oauth2LoginConfigurer.failureHandler(appOAuth2AuthenticationFailureHandler);
        });

        return http.build();
    }


    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> appOidcUserService() {
        return new AppOidcUserService();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> appOAuth2UserService() {
        return new AppOAuth2UserService();
    }

    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public AuthenticationSuccessHandler appOAuth2AuthenticationSuccessHandler(
            AppProperties appProperties,
                                                                              HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository
    ) {
        return new AppOAuth2AuthenticationSuccessHandler(appProperties, httpCookieOAuth2AuthorizationRequestRepository);
    }

    @Bean
    public AuthenticationFailureHandler appOAuth2AuthenticationFailureHandler(
            HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository
    ) {
        return new AppOAuth2AuthenticationFailureHandler(httpCookieOAuth2AuthorizationRequestRepository);
    }


}
