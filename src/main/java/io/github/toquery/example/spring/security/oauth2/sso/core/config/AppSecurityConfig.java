package io.github.toquery.example.spring.security.oauth2.sso.core.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.toquery.example.spring.security.oauth2.sso.core.oauth2.AppOAuth2UserService;
import io.github.toquery.example.spring.security.oauth2.sso.core.oauth2.AppOidcUserService;
import io.github.toquery.example.spring.security.oauth2.sso.core.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import io.github.toquery.example.spring.security.oauth2.sso.core.properties.AppProperties;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppAccessDeniedHandler;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppAuthenticationEntryPoint;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppLogoutSuccessHandler;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppOAuth2AuthenticationFailureHandler;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppOAuth2AuthenticationSuccessHandler;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppSecurityContextRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;

/**
 *
 */
@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
public class AppSecurityConfig {

    @Bean
    public AuthenticationEntryPoint appAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return new AppAuthenticationEntryPoint(objectMapper);
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler(ObjectMapper objectMapper) {
        return new AppAccessDeniedHandler(objectMapper);
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(ObjectMapper objectMapper) {
        return new AppLogoutSuccessHandler(objectMapper);
    }


    /**
     * 从request请求中那个地方获取到token
     */
    @Bean
    public BearerTokenResolver bearerTokenResolver() {
        DefaultBearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
        // 是否可以从uri请求参数中获取token
        bearerTokenResolver.setAllowUriQueryParameter(true);
        bearerTokenResolver.setAllowFormEncodedBodyParameter(true);
        return bearerTokenResolver;
    }


    /**
     * 从 JWT 的 scope 中获取的权限 取消 SCOPE_ 的前缀
     * 设置从 jwt claim 中那个字段获取权限
     * 如果需要同多个字段中获取权限或者是通过url请求获取的权限，则需要自己提供jwtAuthenticationConverter()这个方法的实现
     *
     * @return JwtAuthenticationConverter
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // 去掉 SCOPE_ 的前缀
        authoritiesConverter.setAuthorityPrefix("");
        // 从jwt claim 中那个字段获取权限，模式是从 scope 或 scp 字段中获取
        authoritiesConverter.setAuthoritiesClaimName("scope");
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }


    /**
     * 记录访问信息
     */
    @Bean
    @ConditionalOnMissingBean
    public SecurityContextRepository securityContextRepository() {
        return new AppSecurityContextRepository();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           CorsConfiguration corsConfiguration,
                                           BearerTokenResolver bearerTokenResolver,
                                           OAuth2UserService<OidcUserRequest, OidcUser> appOidcUserService,
                                           OAuth2UserService<OAuth2UserRequest, OAuth2User> appOAuth2UserService,
                                           AccessDeniedHandler accessDeniedHandler,
                                           LogoutSuccessHandler logoutSuccessHandler,
                                           AuthenticationEntryPoint authenticationEntryPoint,
                                           SecurityContextRepository securityContextRepository,
                                           AuthenticationEntryPoint appAuthenticationEntryPoint,
                                           JwtAuthenticationConverter jwtAuthenticationConverter,
                                           AuthenticationSuccessHandler appOAuth2AuthenticationSuccessHandler,
                                           AuthenticationFailureHandler appOAuth2AuthenticationFailureHandler,
                                           AuthorizationRequestRepository<OAuth2AuthorizationRequest> httpCookieOAuth2AuthorizationRequestRepository) throws Exception {
        http.cors(corsConfigurer -> {
            corsConfigurer.configurationSource(exchange -> corsConfiguration);
        });

        http.csrf(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);

        http.sessionManagement(httpSecuritySessionManagementConfigurer -> {
            httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });

        // security 上下文
        http.securityContext(httpSecuritySecurityContextConfigurer -> {
            httpSecuritySecurityContextConfigurer.requireExplicitSave(true);
            // 记录访问信息信息
            httpSecuritySecurityContextConfigurer.securityContextRepository(securityContextRepository);
        });

        http.authorizeHttpRequests(authorizeHttpRequestsCustomizer -> {
            // 白名单
            authorizeHttpRequestsCustomizer
                    .requestMatchers(
                            "/actuator", "/actuator/**",
                            "/", "/error",
                            "/favicon.ico", "/**/*.png", "/**/*.gif", "/**/*.svg", "/**/*.jpg", "/**/*.html", "/**/*.css", "/**/*.js")
                    .permitAll();

            authorizeHttpRequestsCustomizer.anyRequest().authenticated();
        });


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

        //
        http.oauth2ResourceServer(auth2ResourceServerConfigurer -> {
            // 处理 bearerToken方式，允许接受header、param、body的参数
            auth2ResourceServerConfigurer.bearerTokenResolver(bearerTokenResolver);
            auth2ResourceServerConfigurer.accessDeniedHandler(accessDeniedHandler);
            // 处理认证失败、过期
            auth2ResourceServerConfigurer.authenticationEntryPoint(appAuthenticationEntryPoint);

            auth2ResourceServerConfigurer.opaqueToken();
        });

        http.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
            httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(appAuthenticationEntryPoint);
            httpSecurityExceptionHandlingConfigurer.authenticationEntryPoint(authenticationEntryPoint);
        });

        // 退出登录
        http.logout(logoutConfigurer -> {
            logoutConfigurer.logoutSuccessHandler(logoutSuccessHandler);
        });

        return http.build();
    }


    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector(OAuth2ResourceServerProperties auth2ResourceServerProperties) {
        OAuth2ResourceServerProperties.Opaquetoken opaquetoken = auth2ResourceServerProperties.getOpaquetoken();
        return new NimbusOpaqueTokenIntrospector(opaquetoken.getIntrospectionUri(), opaquetoken.getClientId(), opaquetoken.getClientSecret());
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
    public AuthenticationSuccessHandler appOAuth2AuthenticationSuccessHandler(AppProperties appProperties,
                                                                              HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository) {
        return new AppOAuth2AuthenticationSuccessHandler(appProperties, httpCookieOAuth2AuthorizationRequestRepository);
    }

    @Bean
    public AuthenticationFailureHandler appOAuth2AuthenticationFailureHandler(HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository) {
        return new AppOAuth2AuthenticationFailureHandler(httpCookieOAuth2AuthorizationRequestRepository);
    }


}
