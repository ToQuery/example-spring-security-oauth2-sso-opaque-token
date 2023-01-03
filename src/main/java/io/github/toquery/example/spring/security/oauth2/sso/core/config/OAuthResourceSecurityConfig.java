package io.github.toquery.example.spring.security.oauth2.sso.core.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppAccessDeniedHandler;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 *
 */
@Slf4j
@RequiredArgsConstructor
@Configuration
public class OAuthResourceSecurityConfig {


    @Bean
    public AccessDeniedHandler accessDeniedHandler(ObjectMapper objectMapper) {
        return new AppAccessDeniedHandler(objectMapper);
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

    @Bean
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http,
                                           BearerTokenResolver bearerTokenResolver,
                                           AccessDeniedHandler accessDeniedHandler,
                                           AuthenticationEntryPoint appAuthenticationEntryPoint
    ) throws Exception {


        //
        http.oauth2ResourceServer(auth2ResourceServerConfigurer -> {
            // 处理 bearerToken方式，允许接受header、param、body的参数
            auth2ResourceServerConfigurer.bearerTokenResolver(bearerTokenResolver);
            auth2ResourceServerConfigurer.accessDeniedHandler(accessDeniedHandler);
            // 处理认证失败、过期
            auth2ResourceServerConfigurer.authenticationEntryPoint(appAuthenticationEntryPoint);

            auth2ResourceServerConfigurer.opaqueToken();
        });

        return http.build();
    }


    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector(OAuth2ResourceServerProperties auth2ResourceServerProperties) {
        OAuth2ResourceServerProperties.Opaquetoken opaquetoken = auth2ResourceServerProperties.getOpaquetoken();
        return new NimbusOpaqueTokenIntrospector(opaquetoken.getIntrospectionUri(), opaquetoken.getClientId(), opaquetoken.getClientSecret());
    }


}
