package io.github.toquery.example.spring.security.oauth2.sso.core.config;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppAuthenticationEntryPoint;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppLogoutSuccessHandler;
import io.github.toquery.example.spring.security.oauth2.sso.core.security.AppSecurityContextRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;

/**
 *
 */
@Slf4j
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true, prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public AuthenticationEntryPoint appAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return new AppAuthenticationEntryPoint(objectMapper);
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler(ObjectMapper objectMapper) {
        return new AppLogoutSuccessHandler(objectMapper);
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
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   CorsConfiguration corsConfiguration,
                                                   LogoutSuccessHandler logoutSuccessHandler,
                                                   AuthenticationEntryPoint authenticationEntryPoint,
                                                   SecurityContextRepository securityContextRepository,
                                                   AuthenticationEntryPoint appAuthenticationEntryPoint
    ) throws Exception {
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
            authorizeHttpRequestsCustomizer.requestMatchers("/", "/error").permitAll();
            authorizeHttpRequestsCustomizer.requestMatchers("/actuator", "/actuator/*").permitAll();
            authorizeHttpRequestsCustomizer.requestMatchers("/favicon.ico", "/*/*.png", "/*/*.gif", "/*/*.svg", "/*/*.jpg", "/*/*.html", "/*/*.css", "/*/*.js").permitAll();

            authorizeHttpRequestsCustomizer.anyRequest().authenticated();
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


}
