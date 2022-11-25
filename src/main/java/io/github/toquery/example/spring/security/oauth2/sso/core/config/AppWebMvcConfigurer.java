package io.github.toquery.example.spring.security.oauth2.sso.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.time.Duration;

/**
 *
 */
@Configuration
public class AppWebMvcConfigurer implements WebMvcConfigurer {

    @Bean
    public CorsConfiguration corsConfiguration() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.addAllowedOrigin("*");
        corsConfiguration.addAllowedHeader("*");
        corsConfiguration.addAllowedMethod("*");
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setMaxAge(Duration.ofDays(7));
        return corsConfiguration;
    }


    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 允许路径
                .allowedMethods("POST", "GET", "PUT", "OPTIONS", "DELETE")  // 允许请求地方法
                .maxAge(10000)  //预检间隔时间
                .allowedOriginPatterns("*") // 允许跨域访问的源 2.4.0 之前为 .allowedOrigins("*")
                .allowedHeaders("*")  // 允许头部设置
                .allowCredentials(true);  // 是否发送cookie
    }
}
