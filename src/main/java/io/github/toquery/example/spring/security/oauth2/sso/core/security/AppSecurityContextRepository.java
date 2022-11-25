package io.github.toquery.example.spring.security.oauth2.sso.core.security;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 记录访问信息
 */
@AllArgsConstructor
@Slf4j
public class AppSecurityContextRepository implements SecurityContextRepository {


    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        log.info("AppSecurityContextRepository saveContext");
        SecurityContext context = (SecurityContext) requestResponseHolder.getRequest().getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME);
        return (context != null) ? context : SecurityContextHolder.createEmptyContext();
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        log.info("AppSecurityContextRepository saveContext");
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        log.info("AppSecurityContextRepository containsContext");
        return false;
    }
}
