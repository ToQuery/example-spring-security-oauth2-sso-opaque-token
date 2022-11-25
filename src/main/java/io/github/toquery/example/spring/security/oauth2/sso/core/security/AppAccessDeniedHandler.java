package io.github.toquery.example.spring.security.oauth2.sso.core.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.toquery.example.spring.security.oauth2.sso.core.AppBaseResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;


/**
 * 用来解决匿名用户访问无权限资源时的异常
 */
@Slf4j
@RequiredArgsConstructor
public class AppAccessDeniedHandler implements AccessDeniedHandler {

    public final ObjectMapper objectMapper;

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        String errorMsg = "请求访问 " + request.getRequestURI() + " 接口,没有访问权限";
        log.error(errorMsg);
        accessDeniedException.printStackTrace();
        AppBaseResponse<?> appBaseResponse = AppBaseResponse.fail(errorMsg);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("utf-8");
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getWriter().write(objectMapper.writeValueAsString(appBaseResponse));
        // response.sendError(HttpServletResponse.SC_FORBIDDEN, JacksonUtils.object2String(appBaseResponse));
    }
}
