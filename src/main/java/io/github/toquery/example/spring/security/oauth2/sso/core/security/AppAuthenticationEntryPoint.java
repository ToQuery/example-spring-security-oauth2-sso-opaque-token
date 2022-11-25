package io.github.toquery.example.spring.security.oauth2.sso.core.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.toquery.example.spring.security.oauth2.sso.core.AppBaseResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.AuthenticationEntryPoint;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@Slf4j
@RequiredArgsConstructor
public class AppAuthenticationEntryPoint implements AuthenticationEntryPoint {


    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest httpServletRequest,
                         HttpServletResponse httpServletResponse,
                         AuthenticationException authenticationException) throws IOException, ServletException {
        log.error("Responding with unauthorized error. Message - {}", authenticationException.getMessage());
        httpServletResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, authenticationException.getLocalizedMessage());

        log.error("未认证处理处理器,登录失败 " + authenticationException.getClass().getName(), authenticationException);
        HttpStatus httpStatus = HttpStatus.UNAUTHORIZED;
        AppBaseResponse<?> response = AppBaseResponse.fail("认证失败");

        String errorMessage = "认证失败";

        if (authenticationException instanceof InsufficientAuthenticationException) {
            errorMessage = "未获到用户信息，请重新登录！";
        } else if (authenticationException instanceof UsernameNotFoundException) { // 账号不存在
            errorMessage = "账号不存在";
        } else if (authenticationException instanceof BadCredentialsException) { // 用户名或密码错误
            errorMessage = "用户名或密码错误";
        } else if (authenticationException instanceof AccountExpiredException) { // 账号已过期
            errorMessage = "账号已过期";
        } else if (authenticationException instanceof LockedException) {  // 账号已被锁定
            errorMessage = "账号已被锁定";
        } else if (authenticationException instanceof CredentialsExpiredException) {  // 用户凭证已失效
            errorMessage = "用户凭证已失效";
        } else if (authenticationException instanceof DisabledException) {  // 账号已被禁用
            errorMessage = "账号已被禁用";
        } else if (authenticationException instanceof AuthenticationServiceException) {
            errorMessage = "登录失败";
        } else if (authenticationException instanceof AuthenticationCredentialsNotFoundException) {
            errorMessage = "未获取到登录信息，请重新登录！";
        } else if (authenticationException instanceof InvalidBearerTokenException) {
            errorMessage = "用户登录信息失效，请重新登录！";
        }

        response.setMessage(errorMessage);
        response.setCode(httpStatus.value());
        httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(response));
    }
}
