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

        log.error("????????????????????????,???????????? " + authenticationException.getClass().getName(), authenticationException);
        HttpStatus httpStatus = HttpStatus.UNAUTHORIZED;
        AppBaseResponse<?> response = AppBaseResponse.fail("????????????");

        String errorMessage = "????????????";

        if (authenticationException instanceof InsufficientAuthenticationException) {
            errorMessage = "??????????????????????????????????????????";
        } else if (authenticationException instanceof UsernameNotFoundException) { // ???????????????
            errorMessage = "???????????????";
        } else if (authenticationException instanceof BadCredentialsException) { // ????????????????????????
            errorMessage = "????????????????????????";
        } else if (authenticationException instanceof AccountExpiredException) { // ???????????????
            errorMessage = "???????????????";
        } else if (authenticationException instanceof LockedException) {  // ??????????????????
            errorMessage = "??????????????????";
        } else if (authenticationException instanceof CredentialsExpiredException) {  // ?????????????????????
            errorMessage = "?????????????????????";
        } else if (authenticationException instanceof DisabledException) {  // ??????????????????
            errorMessage = "??????????????????";
        } else if (authenticationException instanceof AuthenticationServiceException) {
            errorMessage = "????????????";
        } else if (authenticationException instanceof AuthenticationCredentialsNotFoundException) {
            errorMessage = "?????????????????????????????????????????????";
        } else if (authenticationException instanceof InvalidBearerTokenException) {
            errorMessage = "?????????????????????????????????????????????";
        }

        response.setMessage(errorMessage);
        response.setCode(httpStatus.value());
        httpServletResponse.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        httpServletResponse.getWriter().write(objectMapper.writeValueAsString(response));
    }
}
