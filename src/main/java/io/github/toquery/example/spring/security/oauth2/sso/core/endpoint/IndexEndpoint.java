package io.github.toquery.example.spring.security.oauth2.sso.core.endpoint;

import io.github.toquery.example.spring.security.oauth2.sso.core.util.AuthenticationUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 *
 */
@RequiredArgsConstructor
@RestController
public class IndexEndpoint {

    @ResponseBody
    @GetMapping(value = {"", "/", "/info", "/index"})
    public Map<String, Object> index(
            Authentication authentication,
            @AuthenticationPrincipal OAuth2User oauth2User,
            @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient
    ) {
        return AuthenticationUtils.authenticationInfo(this.getClass().getSimpleName(), authentication, oauth2User, authorizedClient);
    }

}
