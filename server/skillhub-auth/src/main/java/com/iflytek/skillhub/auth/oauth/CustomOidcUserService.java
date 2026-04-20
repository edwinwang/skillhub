package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

/**
 * OIDC counterpart of {@link CustomOAuth2UserService}. Required because Spring
 * Security routes OIDC flows through {@code OAuth2UserService&lt;OidcUserRequest,
 * OidcUser&gt;}; without a registered implementation the default service runs
 * and skips the platform flow, leaving the session without a
 * {@link PlatformPrincipal}.
 */
@Service
public class CustomOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OAuthLoginFlowService oauthLoginFlowService;

    public CustomOidcUserService(OAuthLoginFlowService oauthLoginFlowService) {
        this.oauthLoginFlowService = oauthLoginFlowService;
    }

    @Override
    public OidcUser loadUser(OidcUserRequest request) throws OAuth2AuthenticationException {
        OAuthLoginFlowService.AuthenticatedLoginContext context = oauthLoginFlowService.loadLoginContext(request);
        PlatformPrincipal principal = context.principal();

        Map<String, Object> claims = new HashMap<>(context.upstreamUser().getAttributes());
        claims.put("platformPrincipal", principal);

        Set<GrantedAuthority> authorities = new LinkedHashSet<>(context.upstreamUser().getAuthorities());
        principal.platformRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .forEach(authorities::add);

        String nameAttributeKey = request.getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();
        if (nameAttributeKey == null || nameAttributeKey.isBlank()) {
            nameAttributeKey = "sub";
        }

        OidcIdToken idToken = request.getIdToken();
        return new DefaultOidcUser(authorities, idToken, new OidcUserInfo(claims), nameAttributeKey);
    }
}
