package com.iflytek.skillhub.auth.oauth;

import java.util.Map;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

/**
 * Generic claims extractor for OpenID Connect providers. Maps the standard
 * OIDC userinfo claims into the normalized {@link OAuthClaims} carrier used
 * by {@link OAuthLoginFlowService}.
 *
 * <p>Tied to registration id {@code oidc} in {@code application.yml}. All
 * endpoint and credential values are injected via environment variables so
 * no provider-specific information lives in the repository.
 */
@Component
public class OidcClaimsExtractor implements OAuthClaimsExtractor {

    private static final String PROVIDER = "oidc";

    @Override
    public String getProvider() {
        return PROVIDER;
    }

    @Override
    public OAuthClaims extract(OAuth2UserRequest request, OAuth2User oAuth2User) {
        Map<String, Object> attrs = oAuth2User.getAttributes();
        String subject = stringAttr(attrs, "sub");
        String email = stringAttr(attrs, "email");
        boolean emailVerified = attrs.get("email_verified") instanceof Boolean verified && verified;
        String preferredUsername = stringAttr(attrs, "preferred_username");
        String name = stringAttr(attrs, "name");
        String loginName = preferredUsername != null ? preferredUsername : name;
        return new OAuthClaims(PROVIDER, subject, email, emailVerified, loginName, attrs);
    }

    private static String stringAttr(Map<String, Object> attrs, String key) {
        Object value = attrs.get(key);
        return value == null ? null : value.toString();
    }
}
