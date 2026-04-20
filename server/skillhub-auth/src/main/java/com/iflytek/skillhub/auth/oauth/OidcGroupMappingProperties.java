package com.iflytek.skillhub.auth.oauth;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for syncing OIDC group memberships into SkillHub namespaces.
 *
 * <p>At login time the claim named by {@link #getGroupsClaim()} is read from
 * the userinfo response. For each group that appears in
 * {@link #getNamespaceMapping()} the authenticated user is added to the
 * mapped namespace (looked up by slug). Memberships are only added, never
 * removed — groups removed upstream will not kick the user out of the
 * namespace.
 *
 * <p>Disable by leaving {@link #getNamespaceMapping()} empty; the sync
 * service becomes a no-op.
 */
@ConfigurationProperties(prefix = "skillhub.auth.oidc")
public class OidcGroupMappingProperties {

    private String groupsClaim = "yufu.user.groups";
    private Map<String, String> namespaceMapping = new LinkedHashMap<>();

    public String getGroupsClaim() {
        return groupsClaim;
    }

    public void setGroupsClaim(String groupsClaim) {
        this.groupsClaim = groupsClaim;
    }

    public Map<String, String> getNamespaceMapping() {
        return namespaceMapping;
    }

    public void setNamespaceMapping(Map<String, String> namespaceMapping) {
        this.namespaceMapping = namespaceMapping;
    }
}
