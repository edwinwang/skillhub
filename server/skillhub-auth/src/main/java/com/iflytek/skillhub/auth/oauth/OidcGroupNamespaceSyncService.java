package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.domain.namespace.Namespace;
import com.iflytek.skillhub.domain.namespace.NamespaceMember;
import com.iflytek.skillhub.domain.namespace.NamespaceMemberRepository;
import com.iflytek.skillhub.domain.namespace.NamespaceRepository;
import com.iflytek.skillhub.domain.namespace.NamespaceRole;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Synchronizes group memberships from the OIDC userinfo response into the
 * SkillHub namespace_member table. Operates in add-only mode — users are
 * never removed from a namespace even if the upstream group membership is
 * dropped.
 *
 * <p>Wired into the login flow through {@code IdentityBindingService} so the
 * sync happens once per OIDC login for active users.
 */
@Service
public class OidcGroupNamespaceSyncService {

    private static final Logger log = LoggerFactory.getLogger(OidcGroupNamespaceSyncService.class);

    private final NamespaceRepository namespaceRepository;
    private final NamespaceMemberRepository namespaceMemberRepository;
    private final OidcGroupMappingProperties properties;

    public OidcGroupNamespaceSyncService(NamespaceRepository namespaceRepository,
                                         NamespaceMemberRepository namespaceMemberRepository,
                                         OidcGroupMappingProperties properties) {
        this.namespaceRepository = namespaceRepository;
        this.namespaceMemberRepository = namespaceMemberRepository;
        this.properties = properties;
    }

    @Transactional
    public void sync(String userId, Map<String, Object> claimExtras) {
        Map<String, String> groupToNamespace = properties.getNamespaceMapping();
        if (groupToNamespace == null || groupToNamespace.isEmpty()) {
            return;
        }
        Set<String> groups = extractGroups(claimExtras.get(properties.getGroupsClaim()));
        if (groups.isEmpty()) {
            return;
        }
        for (String group : groups) {
            String namespaceSlug = groupToNamespace.get(group);
            if (namespaceSlug == null || namespaceSlug.isBlank()) {
                continue;
            }
            Namespace namespace = namespaceRepository.findBySlug(namespaceSlug).orElse(null);
            if (namespace == null) {
                log.warn("OIDC group {} maps to namespace slug {} but that namespace does not exist; skipping",
                        group, namespaceSlug);
                continue;
            }
            if (namespaceMemberRepository.findByNamespaceIdAndUserId(namespace.getId(), userId).isPresent()) {
                continue;
            }
            namespaceMemberRepository.save(new NamespaceMember(namespace.getId(), userId, NamespaceRole.MEMBER));
            log.info("Added user {} to namespace {} via OIDC group {}", userId, namespaceSlug, group);
        }
    }

    @SuppressWarnings("unchecked")
    private static Set<String> extractGroups(Object raw) {
        Set<String> result = new LinkedHashSet<>();
        if (raw == null) {
            return result;
        }
        if (raw instanceof Collection<?> collection) {
            for (Object item : collection) {
                if (item != null) {
                    String value = item.toString().trim();
                    if (!value.isEmpty()) {
                        result.add(value);
                    }
                }
            }
        } else if (raw instanceof String str) {
            for (String part : str.split(",")) {
                String value = part.trim();
                if (!value.isEmpty()) {
                    result.add(value);
                }
            }
        }
        return result;
    }

}
