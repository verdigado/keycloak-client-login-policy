package de.verdigado.keycloak.clientloginpolicy;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.keycloak.models.AuthenticatorConfigModel;

/**
 * The policy as the flow execution was configured with it. Documents are read
 * once and kept, because a login must not pay for parsing one.
 */
final class ConfiguredPolicy {

    static final String DOCUMENT = "policy";

    /** Keyed by the document itself, so editing the config replaces the entry. */
    private static final Map<String, Policy> PARSED = new ConcurrentHashMap<>();

    /** Enough room for every realm to hold a document, and for a few edits. */
    private static final int KEEP = 64;

    private ConfiguredPolicy() {
    }

    static Policy of(AuthenticatorConfigModel config) {
        String document = config == null ? null : config.getConfig().get(DOCUMENT);

        if (document == null || document.isBlank()) {
            return Policy.OPEN;
        }

        Policy parsed = PARSED.get(document);
        if (parsed != null) {
            return parsed;
        }

        parsed = PolicyJson.parse(document);
        if (PARSED.size() >= KEEP) {
            PARSED.clear();
        }
        PARSED.put(document, parsed);
        return parsed;
    }
}
