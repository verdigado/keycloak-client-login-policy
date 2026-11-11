package de.verdigado.keycloak.clientloginpolicy;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;

/**
 * The policy as the flow execution was configured with it. Documents are read
 * once and kept, because a login must not pay for parsing one.
 */
final class ConfiguredPolicy {

    private static final Logger log = Logger.getLogger(ConfiguredPolicy.class);

    static final String DOCUMENT = "policy";

    /** Keyed by the document itself, so editing the config replaces the entry. */
    private static final Map<String, Policy> PARSED = new ConcurrentHashMap<>();

    /** Enough room for every realm to hold a document, and for a few edits. */
    private static final int KEEP = 64;

    private ConfiguredPolicy() {
    }

    /** Like {@link #of}, but a document that cannot be read turns everyone away. */
    static Policy orClosed(AuthenticatorConfigModel config) {
        try {
            return of(config);
        } catch (IllegalArgumentException e) {
            log.errorf("the configured policy cannot be read, turning everyone away: %s", e.getMessage());
            return Policy.CLOSED;
        }
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
