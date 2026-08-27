package de.verdigado.keycloak.clientloginpolicy;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * What a condition compares against: a literal, or a regular expression the
 * whole candidate has to match.
 */
record Match(String text, Pattern pattern) {

    static Match exact(String text) {
        return new Match(text, null);
    }

    static Match regex(String text) {
        try {
            return new Match(text, Pattern.compile(text));
        } catch (PatternSyntaxException e) {
            // Caught here so a bad pattern is a broken policy, not a broken login.
            throw new IllegalArgumentException("'" + text + "' is not a regular expression: " + e.getMessage(), e);
        }
    }

    static Match of(String text, String mode) {
        if (mode == null || mode.equals("exact")) {
            return exact(text);
        }
        if (mode.equals("regex")) {
            return regex(text);
        }
        throw new IllegalArgumentException("match is exact or regex, got '" + mode + "'");
    }

    boolean isRegex() {
        return pattern != null;
    }

    boolean test(String candidate) {
        return pattern == null ? text.equals(candidate) : pattern.matcher(candidate).matches();
    }

    String describe() {
        return pattern == null ? text : "matching " + text;
    }
}
