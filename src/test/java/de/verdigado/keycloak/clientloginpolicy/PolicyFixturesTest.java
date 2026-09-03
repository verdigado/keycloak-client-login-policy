package de.verdigado.keycloak.clientloginpolicy;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The documents under {@code testdata/policies/} are read by this provider and
 * by the editor, which has a parser of its own. Both are held to this set, so
 * that a document the editor hands out is one a realm can be run on, and a
 * document the editor refuses is one that would have been refused at login.
 *
 * <p>Only the verdict is shared. The wording of an error is each side's own.
 */
class PolicyFixturesTest {

    private static final Path FIXTURES = Path.of("testdata", "policies");

    static Stream<Path> accepted() {
        return documentsIn("accepted");
    }

    static Stream<Path> refused() {
        return documentsIn("refused");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("accepted")
    void accepts(Path document) {
        PolicyJson.parse(read(document));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("refused")
    void refuses(Path document) {
        assertThrows(IllegalArgumentException.class, () -> PolicyJson.parse(read(document)));
    }

    private static Stream<Path> documentsIn(String verdict) {
        try (Stream<Path> entries = Files.list(FIXTURES.resolve(verdict))) {
            return entries.sorted().toList().stream();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String read(Path document) {
        try {
            return Files.readString(document);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
