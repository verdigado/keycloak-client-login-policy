COMPOSE := docker compose -f dev/compose.yml

.PHONY: build test up down restart reset logs clean

# Rebuild and hand the jar to the running Keycloak.
build:
	# A version bump leaves the jar of the old version in target/, and the copy
	# below would take both.
	find target -name '*.jar' -delete 2>/dev/null || true
	./mvnw -q package -DskipTests
	rm -f dev/providers/*.jar
	cp target/*.jar dev/providers/
	$(COMPOSE) restart keycloak

test:
	./mvnw test

up:
	$(COMPOSE) up -d

down:
	$(COMPOSE) down

restart:
	$(COMPOSE) restart keycloak

# An import is skipped once the realm exists, so edits to dev/import/ only
# land on an empty database.
reset:
	$(COMPOSE) down -v
	$(COMPOSE) up -d

logs:
	$(COMPOSE) logs -f keycloak

clean:
	./mvnw -q clean
	rm -f dev/providers/*.jar
