## Keycloak sources

`.keycloak-src/` may hold a checkout of the Keycloak version this builds against — see `make keycloak-src`. When it is there, read it instead of guessing at SPI interfaces, and look at Keycloak's own providers for how an extension point is meant to be used. When it is not there, say so rather than working from memory.
