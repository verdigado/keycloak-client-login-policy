## Keycloak sources

`.keycloak-src/` may hold a checkout of the Keycloak version this builds against — see `make keycloak-src`. When it is there, read it instead of guessing at SPI interfaces, and look at Keycloak's own providers for how an extension point is meant to be used. When it is not there, say so rather than working from memory.

## The policy format is read twice

The provider parses the policy document, and so does the editor served from
`editor/`, in JavaScript. `testdata/policies/` says which documents both have
to accept and which both have to turn down, and both test suites read it.
A change to the format means changing both parsers and adding a document there.
