# Policy documents to test against

Two parsers read the policy format: the provider, and the editor that writes
documents for it. These files are what keeps them from drifting apart.

- `policies/accepted/` — documents both have to read without complaint.
- `policies/refused/` — documents both have to turn down. The file name says
  what is wrong with it.

Only the verdict is shared. How each side words an error is its own business.

Adding a case means adding one file. Both test suites pick it up on their own.
