# Security policy

`aiproof` is a security tool; bugs in it matter more than usual.

- Report vulnerabilities privately by e-mail to the maintainers (address in the repository profile) or via GitHub private vulnerability reporting. Do not open a public issue for exploitable bugs.
- We aim to acknowledge within 3 working days and to ship a fix or mitigation within 30 days.
- In scope: ledger integrity bypass, redaction bypass for the documented detector types, filter bypass classes that are trivial for the documented rules, proxy request smuggling, any way the library can crash or hang a host application.
- Out of scope: creative prompt injections that evade the heuristic rules (they are documented as heuristics), attacks that require the HMAC key.

Please include a minimal reproduction. Credit is given in the changelog unless you prefer otherwise.
