# Authenticated E2E Report

OIRAN ran 47/47 Playwright cases against an isolated candidate API. The authenticated E2E-002 case imported the reviewed derived dataset through the atomic API path and verified Session Explorer, Call Flow correlation evidence, and packet provenance.

POLARIS ran 20/20 Playwright cases against an isolated candidate API. Three production-style authenticated scenarios verified CPU evidence, four-profile controls, UE Manager, and targeted-traffic eligibility without starting jobs.

Credentials were generated for this run, stored in mode-0600 runtime files, passed through environment variables, and excluded from Git. No authentication test was skipped or counted by mock alone; mock-only tests remain ordinary UI regression cases and are not the authentication evidence.
