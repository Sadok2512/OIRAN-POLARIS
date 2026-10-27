# Authenticated Candidate Browser Validation

The candidate uses a dedicated least-privilege Operator account created only in the isolated candidate user registry. Username and generated password are injected through environment variables; tests fail when either is absent. No credential is embedded in source, screenshots, reports, or commits.

Validated non-executing paths:

- secure login and Operator identity;
- Apply Configuration visibility;
- Add UE visibility;
- multi-UE selection and typed group contract;
- UE Manager and UE-targeted Traffic Generator;
- CPU decision evidence and exact capability state;
- Light/Dark layouts at 1440x900 and 1920x1080.

The candidate runs with `POLARIS_EXECUTION_MODE=disabled`. No Start UE, live traffic, or other simulator action was issued.
