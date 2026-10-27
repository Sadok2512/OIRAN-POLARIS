# Authentication boundaries

Each application retains its existing authentication and authorization boundary.
The Portal launches applications but does not mint credentials, impersonate users,
or bypass application RBAC.

A shared authentication system is explicitly outside this foundation. Any future
change requires a separate security review and migration plan.
