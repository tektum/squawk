# Squawk

- Keep the Worker dependency-free at runtime beyond Hono, Zod, and jose.
- Parse every external request with Zod and use immutable digest identities only.
- Do not persist secrets, names, emails, or static inbound credentials.
- Keep source files under 250 non-comment lines and test Worker behavior with the Workers pool.
