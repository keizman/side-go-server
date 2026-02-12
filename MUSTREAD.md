# MUSTREAD - side-go-server

## Database schema workflow (mandatory)

- `all.sql` is the canonical bootstrap schema for creating the database from zero.
- Every time database structure changes, `all.sql` must be updated in the same change.
- For existing environments, provide an incremental SQL script/snippet for manual upgrade (ALTER statements).
- Never ship DB-related code changes without both:
  - updated `all.sql`
  - matching incremental SQL for already-running databases
