# Entity relationship diagram

This diagram reflects the tables and constraints in
[`001_initial.sql`](../internal/database/migrations/001_initial.sql).
`PK` marks primary-key columns, `FK` foreign keys, `UK` unique columns, and
`NULL` nullable columns. PostgreSQL defaults and check constraints are described
below the diagram.

![Entity relationship diagram](ERD.svg)

The SVG above is the rendered diagram; the Mermaid definition below is its
editable source.

```mermaid
erDiagram
    TENANTS ||--o{ MEMBERSHIPS : contains
    USERS ||--o{ MEMBERSHIPS : joins
    TENANTS ||--o{ ROLES : owns
    MEMBERSHIPS ||--o{ MEMBERSHIP_ROLES : receives
    ROLES ||--o{ MEMBERSHIP_ROLES : assigned
    ROLES ||--o{ ROLE_PERMISSIONS : grants
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : defines
    TENANTS ||--o{ REFRESH_TOKENS : scopes
    USERS ||--o{ REFRESH_TOKENS : owns
    TENANTS o|--o{ AUDIT_LOGS : records
    USERS o|--o{ AUDIT_LOGS : acts

    TENANTS {
        uuid id PK
        text name
        text code UK
        text status
        timestamptz created_at
        timestamptz updated_at
    }

    USERS {
        uuid id PK
        text name
        text email UK
        text password_hash
        timestamptz created_at
        timestamptz updated_at
    }

    MEMBERSHIPS {
        uuid tenant_id PK,FK
        uuid user_id PK,FK
        text display_name "NULL"
        text status
        timestamptz created_at
        timestamptz deleted_at "NULL"
    }

    ROLES {
        uuid id PK
        uuid tenant_id FK
        text name
        text description
        timestamptz created_at
    }

    MEMBERSHIP_ROLES {
        uuid tenant_id PK,FK
        uuid user_id PK,FK
        uuid role_id PK,FK
        timestamptz assigned_at
    }

    PERMISSIONS {
        uuid id PK
        text name UK
        text description
    }

    ROLE_PERMISSIONS {
        uuid tenant_id PK,FK
        uuid role_id PK,FK
        uuid permission_id PK,FK
    }

    REFRESH_TOKENS {
        bytea token_hash PK
        uuid tenant_id FK
        uuid user_id FK
        timestamptz expires_at
        timestamptz revoked_at "NULL"
        timestamptz created_at
    }

    AUDIT_LOGS {
        bigint id PK
        uuid tenant_id FK "NULL"
        uuid actor_id FK "NULL"
        text action
        text target_type
        text target_id
        jsonb details
        timestamptz created_at
    }
```

## Relationship and constraint details

- `memberships` has a composite primary key `(tenant_id, user_id)` and
  references both `tenants.id` and `users.id`. A user can therefore join
  multiple tenants. `deleted_at` is the membership soft-delete marker.
- `roles` belongs to one tenant. Role names are unique within a tenant, and
  `(tenant_id, id)` is also unique so the junction tables can reference a role
  together with its tenant.
- `membership_roles` links a membership to a role. Its composite foreign keys
  `(tenant_id, user_id)` and `(tenant_id, role_id)` ensure the membership and
  role belong to the same tenant.
- `role_permissions` links a tenant role to a shared permission-catalog entry.
  Its `(tenant_id, role_id)` foreign key prevents attaching permissions through
  a role owned by another tenant.
- `refresh_tokens` has separate foreign keys to a tenant and user; the schema
  does not define a composite constraint tying those two references to a
  membership.
- `audit_logs.tenant_id` and `audit_logs.actor_id` are nullable references.
  This allows audit entries without an associated tenant or user actor.
- `users.email` has a unique constraint and a unique index on `lower(email)`.
  Tenant codes and permission names are unique. UUID primary keys default to
  `gen_random_uuid()`; timestamps and `audit_logs.details` have database
  defaults defined in the migration.

Tenant status is constrained to `active` or `suspended`; membership status is
constrained to `active` or `suspended`. Permission names use the
`resource:action` format. The migration also creates indexes for tenant-scoped
role lookups, membership and role-assignment lookups, refresh-token expiry,
and audit lookups by tenant or actor and time.

The migration runner creates `schema_migrations` as operational bookkeeping;
it is omitted from this domain ERD.
