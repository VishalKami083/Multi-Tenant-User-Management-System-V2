# Design and architecture

## Overview

The service is a Go REST API backed by PostgreSQL. Its request path follows
`HTTP handler -> service -> repository -> PostgreSQL`; authentication and
configuration are composed at startup in `cmd/api/main.go`.

- `internal/httpapi` defines the Chi routes, decodes JSON requests, applies
  authentication and permission middleware, and writes JSON responses.
- `internal/service` contains validation and workflows that combine repository
  operations, including authentication, authorization, and permission caching.
- `internal/repository` owns parameterized PostgreSQL queries and transaction
  boundaries. Mutations that need an audit record write both in one transaction.
- `internal/security` issues and validates access tokens and creates and hashes
  refresh tokens.
- `internal/database` configures the `pgxpool` connection pool and applies the
  embedded SQL migrations at startup.

The HTTP server sets read, write, idle, and header timeouts and performs a
graceful shutdown when it receives an interrupt or termination signal.

## Tenant isolation and data model

The database uses shared PostgreSQL tables. A global `users` row can belong to
multiple organizations through `memberships`; membership state and display
name are tenant-specific. Soft deletion sets `memberships.deleted_at`, leaving
the global user and other tenant memberships intact.

Protected requests derive both tenant and user identity from the verified JWT
claims (`tid` and `uid`). Protected routes do not accept a tenant selector.
Repository queries scope tenant-owned records by the token tenant. The
`membership_roles` and `role_permissions` composite foreign keys include
`tenant_id`, preventing role assignments and permission grants from crossing
tenant boundaries. A record outside the token tenant is reported as not found.

The schema migration defines constraints and indexes for tenant membership,
roles, refresh-token expiry, and tenant/actor audit history. Migrations are
embedded in the binary, sorted by filename, serialized with a PostgreSQL
advisory lock, and each applied in a transaction recorded in
`schema_migrations`.

## Authentication and authorization

Passwords are hashed with bcrypt. Login requires a tenant code, email, and
password, and succeeds only for an active tenant and active membership.

Access tokens are signed using HS256 and carry the tenant ID, user ID, issuer,
and standard issue/not-before/expiry claims. Protected requests validate the
signature, issuer, algorithm, and claims before using the identity. The
configured access-token lifetime defaults to 15 minutes.

Refresh tokens are generated from 32 random bytes. Only their SHA-256 hashes
are stored in PostgreSQL. Rotation locks and revokes the existing token and
inserts its replacement in a transaction; logout revokes a token. The default
refresh-token lifetime is 720 hours.

Permissions use `resource:action` names. Tenant roles are connected to
permissions through `role_permissions` and to users through
`membership_roles`. Tenant creation provisions the owner with an `admin` role
containing the permission catalog. The permission middleware returns 401 for
missing or invalid access tokens and 403 when an authenticated identity lacks
the required permission.

The in-process permission cache is keyed by tenant and user. Membership and
role changes invalidate affected entries; permission and tenant changes
invalidate tenant entries. Entries are also bounded by the configured TTL
(30 seconds by default), and the cache has a 10,000-entry limit. Tenant
suspension blocks permission-guarded operations except the `tenant:update`
permission path, which allows an administrator to reactivate the tenant.
Login and refresh require an active tenant and membership.

## Audit and API behavior

Audit records include the tenant, actor, action, target, JSON details, and
timestamp. Tenant and actor references are nullable in the schema. Audit writes
are synchronous with their associated mutations where applicable. The API
returns a consistent error envelope and uses pagination limits for user and
audit listings. The OpenAPI contract is in [openapi.yaml](openapi.yaml).

## Operations and trade-offs

`pgxpool` provides bounded pooled connections; the maximum is configurable.
Tenant-leading indexes support common scoped lookups. The implementation uses
a single PostgreSQL database and synchronous audit writes for straightforward
transactional behavior.

The permission cache is process-local, so invalidation is not shared across
multiple API instances. Its TTL bounds staleness, but a horizontally scaled
deployment that requires immediate cross-instance invalidation needs a shared
cache or invalidation mechanism. Other production deployment concerns include
edge rate limiting and account lockout, secret rotation, audit retention, and
controls on public tenant provisioning.

## Configuration

The application reads configuration from environment variables. `DATABASE_URL`
and `JWT_SECRET` are required; the signing secret must contain at least 32
characters. Defaults for address, token lifetimes, permission-cache TTL, and
database pool size are documented in the project [README](../README.md).
