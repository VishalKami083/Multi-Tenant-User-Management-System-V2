# Design and architecture

## Overview

The service is a Go REST API backed by PostgreSQL. Its request path follows
`domain HTTP handler -> domain service -> repository port -> PostgreSQL`;
configuration and dependency composition happen at startup in `cmd/api/main.go`.

- `internal/httpapi` composes Chi routes and applies shared authentication and
  permission middleware. Domain handlers live under `internal/httpapi/{auth,
  tenant,user,membership,access,audit}` and use shared decoding, response, and
  identity helpers from `internal/httpx`.
- `internal/domain/{auth,tenant,user,membership,access,audit}` owns domain
  workflows and narrow repository interfaces. Shared identity, validation, and
  error translation live in `internal/domain/shared`.
- `internal/service` is a compatibility/composition facade that wires the
  domain services to the PostgreSQL adapters.
- `internal/repository/{tenant,user,auth,membership,access,audit}` contains
  independent PostgreSQL adapters, each implementing the corresponding domain
  repository interface with parameterized queries. Shared persistence models,
  sentinel errors, and audit/error helpers live in `internal/repository/shared`.
  The root `internal/repository` package composes these adapters behind the
  existing `New(pool)` entry point; domain services depend on their narrow
  interfaces, not on this composition facade.
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
Suspension is reversible and tenant-scoped: it preserves the membership and
role assignments but blocks login, refresh, listings, and permission checks
until reactivation. Soft deletion remains a separate operation and clears the
membership's role assignments. Administrators cannot suspend their own
membership through the API, preventing accidental self-lockout.

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

Each API instance has a bounded permission cache keyed by tenant and user.
Membership and role mutations publish PostgreSQL `NOTIFY` events in the same
transaction as the data change; every API instance listens on a dedicated
connection and invalidates the affected member or tenant cache. If a listener
reconnects after missing events, it clears the entire local cache before
resuming. The configured TTL (30 seconds by default) bounds staleness during a
listener outage, and each cache is limited to 10,000 entries. Tenant suspension
blocks permission-guarded operations except the `tenant:update` permission
path, which allows an administrator to reactivate the tenant. Login and refresh
require an active tenant and membership. The `membership:update` permission
controls membership suspension and reactivation.

## Audit and API behavior

Audit records include the tenant, actor, action, target, JSON details, and
timestamp. Tenant and actor references are nullable in the schema. Audit writes
are synchronous with their associated mutations where applicable. Successful
logins are audited with the actor; failed logins for a known tenant are
recorded without an actor or credential details, and unknown tenant codes do
not create tenant audit records. The API
returns a consistent error envelope and uses pagination limits for user and
audit listings. The OpenAPI contract is in [openapi.yaml](openapi.yaml).

Focused unit tests cover auth rejection/audit behavior, permission-cache
invalidation and capacity handling, HTTP authorization, and input validation.
Database-backed repository and service integration tests run only when
`TEST_DATABASE_URL` is configured.

## Operations and trade-offs

`pgxpool` provides bounded pooled connections; the maximum is configurable per
API instance. The Compose proxy routes traffic to API replicas and resolves the
replica set dynamically. Scale the API with
`docker compose up --build --scale api=3`; only the proxy publishes the
application port.

Each API replica also holds one dedicated PostgreSQL connection for
`LISTEN/NOTIFY`. Size `DB_MAX_CONNS` and PostgreSQL `max_connections` for the
sum of all replica pools, listener connections, migration/startup work, and
other clients. PostgreSQL notifications are transactional but not durable;
reconnecting instances clear their cache, and the cache TTL bounds stale data
during listener outages. Other production deployment concerns include edge
rate limiting and account lockout, secret rotation, audit retention, and
controls on public tenant provisioning.

## Configuration

The application reads configuration from environment variables. `DATABASE_URL`
and `JWT_SECRET` are required; the signing secret must contain at least 32
characters. Defaults for address, token lifetimes, permission-cache TTL, and
database pool size are documented in the project [README](../README.md).
