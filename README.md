# Multi-Tenant User Management API

A Go and PostgreSQL REST service for tenant administration, users, roles, permissions, authentication, and audit history. Tenant identity is derived exclusively from the signed access token; callers cannot select a tenant on protected routes.

## Run locally

Requirements: Go 1.23+ and Docker Compose.

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Compose reads `.env` for variable substitution and passes it to the API container. `DATABASE_URL_DOCKER` is used by the container to reach PostgreSQL by its Compose service name; `DATABASE_URL` is for running the API directly on the host. The API listens on `http://localhost:8080`; PostgreSQL is exposed on port `5432`. Migrations and the permission catalog are applied at startup. For a local Go run, start just PostgreSQL with `docker compose up -d db`, set the environment variables from `.env.example`, override the database URL for the host, then run:

```powershell
$env:DATABASE_URL = "postgres://app:app@localhost:5432/usermgmt?sslmode=disable"
go run ./cmd/api
```

Set `JWT_SECRET` to a unique random value of at least 32 characters outside local development. The example secret is for local use only.

## First tenant and authentication

Create a tenant and its initial administrator in one operation:

```powershell
curl.exe -X POST http://localhost:8080/api/v1/tenants `
  -H "Content-Type: application/json" `
  -d "{\"name\":\"Acme\",\"code\":\"acme\",\"owner_name\":\"Admin\",\"email\":\"admin@example.com\",\"password\":\"a-long-password-123\"}"
```

The owner is assigned the tenant's `admin` role with all permissions. Login uses the tenant code as well as email and password:

```powershell
curl.exe -X POST http://localhost:8080/api/v1/auth/login `
  -H "Content-Type: application/json" `
  -d "{\"tenant_code\":\"acme\",\"email\":\"admin@example.com\",\"password\":\"a-long-password-123\"}"
```

Pass the returned `access_token` as `Authorization: Bearer <token>`. Access tokens are tenant-scoped and short lived; refresh tokens are opaque, stored only as SHA-256 hashes, and rotated atomically. Use `POST /api/v1/auth/refresh` with `{"refresh_token":"..."}` to rotate. Logout revokes a refresh token.

An email identifies one global user record. To add an existing user to another tenant, authenticate in the destination tenant and call `POST /api/v1/memberships` with `{"user_id":"..."}`. Normal user list/detail queries only expose active memberships within the token tenant.

## API and security notes

- Swagger/OpenAPI: [`docs/openapi.yaml`](docs/openapi.yaml)
- Architecture/design: [`docs/DESIGN.md`](docs/DESIGN.md)
- Entity relationship diagram: [`docs/ERD.md`](docs/ERD.md)
- Consistent errors use `{"error":{"code":"...","message":"..."}}`; missing cross-tenant records return 404, missing/invalid credentials return 401, and insufficient permissions return 403.
- User deletion removes only the tenant membership (soft delete), not the global user account.
- Tenant suspension blocks all permission-guarded API operations except `tenant:update`, which lets a tenant admin reactivate it. A suspended tenant cannot authenticate new sessions.
- Permission changes invalidate the in-process cache immediately; the configured permission-cache TTL (`PERMISSION_CACHE_TTL`, default 30 seconds) bounds stale entries if invalidation is missed.
- `GET /api/v1/permissions` returns the built-in permission catalog. Role permission updates replace that role's complete permission set.
- The database uses a shared schema and `tenant_id` scoped composite keys/queries. Application SQL never accepts tenant IDs from request bodies for protected operations.

## Configuration

| Variable | Default | Description |
|---|---:|---|
| `APP_ADDR` | `:8080` | HTTP listen address |
| `DATABASE_URL` | required | PostgreSQL connection string |
| `JWT_SECRET` | required | HS256 signing secret, at least 32 characters |
| `ACCESS_TOKEN_TTL` | `15m` | Access token lifetime |
| `REFRESH_TOKEN_TTL` | `720h` | Refresh token lifetime |
| `PERMISSION_CACHE_TTL` | `30s` | In-process permission cache duration |
| `DB_MAX_CONNS` | `30` | PostgreSQL pool maximum |

## Tests

```powershell
go test ./...
```

Unit tests run without external services. PostgreSQL integration tests skip unless `TEST_DATABASE_URL` is set; run them against a disposable database:

```powershell
$env:TEST_DATABASE_URL = "postgres://app:app@localhost:5432/usermgmt?sslmode=disable"
go test ./internal/repository -run TestTenantIsolationAndMultiTenantMembership -v
```

Do not point integration tests at a database containing data you need: the test applies the migration and cleans up its own uniquely-named records.
