CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (length(trim(name)) BETWEEN 2 AND 160),
    code text NOT NULL UNIQUE CHECK (code ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 160),
    email text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (lower(email));

CREATE TABLE IF NOT EXISTS memberships (
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    user_id uuid NOT NULL REFERENCES users(id),
    display_name text,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    PRIMARY KEY (tenant_id, user_id)
);
CREATE INDEX IF NOT EXISTS memberships_user_idx ON memberships (user_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS permissions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE CHECK (name ~ '^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$'),
    description text NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS roles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    name text NOT NULL CHECK (length(trim(name)) BETWEEN 2 AND 80),
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id)
);
CREATE INDEX IF NOT EXISTS roles_tenant_idx ON roles (tenant_id, name);

CREATE TABLE IF NOT EXISTS role_permissions (
    tenant_id uuid NOT NULL,
    role_id uuid NOT NULL,
    permission_id uuid NOT NULL REFERENCES permissions(id),
    PRIMARY KEY (tenant_id, role_id, permission_id),
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS role_permissions_permission_idx ON role_permissions (tenant_id, permission_id);

CREATE TABLE IF NOT EXISTS membership_roles (
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id, role_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES memberships(tenant_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, role_id) REFERENCES roles(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS membership_roles_user_idx ON membership_roles (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash bytea PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenants(id),
    user_id uuid NOT NULL REFERENCES users(id),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS refresh_tokens_expiry_idx ON refresh_tokens (expires_at);

CREATE TABLE IF NOT EXISTS audit_logs (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id uuid REFERENCES tenants(id),
    actor_id uuid REFERENCES users(id),
    action text NOT NULL,
    target_type text NOT NULL,
    target_id text NOT NULL DEFAULT '',
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_tenant_time_idx ON audit_logs (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_actor_time_idx ON audit_logs (actor_id, created_at DESC);

INSERT INTO permissions(name, description) VALUES
('user:create', 'Create tenant users'),
('user:read', 'Read tenant users'),
('user:update', 'Update tenant users'),
('user:delete', 'Soft-delete tenant memberships'),
('role:create', 'Create tenant roles'),
('role:read', 'Read tenant roles'),
('role:update', 'Update tenant roles and permissions'),
('role:assign', 'Assign roles to tenant users'),
('audit:read', 'Read tenant audit log'),
('tenant:read', 'Read tenant settings'),
('tenant:update', 'Update tenant settings and status'),
('membership:create', 'Add an existing user to this tenant')
ON CONFLICT (name) DO NOTHING;
