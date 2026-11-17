INSERT INTO permissions(name, description) VALUES
('membership:update', 'Suspend or reactivate a tenant membership')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions(tenant_id, role_id, permission_id)
SELECT r.tenant_id, r.id, p.id
FROM roles r
JOIN permissions p ON p.name = 'membership:update'
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;
