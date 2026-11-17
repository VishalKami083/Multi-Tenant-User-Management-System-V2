package httpapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vishalKami083/multitenant-usermgmt/internal/service"
)

type fakeApplication struct {
	application
	identity           service.Identity
	permissionIdentity service.Identity
	permissionName     string
	updatedMembership  string
}

func (f *fakeApplication) Authenticate(string) (service.Identity, error) {
	return f.identity, nil
}

func (f *fakeApplication) RequirePermission(_ context.Context, identity service.Identity, permission string) error {
	f.permissionIdentity = identity
	f.permissionName = permission
	if permission == "membership:update" {
		return nil
	}
	return &service.Error{Status: http.StatusForbidden, Code: "forbidden", Message: "permission denied"}
}

func (f *fakeApplication) UpdateMembership(_ context.Context, _ service.Identity, userID string, input service.MembershipUpdate) error {
	f.updatedMembership = userID + ":" + input.Status
	return nil
}

func TestProtectedRouteDistinguishesUnauthorizedAndForbidden(t *testing.T) {
	identity := service.Identity{TenantID: "token-tenant", UserID: "token-user"}
	app := &fakeApplication{identity: identity}
	handler := New(app, slog.New(slog.NewTextHandler(io.Discard, nil)))

	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("missing token status = %d, want 401", unauthenticated.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/users?tenant_id=attacker-tenant", nil)
	request.Header.Set("Authorization", "Bearer valid-for-test")
	forbidden := httptest.NewRecorder()
	handler.ServeHTTP(forbidden, request)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("insufficient permission status = %d, want 403", forbidden.Code)
	}
	if app.permissionIdentity != identity {
		t.Fatalf("permission check identity = %+v, want token identity %+v", app.permissionIdentity, identity)
	}
}

func TestMembershipStatusRouteIsTenantAuthenticatedAndPermissionGuarded(t *testing.T) {
	identity := service.Identity{TenantID: "token-tenant", UserID: "token-user"}
	app := &fakeApplication{identity: identity}
	handler := New(app, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/memberships/member-id", strings.NewReader(`{"status":"suspended"}`))
	request.Header.Set("Authorization", "Bearer valid-for-test")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", response.Code, response.Body.String())
	}
	if app.permissionIdentity != identity || app.permissionName != "membership:update" {
		t.Fatalf("permission check identity/name = %+v/%q", app.permissionIdentity, app.permissionName)
	}
	if app.updatedMembership != "member-id:suspended" {
		t.Fatalf("updated membership = %q", app.updatedMembership)
	}
}
