package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/vishalKami083/multitenant-usermgmt/internal/repository"
	"github.com/vishalKami083/multitenant-usermgmt/internal/security"
	"github.com/vishalKami083/multitenant-usermgmt/internal/service"
)

type application interface {
	CreateTenant(context.Context, service.TenantInput) (repository.Tenant, repository.User, error)
	GetTenant(context.Context, service.Identity) (repository.Tenant, error)
	UpdateTenant(context.Context, service.Identity, service.TenantUpdate) (repository.Tenant, error)
	Login(context.Context, string, string, string) (security.TokenPair, error)
	Refresh(context.Context, string) (security.TokenPair, error)
	Logout(context.Context, string) error
	Authenticate(string) (service.Identity, error)
	RequirePermission(context.Context, service.Identity, string) error
	ListUsers(context.Context, service.Identity, string, int, int) (service.UserPage, error)
	GetUser(context.Context, service.Identity, string) (repository.User, error)
	CreateUser(context.Context, service.Identity, service.UserInput) (repository.User, error)
	UpdateUser(context.Context, service.Identity, string, string) (repository.User, error)
	DeleteUser(context.Context, service.Identity, string) error
	AddMembership(context.Context, service.Identity, string) error
	ListRoles(context.Context, service.Identity) ([]repository.Role, error)
	ListPermissions(context.Context) ([]repository.Permission, error)
	CreateRole(context.Context, service.Identity, service.RoleInput) (repository.Role, error)
	AssignRole(context.Context, service.Identity, string, string) error
	RemoveRole(context.Context, service.Identity, string, string) error
	SetRolePermissions(context.Context, service.Identity, string, []string) error
	AuditLogs(context.Context, service.Identity, int, int) ([]repository.AuditEntry, error)
}

type API struct {
	app    application
	logger *slog.Logger
}

type identityKey struct{}

func New(app application, logger *slog.Logger) http.Handler {
	a := &API{app: app, logger: logger}
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Recoverer)
	r.Use(a.accessLog)
	r.Get("/healthz", a.health)
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/tenants", a.createTenant)
		r.Post("/auth/login", a.login)
		r.Post("/auth/refresh", a.refresh)
		r.Post("/auth/logout", a.logout)
		r.Group(func(r chi.Router) {
			r.Use(a.authenticate)
			r.With(a.permission("tenant:read")).Get("/tenant", a.getTenant)
			r.With(a.permission("tenant:update")).Patch("/tenant", a.updateTenant)
			r.With(a.permission("user:create")).Post("/users", a.createUser)
			r.With(a.permission("user:read")).Get("/users", a.listUsers)
			r.With(a.permission("user:read")).Get("/users/{userID}", a.getUser)
			r.With(a.permission("user:update")).Patch("/users/{userID}", a.updateUser)
			r.With(a.permission("user:delete")).Delete("/users/{userID}", a.deleteUser)
			r.With(a.permission("membership:create")).Post("/memberships", a.addMembership)
			r.With(a.permission("role:read")).Get("/roles", a.listRoles)
			r.With(a.permission("role:read")).Get("/permissions", a.listPermissions)
			r.With(a.permission("role:create")).Post("/roles", a.createRole)
			r.With(a.permission("role:assign")).Post("/users/{userID}/roles", a.assignRole)
			r.With(a.permission("role:assign")).Delete("/users/{userID}/roles/{roleID}", a.removeRole)
			r.With(a.permission("role:update")).Put("/roles/{roleID}/permissions", a.setRolePermissions)
			r.With(a.permission("audit:read")).Get("/audit-logs", a.listAuditLogs)
		})
	})
	return r
}

func (a *API) getTenant(w http.ResponseWriter, r *http.Request) {
	tenant, err := a.app.GetTenant(r.Context(), currentIdentity(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

func (a *API) updateTenant(w http.ResponseWriter, r *http.Request) {
	var input service.TenantUpdate
	if !decode(w, r, &input) {
		return
	}
	tenant, err := a.app.UpdateTenant(r.Context(), currentIdentity(r), input)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, tenant)
}

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) createTenant(w http.ResponseWriter, r *http.Request) {
	var input service.TenantInput
	if !decode(w, r, &input) {
		return
	}
	tenant, owner, err := a.app.CreateTenant(r.Context(), input)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"tenant": tenant, "owner": owner})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantCode string `json:"tenant_code"`
		Email      string `json:"email"`
		Password   string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	result, err := a.app.Login(r.Context(), body.TenantCode, body.Email, body.Password)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *API) refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &body) {
		return
	}
	result, err := a.app.Refresh(r.Context(), body.RefreshToken)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := a.app.Logout(r.Context(), body.RefreshToken); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var input service.UserInput
	if !decode(w, r, &input) {
		return
	}
	user, err := a.app.CreateUser(r.Context(), currentIdentity(r), input)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, user)
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pagination(w, r)
	if !ok {
		return
	}
	page, err := a.app.ListUsers(r.Context(), currentIdentity(r), r.URL.Query().Get("search"), limit, offset)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (a *API) getUser(w http.ResponseWriter, r *http.Request) {
	user, err := a.app.GetUser(r.Context(), currentIdentity(r), chi.URLParam(r, "userID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (a *API) updateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	user, err := a.app.UpdateUser(r.Context(), currentIdentity(r), chi.URLParam(r, "userID"), body.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	if err := a.app.DeleteUser(r.Context(), currentIdentity(r), chi.URLParam(r, "userID")); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) addMembership(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID string `json:"user_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := a.app.AddMembership(r.Context(), currentIdentity(r), body.UserID); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (a *API) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := a.app.ListRoles(r.Context(), currentIdentity(r))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": roles})
}

func (a *API) listPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := a.app.ListPermissions(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": permissions})
}

func (a *API) createRole(w http.ResponseWriter, r *http.Request) {
	var input service.RoleInput
	if !decode(w, r, &input) {
		return
	}
	role, err := a.app.CreateRole(r.Context(), currentIdentity(r), input)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

func (a *API) assignRole(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RoleID string `json:"role_id"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := a.app.AssignRole(r.Context(), currentIdentity(r), chi.URLParam(r, "userID"), body.RoleID); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) removeRole(w http.ResponseWriter, r *http.Request) {
	if err := a.app.RemoveRole(r.Context(), currentIdentity(r), chi.URLParam(r, "userID"), chi.URLParam(r, "roleID")); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) setRolePermissions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Permissions []string `json:"permissions"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.Permissions == nil {
		writeError(w, http.StatusBadRequest, "validation_error", "permissions must be an array")
		return
	}
	if err := a.app.SetRolePermissions(r.Context(), currentIdentity(r), chi.URLParam(r, "roleID"), body.Permissions); err != nil {
		a.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := pagination(w, r)
	if !ok {
		return
	}
	entries, err := a.app.AuditLogs(r.Context(), currentIdentity(r), limit, offset)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": entries, "limit": limit, "offset": offset})
}

func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.Fields(r.Header.Get("Authorization"))
		if len(header) != 2 || !strings.EqualFold(header[0], "Bearer") {
			writeError(w, http.StatusUnauthorized, "unauthorized", "bearer access token required")
			return
		}
		identity, err := a.app.Authenticate(header[1])
		if err != nil {
			a.fail(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), identityKey{}, identity)))
	})
}

func (a *API) permission(name string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := a.app.RequirePermission(r.Context(), currentIdentity(r), name); err != nil {
				a.fail(w, r, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func currentIdentity(r *http.Request) service.Identity {
	identity, _ := r.Context().Value(identityKey{}).(service.Identity)
	return identity
}

func decode(w http.ResponseWriter, r *http.Request, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain valid JSON with supported fields")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must contain a single JSON value")
		return false
	}
	return true
}

func pagination(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	limit := 20
	offset := 0
	var err error
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
	}
	if err == nil {
		if raw := r.URL.Query().Get("offset"); raw != "" {
			offset, err = strconv.Atoi(raw)
		}
	}
	if err != nil || limit < 1 || limit > 100 || offset < 0 {
		writeError(w, http.StatusBadRequest, "validation_error", "limit must be 1-100 and offset must be non-negative")
		return 0, 0, false
	}
	return limit, offset, true
}

func (a *API) fail(w http.ResponseWriter, r *http.Request, err error) {
	var appErr *service.Error
	if errors.As(err, &appErr) {
		writeError(w, appErr.Status, appErr.Code, appErr.Message)
		return
	}
	a.logger.ErrorContext(r.Context(), "request failed", "request_id", middleware.GetReqID(r.Context()), "error", err)
	writeError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
}

func (a *API) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		a.logger.InfoContext(r.Context(), "http request", "request_id", middleware.GetReqID(r.Context()),
			"method", r.Method, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
	})
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	var response errorEnvelope
	response.Error.Code = code
	response.Error.Message = message
	writeJSON(w, status, response)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
