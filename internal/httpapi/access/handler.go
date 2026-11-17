package access

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vishalKami083/multitenant-usermgmt/internal/httpx"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
	"github.com/vishalKami083/multitenant-usermgmt/internal/service"
)

type application interface {
	ListRoles(context.Context, service.Identity) ([]repoData.Role, error)
	ListPermissions(context.Context) ([]repoData.Permission, error)
	CreateRole(context.Context, service.Identity, service.RoleInput) (repoData.Role, error)
	AssignRole(context.Context, service.Identity, string, string) error
	RemoveRole(context.Context, service.Identity, string, string) error
	SetRolePermissions(context.Context, service.Identity, string, []string) error
}

type Handler struct {
	app    application
	logger *slog.Logger
}

func New(app application, logger *slog.Logger) *Handler { return &Handler{app: app, logger: logger} }

func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.app.ListRoles(r.Context(), httpx.IdentityFromContext(r.Context()))
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": roles})
}

func (h *Handler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	permissions, err := h.app.ListPermissions(r.Context())
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": permissions})
}

func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var input service.RoleInput
	if !httpx.Decode(w, r, &input) {
		return
	}
	role, err := h.app.CreateRole(r.Context(), httpx.IdentityFromContext(r.Context()), input)
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, role)
}

func (h *Handler) AssignRole(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RoleID string `json:"role_id"`
	}
	if !httpx.Decode(w, r, &body) {
		return
	}
	if err := h.app.AssignRole(r.Context(), httpx.IdentityFromContext(r.Context()), chi.URLParam(r, "userID"), body.RoleID); err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RemoveRole(w http.ResponseWriter, r *http.Request) {
	if err := h.app.RemoveRole(r.Context(), httpx.IdentityFromContext(r.Context()), chi.URLParam(r, "userID"), chi.URLParam(r, "roleID")); err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) SetRolePermissions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Permissions []string `json:"permissions"`
	}
	if !httpx.Decode(w, r, &body) {
		return
	}
	if body.Permissions == nil {
		httpx.WriteError(w, http.StatusBadRequest, "validation_error", "permissions must be an array")
		return
	}
	if err := h.app.SetRolePermissions(r.Context(), httpx.IdentityFromContext(r.Context()), chi.URLParam(r, "roleID"), body.Permissions); err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
