package tenant

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/vishalKami083/multitenant-usermgmt/internal/httpx"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
	"github.com/vishalKami083/multitenant-usermgmt/internal/service"
)

type application interface {
	CreateTenant(context.Context, service.TenantInput) (repoData.Tenant, repoData.User, error)
	GetTenant(context.Context, service.Identity) (repoData.Tenant, error)
	UpdateTenant(context.Context, service.Identity, service.TenantUpdate) (repoData.Tenant, error)
}

type Handler struct {
	app    application
	logger *slog.Logger
}

func New(app application, logger *slog.Logger) *Handler { return &Handler{app: app, logger: logger} }

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var input service.TenantInput
	if !httpx.Decode(w, r, &input) {
		return
	}
	tenant, owner, err := h.app.CreateTenant(r.Context(), input)
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"tenant": tenant, "owner": owner})
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	tenant, err := h.app.GetTenant(r.Context(), httpx.IdentityFromContext(r.Context()))
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, tenant)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var input service.TenantUpdate
	if !httpx.Decode(w, r, &input) {
		return
	}
	tenant, err := h.app.UpdateTenant(r.Context(), httpx.IdentityFromContext(r.Context()), input)
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, tenant)
}
