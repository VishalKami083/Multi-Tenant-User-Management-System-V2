package audit

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/vishalKami083/multitenant-usermgmt/internal/httpx"
	repoData "github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
	"github.com/vishalKami083/multitenant-usermgmt/internal/service"
)

type application interface {
	AuditLogs(context.Context, service.Identity, int, int) ([]repoData.AuditEntry, error)
}

type Handler struct {
	app    application
	logger *slog.Logger
}

func New(app application, logger *slog.Logger) *Handler { return &Handler{app: app, logger: logger} }

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := httpx.Pagination(w, r)
	if !ok {
		return
	}
	entries, err := h.app.AuditLogs(r.Context(), httpx.IdentityFromContext(r.Context()), limit, offset)
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": entries, "limit": limit, "offset": offset})
}
