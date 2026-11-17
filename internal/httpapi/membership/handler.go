package membership

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vishalKami083/multitenant-usermgmt/internal/httpx"
	"github.com/vishalKami083/multitenant-usermgmt/internal/service"
)

type application interface {
	AddMembership(context.Context, service.Identity, string) error
	UpdateMembership(context.Context, service.Identity, string, service.MembershipUpdate) error
}

type Handler struct {
	app    application
	logger *slog.Logger
}

func New(app application, logger *slog.Logger) *Handler { return &Handler{app: app, logger: logger} }

func (h *Handler) Add(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID string `json:"user_id"`
	}
	if !httpx.Decode(w, r, &body) {
		return
	}
	if err := h.app.AddMembership(r.Context(), httpx.IdentityFromContext(r.Context()), body.UserID); err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var input service.MembershipUpdate
	if !httpx.Decode(w, r, &input) {
		return
	}
	if err := h.app.UpdateMembership(r.Context(), httpx.IdentityFromContext(r.Context()), chi.URLParam(r, "userID"), input); err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
