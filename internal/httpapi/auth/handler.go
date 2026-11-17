package auth

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/vishalKami083/multitenant-usermgmt/internal/httpx"
	"github.com/vishalKami083/multitenant-usermgmt/internal/security"
)

type application interface {
	Login(context.Context, string, string, string) (security.TokenPair, error)
	Refresh(context.Context, string) (security.TokenPair, error)
	Logout(context.Context, string) error
}

type Handler struct {
	app    application
	logger *slog.Logger
}

func New(app application, logger *slog.Logger) *Handler { return &Handler{app: app, logger: logger} }

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TenantCode string `json:"tenant_code"`
		Email      string `json:"email"`
		Password   string `json:"password"`
	}
	if !httpx.Decode(w, r, &body) {
		return
	}
	result, err := h.app.Login(r.Context(), body.TenantCode, body.Email, body.Password)
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !httpx.Decode(w, r, &body) {
		return
	}
	result, err := h.app.Refresh(r.Context(), body.RefreshToken)
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, result)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !httpx.Decode(w, r, &body) {
		return
	}
	if err := h.app.Logout(r.Context(), body.RefreshToken); err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
