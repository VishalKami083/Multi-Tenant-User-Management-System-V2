package user

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
	ListUsers(context.Context, service.Identity, string, int, int) (service.UserPage, error)
	GetUser(context.Context, service.Identity, string) (repoData.User, error)
	CreateUser(context.Context, service.Identity, service.UserInput) (repoData.User, error)
	UpdateUser(context.Context, service.Identity, string, string) (repoData.User, error)
	DeleteUser(context.Context, service.Identity, string) error
}

type Handler struct {
	app    application
	logger *slog.Logger
}

func New(app application, logger *slog.Logger) *Handler { return &Handler{app: app, logger: logger} }

func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var input service.UserInput
	if !httpx.Decode(w, r, &input) {
		return
	}
	user, err := h.app.CreateUser(r.Context(), httpx.IdentityFromContext(r.Context()), input)
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, user)
}

func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := httpx.Pagination(w, r)
	if !ok {
		return
	}
	page, err := h.app.ListUsers(r.Context(), httpx.IdentityFromContext(r.Context()), r.URL.Query().Get("search"), limit, offset)
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	user, err := h.app.GetUser(r.Context(), httpx.IdentityFromContext(r.Context()), chi.URLParam(r, "userID"))
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, user)
}

func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !httpx.Decode(w, r, &body) {
		return
	}
	user, err := h.app.UpdateUser(r.Context(), httpx.IdentityFromContext(r.Context()), chi.URLParam(r, "userID"), body.Name)
	if err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, user)
}

func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.app.DeleteUser(r.Context(), httpx.IdentityFromContext(r.Context()), chi.URLParam(r, "userID")); err != nil {
		httpx.Fail(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
