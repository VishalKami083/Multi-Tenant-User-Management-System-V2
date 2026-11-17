package httpx

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/vishalKami083/multitenant-usermgmt/internal/service"
)

type identityKey struct{}

func WithIdentity(ctx context.Context, identity service.Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, identity)
}

func IdentityFromContext(ctx context.Context) service.Identity {
	identity, _ := ctx.Value(identityKey{}).(service.Identity)
	return identity
}

func Decode(w http.ResponseWriter, r *http.Request, destination any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_json", "request body must contain valid JSON with supported fields")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		WriteError(w, http.StatusBadRequest, "invalid_json", "request body must contain a single JSON value")
		return false
	}
	return true
}

func Pagination(w http.ResponseWriter, r *http.Request) (int, int, bool) {
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
		WriteError(w, http.StatusBadRequest, "validation_error", "limit must be 1-100 and offset must be non-negative")
		return 0, 0, false
	}
	return limit, offset, true
}

func Fail(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	var appErr *service.Error
	if errors.As(err, &appErr) {
		WriteError(w, appErr.Status, appErr.Code, appErr.Message)
		return
	}
	logger.ErrorContext(r.Context(), "request failed", "request_id", middleware.GetReqID(r.Context()), "error", err)
	WriteError(w, http.StatusInternalServerError, "internal_error", "an unexpected error occurred")
}

type errorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func WriteError(w http.ResponseWriter, status int, code, message string) {
	var response errorEnvelope
	response.Error.Code = code
	response.Error.Message = message
	WriteJSON(w, status, response)
}

func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
