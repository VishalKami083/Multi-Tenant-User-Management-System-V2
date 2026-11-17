package shared

import (
	"errors"
	"net/http"

	"github.com/vishalKami083/multitenant-usermgmt/internal/repository/shared"
)

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func Translate(err error) error {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		return &Error{Status: http.StatusNotFound, Code: "not_found", Message: "resource not found"}
	case errors.Is(err, shared.ErrConflict):
		return &Error{Status: http.StatusConflict, Code: "conflict", Message: "resource already exists"}
	case errors.Is(err, shared.ErrInvalid):
		return &Error{Status: http.StatusBadRequest, Code: "invalid_reference", Message: "one or more related resources are invalid"}
	default:
		return err
	}
}

func Invalid(message string) error {
	return &Error{Status: http.StatusBadRequest, Code: "validation_error", Message: message}
}

func Unauthorized() error {
	return &Error{Status: http.StatusUnauthorized, Code: "unauthorized", Message: "invalid email, password, or tenant"}
}

func Forbidden() error {
	return &Error{Status: http.StatusForbidden, Code: "forbidden", Message: "permission denied"}
}
