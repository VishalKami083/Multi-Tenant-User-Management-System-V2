package service

import (
	"errors"

	"github.com/vishalKami083/multitenant-usermgmt/internal/repository"
)

type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func translate(err error) error {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return &Error{Status: 404, Code: "not_found", Message: "resource not found"}
	case errors.Is(err, repository.ErrConflict):
		return &Error{Status: 409, Code: "conflict", Message: "resource already exists"}
	case errors.Is(err, repository.ErrInvalid):
		return &Error{Status: 400, Code: "invalid_reference", Message: "one or more related resources are invalid"}
	default:
		return err
	}
}

func invalid(message string) error {
	return &Error{Status: 400, Code: "validation_error", Message: message}
}

func unauthorized() error {
	return &Error{Status: 401, Code: "unauthorized", Message: "invalid email, password, or tenant"}
}

func forbidden() error {
	return &Error{Status: 403, Code: "forbidden", Message: "permission denied"}
}
