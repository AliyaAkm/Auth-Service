package domain

import "errors"

var (
	ErrEmailTaken         = errors.New("email already in use")
	ErrValidation         = errors.New("validation error")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInactiveUser       = errors.New("user inactive")
	ErrInvalidToken       = errors.New("token inactive")
	ErrSessionRevoked     = errors.New("refresh session revoked")
	ErrNotFound           = errors.New("not found")
	ErrInternal           = errors.New("internal error")
)
