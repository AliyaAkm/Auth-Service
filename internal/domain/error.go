package domain

import "errors"

var (
	ErrEmailTaken          = errors.New("email already in use")
	ErrValidation          = errors.New("validation error")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrInactiveUser        = errors.New("user inactive")
	ErrInvalidToken        = errors.New("token inactive")
	ErrSessionRevoked      = errors.New("refresh session revoked")
	ErrForbidden           = errors.New("forbidden")
	ErrNotFound            = errors.New("not found")
	ErrRoleNotFound        = errors.New("role not found")
	ErrRoleAlreadyAssigned = errors.New("role already assigned")
	ErrRoleNotAssigned     = errors.New("role not assigned")
	ErrUserMustHaveRole    = errors.New("user must have at least one role")
	ErrLastAdminRemoval    = errors.New("cannot revoke the last admin role")
	ErrInternal            = errors.New("internal error")
)
