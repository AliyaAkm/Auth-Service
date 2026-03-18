package domain

import (
	"strings"
)

// todo: перенести в хэндлер и убрать в us (выполнила)
func ValidateEmail(email string) error {
	if email == "" {
		return ErrValidation
	}
	if len(email) > 254 {
		return ErrValidation
	}
	if strings.ContainsAny(email, " \t\n\r") {
		return ErrValidation
	}
	at := strings.IndexByte(email, '@')
	if at <= 0 || at == len(email)-1 {
		return ErrValidation
	}
	local := email[:at]
	domain := email[at+1:]
	if local == "" || domain == "" {
		return ErrValidation
	}
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return ErrValidation
	}
	return nil
}

func ValidatePassword(pw string) error {
	pw = strings.TrimSpace(pw)
	if pw == "" {
		return ErrValidation
	}
	if len(pw) < 8 {
		return ErrValidation
	}
	// bcrypt
	if len(pw) > 72 {
		return ErrValidation
	}
	return nil
}
