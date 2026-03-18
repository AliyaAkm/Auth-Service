package notification

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/smtp"
	"strings"
)

type SMTPPasswordResetCodeSender struct {
	host                 string
	port                 int
	username             string
	password             string
	fromEmail            string
	fromName             string
	passwordResetSubject string
}

func NewSMTPPasswordResetCodeSender(host string, port int, username, password, fromEmail, fromName, passwordResetSubject string) (*SMTPPasswordResetCodeSender, error) {
	switch {
	case strings.TrimSpace(host) == "":
		return nil, errors.New("smtp host is required")
	case port <= 0:
		return nil, errors.New("smtp port must be greater than zero")
	case strings.TrimSpace(fromEmail) == "":
		return nil, errors.New("smtp from email is required")
	case (username == "") != (password == ""):
		return nil, errors.New("smtp username and password must be provided together")
	}

	if strings.TrimSpace(fromName) == "" {
		fromName = "Zerde Study"
	}
	if strings.TrimSpace(passwordResetSubject) == "" {
		passwordResetSubject = "Password reset code"
	}

	return &SMTPPasswordResetCodeSender{
		host:                 strings.TrimSpace(host),
		port:                 port,
		username:             strings.TrimSpace(username),
		password:             password,
		fromEmail:            strings.TrimSpace(fromEmail),
		fromName:             sanitizeHeaderValue(fromName),
		passwordResetSubject: sanitizeHeaderValue(passwordResetSubject),
	}, nil
}

func (s *SMTPPasswordResetCodeSender) SendPasswordResetCode(ctx context.Context, email, code string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	message := s.buildMessage(email, code)
	if s.port == 465 {
		return s.sendImplicitTLS(email, []byte(message))
	}

	return s.sendSTARTTLS(email, []byte(message))
}

func (s *SMTPPasswordResetCodeSender) sendSTARTTLS(email string, message []byte) error {
	addr := s.address()

	client, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}

	if err := s.authenticate(client); err != nil {
		return err
	}
	if err := client.Mail(s.fromEmail); err != nil {
		return err
	}
	if err := client.Rcpt(email); err != nil {
		return err
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	return client.Quit()
}

func (s *SMTPPasswordResetCodeSender) sendImplicitTLS(email string, message []byte) error {
	conn, err := tls.Dial("tcp", s.address(), &tls.Config{
		ServerName: s.host,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := s.authenticate(client); err != nil {
		return err
	}
	if err := client.Mail(s.fromEmail); err != nil {
		return err
	}
	if err := client.Rcpt(email); err != nil {
		return err
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	return client.Quit()
}

func (s *SMTPPasswordResetCodeSender) authenticate(client *smtp.Client) error {
	if s.username == "" && s.password == "" {
		return nil
	}

	auth := smtp.PlainAuth("", s.username, s.password, s.host)
	return client.Auth(auth)
}

func (s *SMTPPasswordResetCodeSender) buildMessage(email, code string) string {
	var body strings.Builder
	body.WriteString("From: ")
	body.WriteString(s.fromHeader())
	body.WriteString("\r\n")
	body.WriteString("To: ")
	body.WriteString(email)
	body.WriteString("\r\n")
	body.WriteString("Subject: ")
	body.WriteString(s.passwordResetSubject)
	body.WriteString("\r\n")
	body.WriteString("MIME-Version: 1.0\r\n")
	body.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	body.WriteString("\r\n")
	body.WriteString("Your password reset code is: ")
	body.WriteString(code)
	body.WriteString("\r\n\r\n")
	body.WriteString("The code expires in 15 minutes.\r\n")
	body.WriteString("If you did not request a password reset, you can ignore this email.\r\n")
	return body.String()
}

func (s *SMTPPasswordResetCodeSender) address() string {
	return fmt.Sprintf("%s:%d", s.host, s.port)
}

func (s *SMTPPasswordResetCodeSender) fromHeader() string {
	if s.fromName == "" {
		return s.fromEmail
	}

	return fmt.Sprintf("%s <%s>", s.fromName, s.fromEmail)
}

func sanitizeHeaderValue(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return strings.TrimSpace(value)
}
