package handlers

import (
	"context"
	"io"
)

type objectStorage interface {
	PutObject(ctx context.Context, objectKey string, body io.ReadSeeker, size int64, contentType string) error
	PresignGetObject(objectKey string) (string, error)
}
