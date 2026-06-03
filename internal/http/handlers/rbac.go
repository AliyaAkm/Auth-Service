package handlers

import (
	"auth-service/internal/domain"
	"auth-service/internal/http/dto"
	"auth-service/internal/http/middleware"
	"auth-service/internal/http/respond"
	"auth-service/internal/usecase"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const maxProfilePhotoUploadSize = 10 * 1024 * 1024

type RBACHandler struct {
	uc      *usecase.RBAC
	storage objectStorage
}

func NewRBACHandler(uc *usecase.RBAC, storage objectStorage) *RBACHandler {
	return &RBACHandler{uc: uc, storage: storage}
}

func (h *RBACHandler) ListUsers(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	users, err := h.uc.ListUsers(c, actorUserID)
	if err != nil {
		writeDomainError(c, err)
		return
	}
	if err = h.attachPhotoURLs(c.Request.Context(), users); err != nil {
		_ = c.Error(err)
		respond.Error(c, http.StatusInternalServerError, "storage", "presign user photo")
		return
	}

	respond.JSON(c, http.StatusOK, toUserResponses(users))
}

func (h *RBACHandler) UpdateUserRoles(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	var req dto.ReplaceUserRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if req.UserID == uuid.Nil {
		respond.Error(c, http.StatusBadRequest, "validation", "user_id required")
		return
	}

	roleIDs := req.EffectiveRoleIDs()
	if len(roleIDs) == 0 {
		respond.Error(c, http.StatusBadRequest, "validation", "role_ids required")
		return
	}

	roles, err := h.uc.ReplaceUserRoles(c, actorUserID, req.UserID, roleIDs)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserRolesResponse(req.UserID, roles))
}

func (h *RBACHandler) ListRoles(c *gin.Context) {
	roles, err := h.uc.ListRoles(c)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toRoleResponses(roles))
}

func (h *RBACHandler) GetUserProfile(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	user, err := h.uc.GetUserProfile(c, actorUserID, actorUserID)
	if err != nil {
		writeDomainError(c, err)
		return
	}
	if err = h.attachPhotoURL(c.Request.Context(), &user); err != nil {
		_ = c.Error(err)
		respond.Error(c, http.StatusInternalServerError, "storage", "presign user photo")
		return
	}

	respond.JSON(c, http.StatusOK, toProfileResponse(&user))
}

func (h *RBACHandler) GetUserProfileByID(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	targetUserID, err := uuid.Parse(c.Param("userID"))
	if err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid user id")
		return
	}

	user, err := h.uc.GetUserProfileByID(c, actorUserID, targetUserID)
	if err != nil {
		writeDomainError(c, err)
		return
	}
	if err = h.attachPhotoURL(c.Request.Context(), &user); err != nil {
		_ = c.Error(err)
		respond.Error(c, http.StatusInternalServerError, "storage", "presign user photo")
		return
	}

	respond.JSON(c, http.StatusOK, toProfileResponse(&user))
}

func (h *RBACHandler) UpdateUserProfile(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	update, err := h.profileUpdateFromRequest(c, actorUserID)
	if err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if update.Email != nil {
		normalized := normalizeEmail(*update.Email)
		if err := domain.ValidateEmail(normalized); err != nil {
			respond.Error(c, http.StatusBadRequest, "validation", "invalid email")
			return
		}
		update.Email = &normalized
	}

	user, err := h.uc.UpdateUserProfile(c, actorUserID, actorUserID, update)
	if err != nil {
		writeDomainError(c, err)
		return
	}
	if err = h.attachPhotoURL(c.Request.Context(), &user); err != nil {
		_ = c.Error(err)
		respond.Error(c, http.StatusInternalServerError, "storage", "presign user photo")
		return
	}

	respond.JSON(c, http.StatusOK, toProfileResponse(&user))
}

func (h *RBACHandler) profileUpdateFromRequest(c *gin.Context, userID uuid.UUID) (domain.UserProfileUpdate, error) {
	if strings.HasPrefix(strings.ToLower(c.GetHeader("Content-Type")), "multipart/form-data") {
		return h.profileUpdateFromMultipart(c, userID)
	}

	var req dto.UpdateUserProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return domain.UserProfileUpdate{}, errors.New("invalid json")
	}

	update := domain.UserProfileUpdate{
		Email:    cleanOptional(req.Email),
		Login:    firstOptional(cleanOptional(req.Login), cleanOptional(req.Name)),
		Bio:      cleanOptional(req.Bio),
		PhotoURL: firstOptional(cleanOptional(req.PhotoURL), cleanOptional(req.AvatarURL)),
	}

	if req.AvatarBase64 != nil && strings.TrimSpace(*req.AvatarBase64) != "" {
		objectKey, err := h.uploadProfilePhotoBase64(c.Request.Context(), userID, *req.AvatarBase64)
		if err != nil {
			return domain.UserProfileUpdate{}, err
		}
		update.PhotoObjectKey = &objectKey
		empty := ""
		update.PhotoURL = &empty
	}

	return update, nil
}

func (h *RBACHandler) profileUpdateFromMultipart(c *gin.Context, userID uuid.UUID) (domain.UserProfileUpdate, error) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxProfilePhotoUploadSize)
	if err := c.Request.ParseMultipartForm(maxProfilePhotoUploadSize); err != nil {
		return domain.UserProfileUpdate{}, errors.New("invalid multipart form")
	}

	update := domain.UserProfileUpdate{
		Email: cleanOptional(formValue(c, "email")),
		Login: firstOptional(
			cleanOptional(formValue(c, "login")),
			cleanOptional(formValue(c, "name")),
		),
		Bio: cleanOptional(formValue(c, "bio")),
	}

	file, header, err := firstMultipartFile(c, "photo", "avatar", "image")
	if err != nil {
		if errors.Is(err, http.ErrMissingFile) {
			return update, nil
		}
		return domain.UserProfileUpdate{}, err
	}
	defer file.Close()

	objectKey, err := h.uploadProfilePhotoFile(c.Request.Context(), userID, file, header)
	if err != nil {
		return domain.UserProfileUpdate{}, err
	}
	update.PhotoObjectKey = &objectKey
	empty := ""
	update.PhotoURL = &empty

	return update, nil
}

func (h *RBACHandler) uploadProfilePhotoBase64(ctx context.Context, userID uuid.UUID, raw string) (string, error) {
	data, contentType, err := decodeProfilePhotoBase64(raw)
	if err != nil {
		return "", err
	}
	if len(data) > maxProfilePhotoUploadSize {
		return "", fmt.Errorf("photo is too large")
	}

	ext, err := profilePhotoExt(contentType, "")
	if err != nil {
		return "", err
	}

	objectKey := buildProfilePhotoObjectKey(userID, ext)
	return objectKey, h.uploadProfilePhoto(ctx, objectKey, bytes.NewReader(data), int64(len(data)), contentType)
}

func (h *RBACHandler) uploadProfilePhotoFile(ctx context.Context, userID uuid.UUID, file multipart.File, header *multipart.FileHeader) (string, error) {
	if header == nil {
		return "", errors.New("photo file is required")
	}
	if header.Size > maxProfilePhotoUploadSize {
		return "", fmt.Errorf("photo is too large")
	}

	contentType := strings.TrimSpace(header.Header.Get("Content-Type"))
	ext, err := profilePhotoExt(contentType, header.Filename)
	if err != nil {
		return "", err
	}
	if contentType == "" {
		contentType = profilePhotoContentType(ext)
	}

	objectKey := buildProfilePhotoObjectKey(userID, ext)
	return objectKey, h.uploadProfilePhoto(ctx, objectKey, file, header.Size, contentType)
}

func (h *RBACHandler) uploadProfilePhoto(ctx context.Context, objectKey string, body io.ReadSeeker, size int64, contentType string) error {
	if h.storage == nil {
		return errors.New("profile photo storage is not configured")
	}
	if err := h.storage.PutObject(ctx, objectKey, body, size, contentType); err != nil {
		return fmt.Errorf("upload profile photo: %w", err)
	}
	return nil
}

func (h *RBACHandler) attachPhotoURLs(ctx context.Context, users []domain.User) error {
	for i := range users {
		if err := h.attachPhotoURL(ctx, &users[i]); err != nil {
			return err
		}
	}
	return nil
}

func (h *RBACHandler) attachPhotoURL(_ context.Context, user *domain.User) error {
	if user == nil || strings.TrimSpace(user.PhotoObjectKey) == "" {
		return nil
	}
	if h.storage == nil {
		return errors.New("profile photo storage is not configured")
	}

	url, err := h.storage.PresignGetObject(user.PhotoObjectKey)
	if err != nil {
		return err
	}
	user.PhotoURL = url
	return nil
}

func formValue(c *gin.Context, key string) *string {
	value, ok := c.GetPostForm(key)
	if !ok {
		return nil
	}
	return &value
}

func firstMultipartFile(c *gin.Context, keys ...string) (multipart.File, *multipart.FileHeader, error) {
	for _, key := range keys {
		file, header, err := c.Request.FormFile(key)
		if err == nil {
			return file, header, nil
		}
		if !errors.Is(err, http.ErrMissingFile) {
			return nil, nil, err
		}
	}
	return nil, nil, http.ErrMissingFile
}

func decodeProfilePhotoBase64(raw string) ([]byte, string, error) {
	value := strings.TrimSpace(raw)
	contentType := ""
	if strings.HasPrefix(value, "data:") {
		comma := strings.Index(value, ",")
		if comma < 0 {
			return nil, "", errors.New("invalid avatarBase64 data url")
		}
		meta := strings.TrimPrefix(value[:comma], "data:")
		contentType = strings.Split(meta, ";")[0]
		value = value[comma+1:]
	}

	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, "", errors.New("invalid avatarBase64")
	}
	if contentType == "" {
		contentType = http.DetectContentType(data)
	}

	return data, contentType, nil
}

func profilePhotoExt(contentType string, filename string) (string, error) {
	contentType = strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	ext := strings.ToLower(filepath.Ext(filename))

	switch contentType {
	case "image/jpeg", "image/jpg":
		return ".jpg", nil
	case "image/png":
		return ".png", nil
	case "image/webp":
		return ".webp", nil
	case "image/gif":
		return ".gif", nil
	}

	switch ext {
	case ".jpg", ".jpeg":
		return ".jpg", nil
	case ".png", ".webp", ".gif":
		return ext, nil
	}

	return "", errors.New("photo must be jpg, png, webp, or gif")
}

func profilePhotoContentType(ext string) string {
	switch ext {
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".webp":
		return "image/webp"
	case ".gif":
		return "image/gif"
	default:
		if contentType := mime.TypeByExtension(ext); contentType != "" {
			return contentType
		}
		return "application/octet-stream"
	}
}

func buildProfilePhotoObjectKey(userID uuid.UUID, ext string) string {
	return "users/" + userID.String() + "/avatar/" + uuid.New().String() + ext
}

func (h *RBACHandler) GetUserRoles(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	targetUserID, err := uuid.Parse(c.Param("userID"))
	if err != nil {
		respond.Error(c, http.StatusBadRequest, "validation", "invalid user id")
		return
	}

	roles, err := h.uc.GetUserRoles(c, actorUserID, targetUserID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserRolesResponse(targetUserID, roles))
}

func (h *RBACHandler) RevokeRoles(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	var req dto.RevokeUserRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if req.UserID == uuid.Nil || req.RoleID == uuid.Nil {
		respond.Error(c, http.StatusBadRequest, "validation", "user_id and role_id required")
		return
	}

	roles, err := h.uc.RevokeRole(c, actorUserID, req.UserID, req.RoleID)
	if err != nil {
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserRolesResponse(req.UserID, roles))
}

func (h *RBACHandler) UpdateUserStatus(c *gin.Context) {
	actorUserID, ok := middleware.CurrentUserID(c)
	if !ok {
		respond.Error(c, http.StatusUnauthorized, "unauthorized", "missing authenticated user")
		return
	}

	var req dto.UpdateUserStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respond.Error(c, http.StatusBadRequest, "bad_request", "invalid json")
		return
	}
	if req.UserID == uuid.Nil {
		respond.Error(c, http.StatusBadRequest, "validation", "user_id required")
		return
	}
	if req.IsActive == nil {
		respond.Error(c, http.StatusBadRequest, "validation", "is_active required")
		return
	}

	user, err := h.uc.UpdateUserStatus(c, actorUserID, req.UserID, *req.IsActive)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			respond.Error(c, http.StatusNotFound, "not_found", domain.ErrNotFound.Error())
			return
		}
		writeDomainError(c, err)
		return
	}

	respond.JSON(c, http.StatusOK, toUserResponse(&user))
}

func cleanOptional(value *string) *string {
	if value == nil {
		return nil
	}
	cleaned := strings.TrimSpace(*value)
	return &cleaned
}

func firstOptional(values ...*string) *string {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}
