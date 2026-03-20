# Render Setup

This service is intended to run as a private Render service behind the public gateway.

## What changed for Render

- The service now supports Render's `PORT` environment variable automatically.
- The database config now supports `DB_URL` in addition to `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, and `DB_NAME`.

## Required secrets in Render

Set these manually in the Render dashboard or keep them as `sync: false` in `render.yaml`:

- `JWT_SECRET`
- `SMTP_HOST`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_FROM_EMAIL`

## Recommended deployment

1. Create a Render Postgres database.
2. Deploy `auth-service` as a private service.
3. Set `DB_URL` from the database `connectionString`.
4. Apply SQL migrations from the `migrations/` directory.
5. Set JWT and SMTP secrets in Render.
6. After the service is healthy, connect the public gateway to this private service by its Render internal `hostport`.

## Health check

- `/health`
