# PodClub Backend

FastAPI backend for PodClub using SQLAlchemy 2, PostgreSQL, Alembic, and JWT
authentication. It currently implements Phase 1B club-scoped authorization,
memberships, club bans, reports, and platform roles.

## Stack

- FastAPI and Uvicorn
- PostgreSQL
- SQLAlchemy 2
- Alembic
- PyJWT and bcrypt
- Pydantic 2
- pytest and httpx

## Requirements

- Python 3.12 recommended
- PostgreSQL running on `localhost:5432`
- A virtual environment

The application database and test database must be separate. Tests are configured
for a real PostgreSQL test database and do not support SQLite.

## Installation

Clone the repository and enter it:

```bash
git clone https://github.com/Jeremy-3/PodClub-Backend.git
cd PodClub-Backend
```

PowerShell:

```powershell
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

bash:

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Environment

Copy `.env.example` to `.env`:

PowerShell:

```powershell
Copy-Item .env.example .env
```

bash:

```bash
cp .env.example .env
```

Update `.env` with local PostgreSQL credentials and secrets. Do not commit
`.env`. It is intentionally ignored by Git.

Required and commonly used settings include:

```dotenv
APP_ENV=local
DEBUG=True
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/podclub
DATABASE_URL_TEST=postgresql://postgres:postgres@localhost:5432/podclub_test
JWT_SECRET_KEY=replace-this-with-a-long-random-secret
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_SECONDS=18000
CORS_ORIGINS=["http://localhost:3000","http://localhost:5173"]

SUPERADMIN_NAME=Super Admin
SUPERADMIN_EMAIL=admin@podclub.io
SUPERADMIN_PASSWORD=AdminPassword123!
```

`JWT_SECRET_KEY` must not remain `not-secret-key` outside `APP_ENV=local`.
`DATABASE_URL` and `DATABASE_URL_TEST` must use a localhost PostgreSQL server,
not a Unix socket.

## Database Setup

Before applying migrations to an existing database, back it up. Do not run
migrations against an existing database without preserving or intentionally
upgrading its data.

PowerShell and bash:

```powershell
alembic upgrade head
```

```bash
alembic upgrade head
```

To inspect migration state:

```powershell
alembic current
alembic heads
alembic check
```

```bash
alembic current
alembic heads
alembic check
```

## Seed

Create or reconcile the built-in platform roles and permissions:

```powershell
python -m app.commands.seed
```

```bash
python -m app.commands.seed
```

Include demo users and club content:

```powershell
python -m app.commands.seed --dummy
```

```bash
python -m app.commands.seed --dummy
```

The dummy accounts use the `@podclub.io` addresses shown at the end of the seed
output and the password `Password123!`.

To reconcile old permission names and system-role grants after a migration,
first take a PostgreSQL backup and preview the reset:

```powershell
python -m app.commands.seed --reset-permissions
```

```bash
python -m app.commands.seed --reset-permissions
```

This command asks for confirmation. For a non-interactive run:

```powershell
python -m app.commands.seed --reset-permissions --yes
```

```bash
python -m app.commands.seed --reset-permissions --yes
```

The reset is destructive to obsolete permission rows and extra system-role grants.

## Run the API

The application entry point is `main.py` at the repository root.

PowerShell:

```powershell
uvicorn main:app --reload
```

bash:

```bash
uvicorn main:app --reload
```

- API: `http://localhost:8000`
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- Health check: `http://localhost:8000/health`

## Authentication

JWTs contain the user ID, issued-at time, and expiration. The token does not
contain a role or permissions. Role and permissions are loaded from PostgreSQL
for each authenticated request.

- `POST /auth/register` creates a platform `user`
- `POST /auth/login` accepts a username or email
- `GET /auth/me` returns the user, role name, and permission names

The login endpoint uses form data for Swagger and OAuth2 compatibility:

```text
username=<username-or-email>
password=<password>
```

Unknown usernames, unknown emails, and wrong passwords return the same 401
response.

## Authorization Model

PodClub distinguishes platform roles from club roles:

- Platform roles: `super_admin`, `admin`, `user`
- Club roles: `club_owner`, `club_moderator`, `club_member`

Platform permissions are resolved from the user's platform role. Club operations
also resolve the user's role in the requested club. The `super_admin` role
system-wide bypasses permission checks.

Club ownership and membership are enforced by request-scoped access checks.
Content routes and member routes derive or require `podclub_id` from the API
payload or resource instead of trusting a client identity field.

## API Groups

Main route groups include:

- Authentication: `/auth`
- Users and public profiles: `/users`
- Roles and role permissions: `/roles`, `/role-permissions`
- Permissions: `/permissions`
- Clubs and club permissions: `/podclubs`
- Club memberships: `/podclub-members`
- Club bans: `/podclubs/{uid}/bans`
- Invites: `/invites`
- Podcasts and episodes: `/podcasts`, `/episodes`
- Messages: `/messages`
- Reports: `/reports`
- Upload signing: `/uploads`
- Admin statistics: `/admin`

Client write schemas reject unknown fields. Identity and server-managed fields
such as `owner_id`, `sender_id`, `creator_id`, `reporter_id`, `reviewed_by_id`,
and invite tokens are not accepted from clients.

## Postman

A local Postman collection is stored under `postman/collections/PodClub API`.
The collection is currently ignored by Git. The following collection variables
are used between requests:

- `base_url`
- `token`
- `podclub_id`
- `podclub_uid`
- `podcast_id`
- `user_id`
- `user_uid`
- `member_uid`
- `message_uid`
- `episode_uid`
- `invite_uid`
- `report_uid`

Suggested manual run order:

1. Run the seed command.
2. Log in as the super admin or an account with the required permissions.
3. Create a PodClub.
4. Add members or create podcasts and episodes.
5. Run club-scoped message, invite, report, or ban requests.

## API Contract and Uploads

The machine-readable API contract is in [docs/openapi.json](docs/openapi.json).
Regenerate it with:

PowerShell:

```powershell
python -m app.commands.export_openapi
```

bash:

```bash
python -m app.commands.export_openapi
```

The browser upload flow, plain-fetch example, private-club media limitation,
and WebSocket contract are documented in [docs/API.md](docs/API.md).

Media uploads use signed Supabase Storage URLs created by the FastAPI server.
The browser never receives or uses the Supabase service-role key. Private-club
media in the public bucket is unlisted rather than secret: an object URL reveals
the file to anyone who obtains it.

## Deploy

### Supabase checklist

1. Create separate **dev** and **prod** Supabase projects.
2. Open the database connection settings and copy the **Session Pooler**
   connection string for each project. It uses port `5432`.
3. URL-encode special characters in the database password.
4. Do not use the transaction pooler on port `6543` for the app or migrations.
5. Create or update the media bucket:

   PowerShell:

   ```powershell
   python -m app.commands.setup_storage
   ```

   bash:

   ```bash
   python -m app.commands.setup_storage
   ```

6. Optionally disable Supabase Data API for the project. FastAPI remains the only
   application API and uses the PostgreSQL session pooler directly.
7. Run `python -m app.commands.check_rls` after migrations. It must print
   `No public tables without RLS.`.

The Supabase bucket is public and has the project plan's file-size limit.
The application additionally caps audio at `MAX_AUDIO_MB` and images at
`MAX_IMAGE_MB`; `MAX_AUDIO_MB` is not allowed to exceed the bucket limit.

### Render

[`render.yaml`](render.yaml) creates one long-running API process and no Render
Postgres database. The start command migrates, configures Storage, seeds roles,
permissions, and the super admin, then starts one Uvicorn worker.

The dummy seed is prohibited in production. WebSocket state is held in process
memory, so deployment must use exactly one worker. Multiple workers or replicas
will not share connections or events.

### Environment variables

| Name | Required | Example |
|---|---|---|
| `APP_ENV` | Yes | `production` |
| `JWT_SECRET_KEY` | Yes | Generate a long random secret |
| `JWT_ALGORITHM` | No | `HS256` |
| `ACCESS_TOKEN_EXPIRE_SECONDS` | No | `18000` |
| `DATABASE_URL` | Yes | Supabase Session Pooler URL on port `5432` |
| `CORS_ORIGINS` | Yes | `["https://app.example.com"]` |
| `CORS_ORIGIN_REGEX` | No | `^https://.*\.vercel\.app$` |
| `SUPABASE_URL` | Yes | `https://<project-ref>.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes, server only | Supabase service-role key |
| `SUPABASE_STORAGE_BUCKET` | No | `podclub-media` |
| `MAX_AUDIO_MB` | No | `50` |
| `MAX_IMAGE_MB` | No | `5` |
| `ALLOW_EXTERNAL_MEDIA_URLS` | No | `false` |
| `SUPERADMIN_NAME` | Yes | `Super Admin` |
| `SUPERADMIN_EMAIL` | Yes | `admin@example.com` |
| `SUPERADMIN_PASSWORD` | Yes | Long random password |
| `ENABLE_DOCS` | No | `false` in production if Swagger should be hidden |

Supabase keys must never be placed in Vercel/frontend environment variables or
returned by API responses. Only the service-role key is needed by this backend;
plain browser uploads use the server-signed URL and do not require a public key.

## Tests

Tests require a real PostgreSQL test database configured as `DATABASE_URL_TEST`.
The test database must be different from `DATABASE_URL`.

PowerShell:

```powershell
python -m pytest tests
```

bash:

```bash
python -m pytest tests
```

Never use SQLite for the test database. PostgreSQL-only features and migrations
are exercised with the real PostgreSQL engine.

## Project Structure

```text
PodClub-Backend/
├── alembic/                 Alembic environment and migrations
├── app/
│   ├── commands/            Seed and administrative commands
│   ├── core/                Configuration and permissions
│   ├── crud/                Database operations
│   ├── dependencies/        Authentication and access checks
│   ├── handlers/            API exception handlers
│   ├── models/              SQLAlchemy models
│   ├── routes/              FastAPI route modules
│   ├── schema/              Pydantic request and response models
│   ├── services/            Supabase media and WebSocket services
│   └── utils/               Shared validation and helpers
├── docs/
│   ├── API.md               Upload and WebSocket API guide
│   └── openapi.json         Generated OpenAPI contract
├── tests/                   PostgreSQL-backed pytest suite
├── main.py                  FastAPI application entry point
├── requirements.txt
└── alembic.ini
```

## Development Notes

- Use `pathlib` for filesystem paths.
- Keep `.env` local and commit `.env.example`.
- Preserve the `main.py` location at the repository root.
- Run PostgreSQL on `localhost:5432` on Windows and Ubuntu.
- Do not add a guest role or guest table.
- Supabase Auth, Realtime, PostgREST, private media buckets, orphan cleanup,
  and server-side audio-duration extraction are not used in this API.

## License

MIT
