# Demo Guide

## Quick Start
```bash
dotnet run --project src/IdentityServer
# Opens at http://localhost:5000
# Swagger UI at http://localhost:5000/swagger
```

## Demo Credentials
A seed admin user is created on startup:
- **Email:** admin@demo.com
- **Password:** Admin123!

## Test Flow
1. `POST /api/auth/register` — Register a new user
2. `POST /api/auth/login` — Login with credentials → returns JWT
3. `GET /api/auth/me` — Use JWT in Authorization header to get profile
4. `POST /api/auth/refresh` — Refresh expired token
