# dotnet-identity-server

> **Quick Start:** `dotnet run` then open http://localhost:5000/swagger. Register or use seeded admin: `admin@demo.com` / `Admin123!`


![CI](https://github.com/Shaisolaris/dotnet-identity-server/actions/workflows/ci.yml/badge.svg)

ASP.NET Core 8 identity server implementing OAuth2/OpenID Connect patterns with JWT access tokens, refresh token rotation, role-based authorization, ASP.NET Core Identity for user management, account lockout, password policies, OpenID discovery endpoint, and pre-configured OAuth clients.

## Stack

- **Framework:** ASP.NET Core 8
- **Identity:** ASP.NET Core Identity with EF Core
- **Auth:** JWT Bearer with refresh token rotation
- **Docs:** Swagger with Bearer auth support

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Register user, returns access + refresh tokens |
| POST | `/api/auth/login` | Login, returns tokens, updates last login |
| POST | `/api/auth/refresh` | Rotate refresh token, return new token pair |
| POST | `/api/auth/logout` | Revoke all refresh tokens for user |
| POST | `/api/auth/change-password` | Change password (requires current) |

### Users
| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/users/me` | Bearer | Current user info with roles |
| GET | `/api/users` | Admin | List all active users |

### Discovery
| Method | Endpoint | Description |
|---|---|---|
| GET | `/.well-known/openid-configuration` | OpenID Connect discovery document |

## Security Features

### JWT Access Tokens
- HMAC-SHA256 signed
- Configurable lifetime (default 60 min)
- Claims: sub, email, name, roles, jti
- Validated on every request via middleware

### Refresh Token Rotation
- Cryptographically random 64-byte tokens
- Stored in database with user ID, IP, timestamps
- On refresh: old token revoked, new token issued
- Chain tracking via `ReplacedByToken` field
- Revoked tokens cannot be reused

### Account Security
- Password policy: 8+ chars, uppercase, lowercase, digit
- Account lockout: 5 failed attempts, 15-minute lockout
- Email uniqueness enforced
- Soft deactivation (IsActive flag)

### OAuth Clients (pre-configured)
| Client | Grant Types | Token Lifetime |
|---|---|---|
| `web-app` | authorization_code, refresh_token | 60 min access, 30 day refresh |
| `mobile-app` | authorization_code, refresh_token | 30 min access, 90 day refresh |
| `service-client` | client_credentials | 15 min access |

### Roles
- `Admin` — Full access, user management
- `Manager` — Extended permissions
- `User` — Standard access

## Seed Data

On startup, the server automatically creates:
- 3 roles: Admin, User, Manager
- Admin user: `admin@example.com` / `Admin123!` with Admin + User roles

## Architecture

```
src/IdentityServer/
├── Controllers/
│   └── Controllers.cs              # AuthController, UsersController, DiscoveryController
├── Models/
│   └── Models.cs                   # ApplicationUser, RefreshToken, OAuthClient, DTOs
├── Services/
│   ├── TokenService.cs             # JWT generation, refresh token creation, validation
│   ├── IdentityDbContext.cs        # EF Core context with Identity tables + RefreshTokens
│   └── (Configuration/)            # OAuthClients static config
├── Program.cs                      # Identity setup, JWT config, role seeding
├── appsettings.json
└── IdentityServer.csproj
```

## Setup

```bash
git clone https://github.com/Shaisolaris/dotnet-identity-server.git
cd dotnet-identity-server
dotnet run --project src/IdentityServer
# → https://localhost:5001/swagger
# → Discovery: https://localhost:5001/.well-known/openid-configuration
```

## Key Design Decisions

**Refresh token rotation.** Every refresh exchanges the old token for a new one. The old token is marked as revoked with a pointer to its replacement. This limits the window of exposure if a refresh token is compromised and creates an audit trail of token usage.

**In-memory database for demo.** Uses EF Core InMemory provider for zero-setup. Swap to SQL Server or PostgreSQL by changing one line in Program.cs. Identity tables, refresh tokens, and seed data are all created on startup.

**OpenID Connect discovery.** The `/.well-known/openid-configuration` endpoint returns a standard OIDC discovery document. This enables client libraries to auto-configure by pointing at the issuer URL.

**ASP.NET Core Identity over custom auth.** Using the built-in Identity framework provides battle-tested password hashing (PBKDF2), lockout policy, two-factor readiness, and token providers. The custom layer adds JWT issuance and refresh token management on top.

**Swagger with Bearer auth.** The Swagger UI includes a "Bearer" security definition, enabling API testing with JWT tokens directly from the docs page without external tools.

## License

MIT
