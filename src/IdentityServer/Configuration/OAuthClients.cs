using IdentityServer.Models;

namespace IdentityServer.Configuration;

public static class OAuthClients
{
    public static List<OAuthClient> GetClients() => new()
    {
        new OAuthClient
        {
            ClientId = "web-app",
            ClientSecret = "web-app-secret",
            Name = "Web Application",
            AllowedGrantTypes = new() { "authorization_code", "refresh_token" },
            RedirectUris = new() { "http://localhost:3000/callback", "https://app.example.com/callback" },
            AllowedScopes = new() { "openid", "profile", "email", "api" },
            AccessTokenLifetimeMinutes = 60,
            RefreshTokenLifetimeDays = 30,
        },
        new OAuthClient
        {
            ClientId = "mobile-app",
            ClientSecret = "mobile-app-secret",
            Name = "Mobile Application",
            AllowedGrantTypes = new() { "authorization_code", "refresh_token" },
            RedirectUris = new() { "myapp://callback" },
            AllowedScopes = new() { "openid", "profile", "email", "api", "offline_access" },
            AccessTokenLifetimeMinutes = 30,
            RefreshTokenLifetimeDays = 90,
        },
        new OAuthClient
        {
            ClientId = "service-client",
            ClientSecret = "service-client-secret",
            Name = "Backend Service",
            AllowedGrantTypes = new() { "client_credentials" },
            AllowedScopes = new() { "api", "admin" },
            AccessTokenLifetimeMinutes = 15,
        },
    };
}