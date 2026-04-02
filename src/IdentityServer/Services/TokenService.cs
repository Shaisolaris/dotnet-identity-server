namespace IdentityServer.Services;

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

public class TokenService
{
    private readonly IConfiguration _config;
    private readonly UserManager<ApplicationUser> _userManager;

    public TokenService(IConfiguration config, UserManager<ApplicationUser> userManager)
    {
        _config = config;
        _userManager = userManager;
    }

    public async Task<(string AccessToken, DateTime ExpiresAt)> GenerateAccessTokenAsync(ApplicationUser user, IList<string>? roles = null)
    {
        roles ??= await _userManager.GetRolesAsync(user);

        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email ?? ""),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("name", user.FullName),
        };

        foreach (var role in roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        var userClaims = await _userManager.GetClaimsAsync(user);
        claims.AddRange(userClaims);

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Secret"] ?? "super-secret-key-that-is-at-least-32-chars-long!!"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expiresAt = DateTime.UtcNow.AddMinutes(int.Parse(_config["Jwt:AccessTokenLifetimeMinutes"] ?? "60"));

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"] ?? "identity-server",
            audience: _config["Jwt:Audience"] ?? "api",
            claims: claims,
            expires: expiresAt,
            signingCredentials: creds
        );

        return (new JwtSecurityTokenHandler().WriteToken(token), expiresAt);
    }

    public RefreshToken GenerateRefreshToken(string userId, string? ipAddress = null)
    {
        return new RefreshToken
        {
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            UserId = userId,
            ExpiresAt = DateTime.UtcNow.AddDays(int.Parse(_config["Jwt:RefreshTokenLifetimeDays"] ?? "30")),
            CreatedByIp = ipAddress,
        };
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Secret"] ?? "super-secret-key-that-is-at-least-32-chars-long!!"));

        try
        {
            var principal = new JwtSecurityTokenHandler().ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ValidateIssuer = true,
                ValidIssuer = _config["Jwt:Issuer"] ?? "identity-server",
                ValidateAudience = true,
                ValidAudience = _config["Jwt:Audience"] ?? "api",
                ValidateLifetime = false, // We check expiry separately for refresh
                ClockSkew = TimeSpan.Zero,
            }, out _);

            return principal;
        }
        catch
        {
            return null;
        }
    }
}

namespace IdentityServer.Configuration;

using IdentityServer.Models;

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
