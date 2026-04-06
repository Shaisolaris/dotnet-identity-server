using System.IdentityModel.Tokens.Jwt;
namespace IdentityServer.Controllers;

using IdentityServer.Models;
using IdentityServer.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly TokenService _tokenService;
    private readonly IdentityDbContext _db;
    private readonly ILogger<AuthController> _logger;

    public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager,
        TokenService tokenService, IdentityDbContext db, ILogger<AuthController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _tokenService = tokenService;
        _db = db;
        _logger = logger;
    }

    [HttpPost("register")]
    public async Task<ActionResult<TokenResponse>> Register([FromBody] RegisterRequest request)
    {
        var existing = await _userManager.FindByEmailAsync(request.Email);
        if (existing != null)
            return Conflict(new { error = "Email already registered" });

        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FullName = request.FullName,
            EmailConfirmed = true,
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        await _userManager.AddToRoleAsync(user, "User");
        _logger.LogInformation("User registered: {Email}", user.Email);

        return await GenerateTokenResponse(user);
    }

    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login([FromBody] LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null || !user.IsActive)
            return Unauthorized(new { error = "Invalid credentials" });

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (result.IsLockedOut)
            return StatusCode(429, new { error = "Account locked. Try again later." });
        if (!result.Succeeded)
            return Unauthorized(new { error = "Invalid credentials" });

        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        _logger.LogInformation("User logged in: {Email}", user.Email);
        return await GenerateTokenResponse(user);
    }

    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> Refresh([FromBody] RefreshTokenRequest request)
    {
        var storedToken = await _db.RefreshTokens
            .FirstOrDefaultAsync(t => t.Token == request.RefreshToken);

        if (storedToken == null || !storedToken.IsActive)
            return Unauthorized(new { error = "Invalid or expired refresh token" });

        var user = await _userManager.FindByIdAsync(storedToken.UserId);
        if (user == null || !user.IsActive)
            return Unauthorized(new { error = "User not found or inactive" });

        // Rotate refresh token
        storedToken.RevokedAt = DateTime.UtcNow;
        storedToken.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString();

        var (accessToken, expiresAt) = await _tokenService.GenerateAccessTokenAsync(user);
        var newRefreshToken = _tokenService.GenerateRefreshToken(user.Id, HttpContext.Connection.RemoteIpAddress?.ToString());

        storedToken.ReplacedByToken = newRefreshToken.Token;
        _db.RefreshTokens.Add(newRefreshToken);
        await _db.SaveChangesAsync();

        return Ok(new TokenResponse(accessToken, newRefreshToken.Token, expiresAt));
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        if (userId != null)
        {
            var tokens = await _db.RefreshTokens
                .Where(t => t.UserId == userId && t.RevokedAt == null)
                .ToListAsync();
            foreach (var token in tokens)
                token.RevokedAt = DateTime.UtcNow;
            await _db.SaveChangesAsync();
        }
        return Ok(new { message = "All sessions revoked" });
    }

    [Authorize]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        var user = await _userManager.FindByIdAsync(userId!);
        if (user == null) return NotFound();

        var result = await _userManager.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
            return BadRequest(new { errors = result.Errors.Select(e => e.Description) });

        return Ok(new { message = "Password changed" });
    }

    private async Task<ActionResult<TokenResponse>> GenerateTokenResponse(ApplicationUser user)
    {
        var (accessToken, expiresAt) = await _tokenService.GenerateAccessTokenAsync(user);
        var refreshToken = _tokenService.GenerateRefreshToken(user.Id, HttpContext.Connection.RemoteIpAddress?.ToString());

        _db.RefreshTokens.Add(refreshToken);
        await _db.SaveChangesAsync();

        return Ok(new TokenResponse(accessToken, refreshToken.Token, expiresAt));
    }
}

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UsersController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;

    public UsersController(UserManager<ApplicationUser> userManager) => _userManager = userManager;

    [HttpGet("me")]
    public async Task<ActionResult<UserInfoResponse>> GetMe()
    {
        var userId = User.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        var user = await _userManager.FindByIdAsync(userId!);
        if (user == null) return NotFound();

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(new UserInfoResponse(user.Id, user.Email!, user.FullName, user.AvatarUrl, roles, user.CreatedAt));
    }

    [HttpGet]
    [Authorize(Roles = "Admin")]
    public async Task<ActionResult<List<UserInfoResponse>>> GetAll()
    {
        var users = _userManager.Users.Where(u => u.IsActive).ToList();
        var result = new List<UserInfoResponse>();
        foreach (var user in users)
        {
            var roles = await _userManager.GetRolesAsync(user);
            result.Add(new UserInfoResponse(user.Id, user.Email!, user.FullName, user.AvatarUrl, roles, user.CreatedAt));
        }
        return Ok(result);
    }
}

[ApiController]
[Route(".well-known")]
public class DiscoveryController : ControllerBase
{
    private readonly IConfiguration _config;
    public DiscoveryController(IConfiguration config) => _config = config;

    [HttpGet("openid-configuration")]
    public IActionResult GetOpenIdConfig()
    {
        var baseUrl = _config["Jwt:Issuer"] ?? "https://localhost:5001";
        return Ok(new
        {
            issuer = baseUrl,
            authorization_endpoint = $"{baseUrl}/api/oauth/authorize",
            token_endpoint = $"{baseUrl}/api/auth/login",
            userinfo_endpoint = $"{baseUrl}/api/users/me",
            jwks_uri = $"{baseUrl}/.well-known/jwks",
            registration_endpoint = $"{baseUrl}/api/auth/register",
            scopes_supported = new[] { "openid", "profile", "email", "api", "offline_access" },
            response_types_supported = new[] { "code", "token" },
            grant_types_supported = new[] { "authorization_code", "client_credentials", "refresh_token" },
            token_endpoint_auth_methods_supported = new[] { "client_secret_post", "client_secret_basic" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "HS256" },
        });
    }
}
